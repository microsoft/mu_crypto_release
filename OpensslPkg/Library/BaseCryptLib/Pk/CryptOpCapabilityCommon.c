/** @file
  Provider-backed algorithm OID enumeration for ECIT capability reporting.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include "CryptOpCapability.h"

#include <openssl/evp.h>
#include <openssl/objects.h>

typedef struct {
  CHAR8                      *Buffer;
  UINTN                      BufferSize;
  UINTN                      Written;    ///< Required payload bytes, excluding the NUL.
  UINTN                      Committed;  ///< Payload bytes written to Buffer.
  BOOLEAN                    Overflow;
  CRYPTO_OP_SIG_ACCEPT_FN    Accept;
  VOID                       *AcceptCtx;
  CONST BOOLEAN              *PkAvail;
} EMIT_STATE;

//
// OBJ_find_sigid_by_algs() does not verify that the provider implements the
// key type, so each type is paired with the name used to probe availability.
//
typedef struct {
  INT32          PkNid;
  CONST CHAR8    *KeyMgmtName;
} PASS_A_PK_TYPE;

STATIC CONST PASS_A_PK_TYPE  mPassAPkTypes[] = {
  { EVP_PKEY_RSA,     "RSA"     },
  { EVP_PKEY_EC,      "EC"      },
  { EVP_PKEY_ED25519, "ED25519" },
  { EVP_PKEY_ED448,   "ED448"   },
};

STATIC
BOOLEAN
IsFixedOutputDigest (
  IN CONST EVP_MD  *Md
  )
{
  return (BOOLEAN)((EVP_MD_get_size (Md) > 0) &&
                   ((EVP_MD_get_flags (Md) & EVP_MD_FLAG_XOF) == 0));
}

STATIC
BOOLEAN
PkTypeIsAvailable (
  IN CONST CHAR8  *KeyMgmtName
  )
{
  EVP_PKEY_CTX  *PkeyCtx;

  PkeyCtx = EVP_PKEY_CTX_new_from_name (NULL, KeyMgmtName, NULL);
  if (PkeyCtx == NULL) {
    return FALSE;
  }

  EVP_PKEY_CTX_free (PkeyCtx);
  return TRUE;
}

STATIC
BOOLEAN
StateContainsOid (
  IN CONST EMIT_STATE  *State,
  IN CONST CHAR8       *Oid
  )
{
  UINTN  OidLen;
  UINTN  Index;
  CHAR8  Prev;

  if ((State->Buffer == NULL) || (State->Committed == 0)) {
    return FALSE;
  }

  OidLen = AsciiStrLen (Oid);
  if (OidLen == 0) {
    return FALSE;
  }

  for (Index = 0; (Index + OidLen) <= State->Committed; Index++) {
    Prev = (Index == 0) ? ',' : State->Buffer[Index - 1];
    if (Prev != ',') {
      continue;
    }

    if (CompareMem (&State->Buffer[Index], Oid, OidLen) != 0) {
      continue;
    }

    if ((Index + OidLen == State->Committed) ||
        (State->Buffer[Index + OidLen] == ','))
    {
      return TRUE;
    }
  }

  return FALSE;
}

STATIC
VOID
EmitOid (
  IN OUT EMIT_STATE   *State,
  IN     CONST CHAR8  *Oid
  )
{
  UINTN  OidLen;
  UINTN  CommaLen;
  UINTN  Need;

  if (StateContainsOid (State, Oid)) {
    return;
  }

  OidLen   = AsciiStrLen (Oid);
  CommaLen = (State->Written > 0) ? 1 : 0;
  Need     = CommaLen + OidLen;

  State->Written += Need;

  if ((State->Buffer == NULL) ||
      State->Overflow ||
      (State->Committed + Need + 1 > State->BufferSize))
  {
    if (State->Buffer != NULL) {
      State->Overflow = TRUE;
    }

    return;
  }

  if (CommaLen != 0) {
    State->Buffer[State->Committed++] = ',';
  }

  CopyMem (&State->Buffer[State->Committed], Oid, OidLen);
  State->Committed += OidLen;
}

STATIC
VOID
EmitNidAsOid (
  IN OUT EMIT_STATE  *State,
  IN     INT32       Nid
  )
{
  ASN1_OBJECT  *Obj;
  CHAR8        Buf[80];
  int          Len;

  Obj = OBJ_nid2obj (Nid);
  if (Obj == NULL) {
    return;
  }

  Len = OBJ_obj2txt (Buf, sizeof (Buf), Obj, 1 /* always_dotted */);
  if ((Len <= 0) || ((UINTN)Len >= sizeof (Buf))) {
    return;
  }

  Buf[Len] = '\0';
  EmitOid (State, Buf);
}

STATIC
BOOLEAN
IsSignatureNid (
  IN INT32  Nid
  )
{
  int  DigestNid;
  int  PkNid;

  if (Nid == NID_undef) {
    return FALSE;
  }

  DigestNid = NID_undef;
  PkNid     = NID_undef;
  return (OBJ_find_sigid_algs (Nid, &DigestNid, &PkNid) == 1);
}

STATIC
VOID
DigestVisitorPassA (
  EVP_MD  *Md,
  VOID    *Arg
  )
{
  EMIT_STATE  *State;
  INT32       DigestNid;
  UINTN       PkIdx;
  INT32       SigNid;

  State = (EMIT_STATE *)Arg;

  if (!IsFixedOutputDigest (Md)) {
    return;
  }

  DigestNid = EVP_MD_get_type (Md);
  if (DigestNid == NID_undef) {
    return;
  }

  for (PkIdx = 0; PkIdx < ARRAY_SIZE (mPassAPkTypes); PkIdx++) {
    if (!State->PkAvail[PkIdx]) {
      continue;
    }

    SigNid = NID_undef;
    if (OBJ_find_sigid_by_algs (&SigNid, DigestNid, mPassAPkTypes[PkIdx].PkNid) != 1) {
      continue;
    }

    if (!State->Accept (SigNid, State->AcceptCtx)) {
      continue;
    }

    EmitNidAsOid (State, SigNid);
  }
}

STATIC
VOID
NameVisitorPassB (
  CONST CHAR8  *Name,
  VOID         *Arg
  )
{
  EMIT_STATE  *State;
  INT32       Nid;

  State = (EMIT_STATE *)Arg;
  State = (EMIT_STATE *)Arg;

  Nid = OBJ_txt2nid (Name);
  if (!IsSignatureNid (Nid)) {
    return;
  }

  if (!State->Accept (Nid, State->AcceptCtx)) {
    return;
  }

  EmitNidAsOid (State, Nid);
}

STATIC
VOID
SignatureVisitorPassB (
  EVP_SIGNATURE  *Sig,
  VOID           *Arg
  )
{
  EVP_SIGNATURE_names_do_all (Sig, NameVisitorPassB, Arg);
}

EFI_STATUS
CryptOpEmitProviderSignatureOids (
  IN     CRYPTO_OP_SIG_ACCEPT_FN  Accept,
  IN     VOID                     *Ctx,
  OUT    CHAR8                    *Buffer       OPTIONAL,
  IN OUT UINTN                    *BufferSize
  )
{
  EMIT_STATE  State;
  UINTN       Required;
  BOOLEAN     PkAvail[ARRAY_SIZE (mPassAPkTypes)];
  UINTN       PkIdx;

  if ((Accept == NULL) || (BufferSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&State, sizeof (State));
  State.Buffer     = Buffer;
  State.BufferSize = (Buffer != NULL) ? *BufferSize : 0;
  State.Accept     = Accept;
  State.AcceptCtx  = Ctx;

  for (PkIdx = 0; PkIdx < ARRAY_SIZE (mPassAPkTypes); PkIdx++) {
    PkAvail[PkIdx] = PkTypeIsAvailable (mPassAPkTypes[PkIdx].KeyMgmtName);
  }

  State.PkAvail = PkAvail;

  EVP_MD_do_all_provided (NULL /* default libctx */, DigestVisitorPassA, &State);

  EVP_SIGNATURE_do_all_provided (NULL, SignatureVisitorPassB, &State);

  Required = State.Written + 1;

  if (Buffer == NULL) {
    *BufferSize = Required;
    return EFI_SUCCESS;
  }

  if (State.Overflow || (*BufferSize < Required)) {
    *BufferSize = Required;
    return EFI_BUFFER_TOO_SMALL;
  }

  Buffer[State.Committed] = '\0';
  *BufferSize             = Required;
  return EFI_SUCCESS;
}
