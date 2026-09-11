/** @file
  ECIT capability reporting -- shared engine for op handlers.

  This file implements CryptOpEmitProviderSignatureOids, the predicate-
  driven enumerator every per-op handler in Pk/Crypt<Op>OpCapability.c
  delegates to. Per-op handlers contribute only their accept predicate;
  the iteration, OID conversion, dedupe, and EFI_BUFFER_TOO_SMALL
  contract live here.

  Two complementary passes cover OpenSSL's bifurcated signature surface:

    Pass A -- digest x pk-type cross-product (legacy "digest+key" sig OIDs)
              Walks EVP_MD_do_all_provided and queries OBJ_find_sigid_by_algs
              for each (digest, pk-type) pair. Catches the PKCS#1 RSA family
              (sha*WithRSA, OID 1.2.840.113549.1.1.*) and ANSI X9.62 ECDSA
              (ecdsa-with-sha*, OID 1.2.840.10045.4.*).

    Pass B -- enumerate provider-published signature algorithms directly
              Walks EVP_SIGNATURE_do_all_provided and inspects each
              algorithm's published name list. Names that resolve to a
              known signature NID (per OBJ_find_sigid_algs) are emitted.
              Catches RSA-PSS, EdDSA, ML-DSA-44/65/87, and any future
              entry added to OpensslLib's deflt_signature[] -- no drift.

  Pass A and Pass B can produce overlapping NIDs. The accept predicate is
  invoked exactly once per *candidate NID* (Pass A's per-(digest,pk) emit
  and Pass B's per-name emit) and dedupe in the OID emit path collapses
  duplicates.

  State layout
  ------------
  Each enumeration uses one CRYPTO_OP_OID_EMIT_STATE on the stack. The
  Written / Committed split is required for ASan-safe handling of the
  EFI_BUFFER_TOO_SMALL contract:

   * Written tracks the running REQUIRED size, advanced on every accepted
     emit regardless of capacity.

   * Committed tracks bytes ACTUALLY written into Buffer. Stays at zero
     once Overflow latches.

   * Without this distinction, an overflowed write would advance Written
     into uninitialized buffer space and the next dedupe scan would read
     OOB.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include "CryptOpCapability.h"

#include <openssl/evp.h>
#include <openssl/objects.h>

/**
  Iteration state shared by Pass A and Pass B emit calls. Engine-private:
  per-op handlers never see it.
**/
typedef struct {
  CHAR8                      *Buffer;       ///< Caller buffer; NULL on probe.
  UINTN                      BufferSize;    ///< Capacity; 0 when Buffer NULL.
  UINTN                      Written;       ///< Running required bytes (excl. NUL).
  UINTN                      Committed;     ///< Bytes actually placed in Buffer.
  BOOLEAN                    Overflow;      ///< Latches once a write was skipped.
  CRYPTO_OP_SIG_ACCEPT_FN    Accept;        ///< Per-op acceptance predicate.
  VOID                       *AcceptCtx;    ///< Caller context for Accept.
} EMIT_STATE;

//
// Pass A search space: pk-types we ask OpenSSL about for each digest.
//
// EVP_MD_do_all_provided x mPassAPkNids enumerates every (digest, pk)
// signature combination the provider can form via the legacy sigid table.
// EdDSA pk-types are listed even though OpenSSL never returns a sigid for
// (digest, EdDSA) -- they're harmless no-ops -- so the search space stays
// a literal mirror of "asymmetric key types BaseCryptLib's pipeline
// supports".
//
STATIC CONST INT32  mPassAPkNids[] = {
  EVP_PKEY_RSA,
  EVP_PKEY_EC,
  EVP_PKEY_ED25519,
  EVP_PKEY_ED448
};

/**
  Linear scan of the running CSV looking for an exact, comma-bounded
  match of Oid.

  Dedupe is best-effort and conservative: on the sizing-probe path
  (Buffer NULL) and after capacity overflow it returns FALSE. Duplicates
  in those modes only inflate the running required-size estimate; they
  never break the public contract.

  @param[in]  State  Iteration state.
  @param[in]  Oid    NUL-terminated dotted-OID string.

  @retval TRUE   Oid is already a comma-bounded entry in State->Buffer.
  @retval FALSE  Not present, or dedupe is skipped for this state shape.
**/
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

/**
  Append Oid to the running CSV (with leading comma when needed).
  Updates Written unconditionally; Committed only when capacity allows.
  Latches Overflow on the first capacity-skipped write.

  @param[in,out]  State  Iteration state.
  @param[in]      Oid    NUL-terminated dotted-OID string.
**/
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

/**
  Convert a NID to its dotted-decimal OID and forward to EmitOid.

  Silently dropped when OpenSSL has no stable dotted form for Nid; that
  case by definition is not a useful entry to publish.

  @param[in,out]  State  Iteration state.
  @param[in]      Nid    OpenSSL NID for a signature algorithm.
**/
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

/**
  TRUE iff Nid identifies an OpenSSL-known *signature algorithm* (registered
  in the legacy sig table via OBJ_find_sigid_algs). Used to weed out
  key-only NIDs the Pass B name walk surfaces.

  @param[in]  Nid  OpenSSL NID resolved from a published name.

  @retval TRUE   Nid is a registered signature algorithm.
  @retval FALSE  Nid is undefined or refers to a key-only algorithm.
**/
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

/**
  Pass A callback. For every digest the provider publishes, walk every
  pk-type in mPassAPkNids and emit the legacy (digest, pk) sig OID when
  the accept predicate says yes.

  @param[in]      Md   Digest algorithm being visited.
  @param[in,out]  Arg  EMIT_STATE* (cast at entry).
**/
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

  State     = (EMIT_STATE *)Arg;
  DigestNid = EVP_MD_get_type (Md);
  if (DigestNid == NID_undef) {
    return;
  }

  for (PkIdx = 0; PkIdx < ARRAY_SIZE (mPassAPkNids); PkIdx++) {
    SigNid = NID_undef;
    if (OBJ_find_sigid_by_algs (&SigNid, DigestNid, mPassAPkNids[PkIdx]) != 1) {
      continue;
    }

    if (!State->Accept (SigNid, State->AcceptCtx)) {
      continue;
    }

    EmitNidAsOid (State, SigNid);
  }
}

/**
  Pass B per-name callback. Resolves a single algorithm name to a NID,
  filters key-only NIDs, applies the accept predicate, and emits the
  dotted OID on a hit.

  @param[in]      Name  Name or dotted OID published by the provider.
  @param[in,out]  Arg   EMIT_STATE* (cast at entry).
**/
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

  // OBJ_txt2nid recognises both short names ("ML-DSA-65") and dotted OIDs.
  Nid = OBJ_txt2nid (Name);
  if (!IsSignatureNid (Nid)) {
    return;
  }

  if (!State->Accept (Nid, State->AcceptCtx)) {
    return;
  }

  EmitNidAsOid (State, Nid);
}

/**
  Pass B per-algorithm fan-out. Iterates the names list of the visited
  EVP_SIGNATURE, delegating per-name handling to NameVisitorPassB.

  @param[in]      Sig  Signature algorithm being visited.
  @param[in,out]  Arg  EMIT_STATE* (cast at entry).
**/
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

  if ((Accept == NULL) || (BufferSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&State, sizeof (State));
  State.Buffer     = Buffer;
  State.BufferSize = (Buffer != NULL) ? *BufferSize : 0;
  State.Accept     = Accept;
  State.AcceptCtx  = Ctx;

  // Pass A: digest+key combinations via the legacy sigid lookup.
  EVP_MD_do_all_provided (NULL /* default libctx */, DigestVisitorPassA, &State);

  // Pass B: parameter-free / direct sig algs (PSS, EdDSA, ML-DSA, ...).
  EVP_SIGNATURE_do_all_provided (NULL, SignatureVisitorPassB, &State);

  Required = State.Written + 1; /* trailing NUL */

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
