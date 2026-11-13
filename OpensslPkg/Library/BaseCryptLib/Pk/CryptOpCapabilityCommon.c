/** @file
  Provider-backed algorithm OID enumeration for crypto capabilities.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include "CryptOpCapability.h"

#include <openssl/evp.h>
#include <openssl/objects.h>

#define MAX_ALGORITHM_OID_SIZE  80

typedef struct {
  LIST_ENTRY    Link;
  UINTN         OidSize;
  CHAR8         Oid[MAX_ALGORITHM_OID_SIZE];
} CAPABILITY_NODE;

typedef struct {
  LIST_ENTRY                 Capabilities;
  UINTN                      CapabilityCount;
  UINTN                      OidBytes;
  EFI_STATUS                 Status;
  CRYPTO_OP_SIG_ACCEPT_FN    Accept;
  VOID                       *AcceptCtx;
  CONST BOOLEAN              *PkAvail;
} COLLECT_STATE;

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
VOID
FreeCollectedCapabilities (
  IN OUT COLLECT_STATE  *State
  )
{
  LIST_ENTRY       *Link;
  CAPABILITY_NODE  *Node;

  while (!IsListEmpty (&State->Capabilities)) {
    Link = GetFirstNode (&State->Capabilities);
    Node = BASE_CR (Link, CAPABILITY_NODE, Link);
    RemoveEntryList (Link);
    FreePool (Node);
  }
}

STATIC
BOOLEAN
StateContainsOid (
  IN CONST COLLECT_STATE  *State,
  IN CONST CHAR8          *Oid
  )
{
  LIST_ENTRY       *Link;
  CAPABILITY_NODE  *Node;

  for (Link = GetFirstNode (&State->Capabilities);
       !IsNull (&State->Capabilities, Link);
       Link = GetNextNode (&State->Capabilities, Link))
  {
    Node = BASE_CR (Link, CAPABILITY_NODE, Link);
    if (AsciiStrCmp (Node->Oid, Oid) == 0) {
      return TRUE;
    }
  }

  return FALSE;
}

STATIC
VOID
CollectOid (
  IN OUT COLLECT_STATE  *State,
  IN     CONST CHAR8    *Oid
  )
{
  CAPABILITY_NODE  *Node;
  UINTN            OidSize;

  if (EFI_ERROR (State->Status) || StateContainsOid (State, Oid)) {
    return;
  }

  OidSize = AsciiStrSize (Oid);
  if ((OidSize <= 1) || (OidSize > sizeof (Node->Oid))) {
    return;
  }

  if ((State->CapabilityCount == MAX_UINTN) ||
      (State->OidBytes > (MAX_UINTN - OidSize)))
  {
    State->Status = EFI_OUT_OF_RESOURCES;
    return;
  }

  Node = AllocateZeroPool (sizeof (*Node));
  if (Node == NULL) {
    State->Status = EFI_OUT_OF_RESOURCES;
    return;
  }

  CopyMem (Node->Oid, Oid, OidSize);
  Node->OidSize = OidSize;
  InsertTailList (&State->Capabilities, &Node->Link);
  State->CapabilityCount++;
  State->OidBytes += OidSize;
}

STATIC
VOID
CollectNidAsOid (
  IN OUT COLLECT_STATE  *State,
  IN     INT32          Nid
  )
{
  ASN1_OBJECT  *Obj;
  CHAR8        Oid[MAX_ALGORITHM_OID_SIZE];
  int          Length;

  Obj = OBJ_nid2obj (Nid);
  if (Obj == NULL) {
    return;
  }

  Length = OBJ_obj2txt (Oid, sizeof (Oid), Obj, 1);
  if ((Length <= 0) || ((UINTN)Length >= sizeof (Oid))) {
    return;
  }

  Oid[Length] = '\0';
  CollectOid (State, Oid);
}

STATIC
EFI_STATUS
BuildCapabilityArray (
  IN OUT COLLECT_STATE          *State,
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  )
{
  UINTN                     ArraySize;
  UINTN                     AllocationSize;
  BASE_CRYPT_OP_CAPABILITY  *Result;
  CHAR8                     *OidCursor;
  UINTN                     Index;
  LIST_ENTRY                *Link;
  CAPABILITY_NODE           *Node;

  if (EFI_ERROR (State->Status)) {
    return State->Status;
  }

  if (State->CapabilityCount == 0) {
    return EFI_SUCCESS;
  }

  if (State->CapabilityCount > (MAX_UINTN / sizeof (*Result))) {
    return EFI_OUT_OF_RESOURCES;
  }

  ArraySize = State->CapabilityCount * sizeof (*Result);
  if (ArraySize > (MAX_UINTN - State->OidBytes)) {
    return EFI_OUT_OF_RESOURCES;
  }

  AllocationSize = ArraySize + State->OidBytes;
  Result         = AllocateZeroPool (AllocationSize);
  if (Result == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  OidCursor = (CHAR8 *)Result + ArraySize;
  Index     = 0;
  for (Link = GetFirstNode (&State->Capabilities);
       !IsNull (&State->Capabilities, Link);
       Link = GetNextNode (&State->Capabilities, Link))
  {
    Node = BASE_CR (Link, CAPABILITY_NODE, Link);
    CopyMem (OidCursor, Node->Oid, Node->OidSize);
    Result[Index].AlgorithmOid     = OidCursor;
    Result[Index].AlgorithmOidSize = Node->OidSize;
    OidCursor                     += Node->OidSize;
    Index++;
  }

  *Capabilities    = Result;
  *CapabilityCount = State->CapabilityCount;
  return EFI_SUCCESS;
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
  COLLECT_STATE  *State;
  INT32          DigestNid;
  UINTN          PkIndex;
  INT32          SignatureNid;

  State = (COLLECT_STATE *)Arg;
  if (EFI_ERROR (State->Status) || !IsFixedOutputDigest (Md)) {
    return;
  }

  DigestNid = EVP_MD_get_type (Md);
  if (DigestNid == NID_undef) {
    return;
  }

  for (PkIndex = 0; PkIndex < ARRAY_SIZE (mPassAPkTypes); PkIndex++) {
    if (!State->PkAvail[PkIndex]) {
      continue;
    }

    SignatureNid = NID_undef;
    if (OBJ_find_sigid_by_algs (
          &SignatureNid,
          DigestNid,
          mPassAPkTypes[PkIndex].PkNid
          ) != 1)
    {
      continue;
    }

    if (State->Accept (SignatureNid, State->AcceptCtx)) {
      CollectNidAsOid (State, SignatureNid);
    }
  }
}

STATIC
VOID
NameVisitorPassB (
  CONST CHAR8  *Name,
  VOID         *Arg
  )
{
  COLLECT_STATE  *State;
  INT32          Nid;

  State = (COLLECT_STATE *)Arg;
  if (EFI_ERROR (State->Status)) {
    return;
  }

  Nid = OBJ_txt2nid (Name);
  if (IsSignatureNid (Nid) && State->Accept (Nid, State->AcceptCtx)) {
    CollectNidAsOid (State, Nid);
  }
}

STATIC
VOID
SignatureVisitorPassB (
  EVP_SIGNATURE  *Signature,
  VOID           *Arg
  )
{
  EVP_SIGNATURE_names_do_all (Signature, NameVisitorPassB, Arg);
}

STATIC
VOID
DigestVisitor (
  EVP_MD  *Md,
  VOID    *Arg
  )
{
  COLLECT_STATE  *State;
  INT32          DigestNid;

  State = (COLLECT_STATE *)Arg;
  if (EFI_ERROR (State->Status) || !IsFixedOutputDigest (Md)) {
    return;
  }

  DigestNid = EVP_MD_get_type (Md);
  if (DigestNid != NID_undef) {
    CollectNidAsOid (State, DigestNid);
  }
}

EFI_STATUS
CryptOpCreateCapabilities (
  IN  CONST CHAR8               *CONST  *AlgorithmOids OPTIONAL,
  IN  UINTN                             AlgorithmCount,
  OUT BASE_CRYPT_OP_CAPABILITY          **Capabilities,
  OUT UINTN                             *CapabilityCount
  )
{
  COLLECT_STATE  State;
  EFI_STATUS     Status;
  UINTN          Index;

  if (Capabilities != NULL) {
    *Capabilities = NULL;
  }

  if (CapabilityCount != NULL) {
    *CapabilityCount = 0;
  }

  if ((Capabilities == NULL) || (CapabilityCount == NULL) ||
      ((AlgorithmCount != 0) && (AlgorithmOids == NULL)))
  {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&State, sizeof (State));
  InitializeListHead (&State.Capabilities);
  State.Status = EFI_SUCCESS;

  for (Index = 0; Index < AlgorithmCount; Index++) {
    if (AlgorithmOids[Index] == NULL) {
      Status = EFI_INVALID_PARAMETER;
      goto Exit;
    }

    CollectOid (&State, AlgorithmOids[Index]);
  }

  Status = BuildCapabilityArray (&State, Capabilities, CapabilityCount);

Exit:
  FreeCollectedCapabilities (&State);
  return Status;
}

EFI_STATUS
CryptOpGetProviderDigestCapabilities (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  )
{
  COLLECT_STATE  State;
  EFI_STATUS     Status;

  if (Capabilities != NULL) {
    *Capabilities = NULL;
  }

  if (CapabilityCount != NULL) {
    *CapabilityCount = 0;
  }

  if ((Capabilities == NULL) || (CapabilityCount == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&State, sizeof (State));
  InitializeListHead (&State.Capabilities);
  State.Status = EFI_SUCCESS;

  EVP_MD_do_all_provided (NULL, DigestVisitor, &State);
  Status = BuildCapabilityArray (&State, Capabilities, CapabilityCount);
  FreeCollectedCapabilities (&State);
  return Status;
}

EFI_STATUS
CryptOpGetProviderSignatureCapabilities (
  IN  CRYPTO_OP_SIG_ACCEPT_FN   Accept,
  IN  VOID                      *Ctx,
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  )
{
  COLLECT_STATE  State;
  EFI_STATUS     Status;
  BOOLEAN        PkAvailable[ARRAY_SIZE (mPassAPkTypes)];
  UINTN          PkIndex;

  if (Capabilities != NULL) {
    *Capabilities = NULL;
  }

  if (CapabilityCount != NULL) {
    *CapabilityCount = 0;
  }

  if ((Accept == NULL) || (Capabilities == NULL) || (CapabilityCount == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&State, sizeof (State));
  InitializeListHead (&State.Capabilities);
  State.Status    = EFI_SUCCESS;
  State.Accept    = Accept;
  State.AcceptCtx = Ctx;

  for (PkIndex = 0; PkIndex < ARRAY_SIZE (mPassAPkTypes); PkIndex++) {
    PkAvailable[PkIndex] = PkTypeIsAvailable (mPassAPkTypes[PkIndex].KeyMgmtName);
  }

  State.PkAvail = PkAvailable;
  EVP_MD_do_all_provided (NULL, DigestVisitorPassA, &State);
  EVP_SIGNATURE_do_all_provided (NULL, SignatureVisitorPassB, &State);

  Status = BuildCapabilityArray (&State, Capabilities, CapabilityCount);
  FreeCollectedCapabilities (&State);
  return Status;
}
