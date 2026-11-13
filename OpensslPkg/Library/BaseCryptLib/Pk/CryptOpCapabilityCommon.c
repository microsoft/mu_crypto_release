/** @file
  Provider-backed algorithm OID enumeration for crypto capabilities.

  Copyright (c) Microsoft Corporation
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

/**
  Check whether a provider digest has a positive, fixed output size.

  @param[in] Md  Provider digest to inspect.

  @retval TRUE   The digest has a positive size and is not an XOF.
  @retval FALSE  The digest has no fixed positive output size.
**/
STATIC
BOOLEAN
IsFixedOutputDigest (
  IN CONST EVP_MD  *Md
  )
{
  return (BOOLEAN)((EVP_MD_get_size (Md) > 0) &&
                   ((EVP_MD_get_flags (Md) & EVP_MD_FLAG_XOF) == 0));
}

/**
  Probe whether the default library context can create a key-management context.

  @param[in] KeyMgmtName  OpenSSL key-management algorithm name.

  @retval TRUE   A context was created and released.
  @retval FALSE  A context could not be created.
**/
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

/**
  Free all temporary OID nodes without changing the saved counters or status.

  @param[in,out] State  Collection state whose list is drained.
**/
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

/**
  Check whether the temporary collection already contains an OID string.

  @param[in] State  Collection state to search.
  @param[in] Oid    NUL-terminated dotted-decimal OID to find.

  @retval TRUE   The OID is already collected.
  @retval FALSE  The OID is not collected.
**/
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

/**
  Copy a unique, nonempty OID that fits the temporary node.

  Duplicate or oversized strings and calls after a collection error are ignored.
  Allocation or counter overflow records EFI_OUT_OF_RESOURCES in State->Status.

  @param[in,out] State  Collection state to update.
  @param[in]     Oid    NUL-terminated dotted-decimal OID to copy.
**/
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

/**
  Convert an OpenSSL object identifier to a dotted-decimal OID and collect it.

  Unknown identifiers and OIDs that do not fit the conversion buffer are skipped.

  @param[in,out] State  Collection state to update.
  @param[in]     Nid    OpenSSL object identifier to convert.
**/
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

/**
  Copy collected OIDs into one allocation containing descriptors and strings.

  The caller initializes both outputs to NULL/zero before calling this helper.
  Empty collections leave those outputs unchanged. The temporary list remains
  owned by State; the caller frees a returned array once with FreePool().

  @param[in,out] State            Collection state to serialize.
  @param[out]    Capabilities     Receives the owned capability array.
  @param[out]    CapabilityCount  Receives the array element count.

  @retval EFI_SUCCESS           The array was built or the collection was empty.
  @retval EFI_OUT_OF_RESOURCES  Collection failed, allocation failed, or size
                               arithmetic would overflow.
**/
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

/**
  Check whether OpenSSL maps an object identifier to signature components.

  @param[in] Nid  OpenSSL object identifier to inspect.

  @retval TRUE   OpenSSL recognizes a signature-algorithm mapping.
  @retval FALSE  The identifier is undefined or has no signature mapping.
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
  Collect accepted signature OIDs pairing a digest with available key types.

  This OpenSSL digest-enumeration callback skips variable-output digests and
  digest/key pairs without a registered signature OID.

  @param[in]     Md   Provider digest being enumerated.
  @param[in,out] Arg  COLLECT_STATE containing the key availability and filter.
**/
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

/**
  Collect a provider signature name if it maps to an accepted signature OID.

  @param[in]     Name  Provider signature algorithm name or alias.
  @param[in,out] Arg   COLLECT_STATE containing the acceptance filter.
**/
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

/**
  Visit every name advertised by an enumerated provider signature algorithm.

  @param[in]     Signature  Provider signature algorithm being enumerated.
  @param[in,out] Arg        COLLECT_STATE passed to each name callback.
**/
STATIC
VOID
SignatureVisitorPassB (
  EVP_SIGNATURE  *Signature,
  VOID           *Arg
  )
{
  EVP_SIGNATURE_names_do_all (Signature, NameVisitorPassB, Arg);
}

/**
  Collect the OID of an enumerated, fixed-output provider digest.

  @param[in]     Md   Provider digest being enumerated.
  @param[in,out] Arg  COLLECT_STATE receiving the digest OID.
**/
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

/**
  Copy unique OID strings into a caller-owned capability array.

  Descriptors and strings share one allocation released once with FreePool().
  Empty results return NULL/zero. With valid output pointers, errors clear both
  outputs. Empty or oversized strings are skipped by the collector.

  @param[in]  AlgorithmOids    Input OID strings; may be NULL when the count is zero.
  @param[in]  AlgorithmCount   Number of input strings.
  @param[out] Capabilities     Receives the owned capability array.
  @param[out] CapabilityCount  Receives the array element count.

  @retval EFI_SUCCESS           The array was built, possibly empty.
  @retval EFI_INVALID_PARAMETER  An output or required input pointer is NULL.
  @retval EFI_OUT_OF_RESOURCES  Allocation failed or size arithmetic overflowed.
**/
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

  if ((Capabilities == NULL) || (CapabilityCount == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *Capabilities    = NULL;
  *CapabilityCount = 0;

  if ((AlgorithmCount != 0) && (AlgorithmOids == NULL)) {
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

/**
  Enumerate unique OIDs for fixed-output digests in the default library context.

  Descriptors and strings share one allocation released once with FreePool().
  Empty results return NULL/zero. With valid output pointers, errors clear both
  outputs.

  @param[out] Capabilities     Receives the owned capability array.
  @param[out] CapabilityCount  Receives the array element count.

  @retval EFI_SUCCESS           Enumeration completed, possibly with an empty set.
  @retval EFI_INVALID_PARAMETER  An output pointer is NULL.
  @retval EFI_OUT_OF_RESOURCES  Allocation failed or size arithmetic overflowed.
**/
EFI_STATUS
CryptOpGetProviderDigestCapabilities (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  )
{
  COLLECT_STATE  State;
  EFI_STATUS     Status;

  if ((Capabilities == NULL) || (CapabilityCount == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *Capabilities    = NULL;
  *CapabilityCount = 0;

  ZeroMem (&State, sizeof (State));
  InitializeListHead (&State.Capabilities);
  State.Status = EFI_SUCCESS;

  EVP_MD_do_all_provided (NULL, DigestVisitor, &State);
  Status = BuildCapabilityArray (&State, Capabilities, CapabilityCount);
  FreeCollectedCapabilities (&State);
  return Status;
}

/**
  Collect provider signature OIDs accepted by an operation-specific filter.

  Combines digest/key mappings, advertised signature names, and an explicit
  RSA-PSS initialization probe. Results describe algorithms, not exact profiles.
  Descriptors and strings share one allocation released once with FreePool().
  Empty results return NULL/zero. With valid output pointers, errors clear both
  outputs.

  @param[in]  Accept           Filter called for candidate signature identifiers.
  @param[in]  Ctx              Opaque context passed to Accept; may be NULL.
  @param[out] Capabilities     Receives the owned capability array.
  @param[out] CapabilityCount  Receives the array element count.

  @retval EFI_SUCCESS           Enumeration completed, possibly with an empty set.
  @retval EFI_INVALID_PARAMETER  The filter or an output pointer is NULL.
  @retval EFI_OUT_OF_RESOURCES  Allocation failed or size arithmetic overflowed.
**/
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

  if ((Capabilities == NULL) || (CapabilityCount == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *Capabilities    = NULL;
  *CapabilityCount = 0;

  if (Accept == NULL) {
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
