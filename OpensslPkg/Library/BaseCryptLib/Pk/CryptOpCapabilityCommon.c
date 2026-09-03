/** @file
  ECIT capability reporting -- shared engine for op handlers.

  Implements provider-backed signature and digest OID enumeration. The
  iteration, OID conversion, dedupe, and EFI_BUFFER_TOO_SMALL contract
  are shared by the operation handlers.

  Two complementary passes cover OpenSSL's bifurcated signature surface:

    Pass A -- digest x pk-type cross-product (legacy "digest+key" sig OIDs)
              Walks EVP_MD_do_all_provided and, for each fixed-output digest
              crossed with each provider-available pk-type, queries
              OBJ_find_sigid_by_algs. Catches the PKCS#1 RSA family
              (sha*WithRSA, OID 1.2.840.113549.1.1.*) and ANSI X9.62 ECDSA
              (ecdsa-with-sha*, OID 1.2.840.10045.4.*). Two guards keep this
              honest, because OBJ_find_sigid_by_algs consults a STATIC table
              that does not know what the linked build actually ships: the
              pk-type must be present in the provider (PkTypeIsAvailable),
              and XOF digests are skipped (a legacy composite digest is
              always fixed-output).

    Pass B -- enumerate provider-published signature algorithms directly
              Walks EVP_SIGNATURE_do_all_provided and inspects each
              algorithm's published name list. Names that resolve to a
              signature NID registered in the legacy sigid table (per
              OBJ_find_sigid_algs) are emitted. Catches RSA-PSS, EdDSA,
              ML-DSA-44/65/87, and any future entry that carries a built-in
              NID registered in that table. Caveat -- NOT fully drift-proof:
              a purely provider-native algorithm whose name has no built-in
              NID (OBJ_txt2nid -> NID_undef) is enumerated but dropped here;
              reporting it would require a NID + sigid registration or a
              provider-based accept predicate (e.g. composite ML-DSA).

    Digests -- walks EVP_MD_do_all_provided and emits fixed-output digest
           algorithms with stable OIDs. XOFs are excluded because the
           CMS path does not configure the output lengths required by
           RFC 8702.

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
  Iteration state shared by provider enumeration callbacks.
**/
typedef struct {
  CHAR8                      *Buffer;       ///< Caller buffer; NULL on probe.
  UINTN                      BufferSize;    ///< Capacity; 0 when Buffer NULL.
  UINTN                      Written;       ///< Running required bytes (excl. NUL).
  UINTN                      Committed;     ///< Bytes actually placed in Buffer.
  BOOLEAN                    Overflow;      ///< Latches once a write was skipped.
  CRYPTO_OP_SIG_ACCEPT_FN    Accept;        ///< Per-op acceptance predicate.
  VOID                       *AcceptCtx;    ///< Caller context for Accept.
  CONST BOOLEAN              *PkAvail;      ///< Pass A: per-mPassAPkTypes provider availability.
} EMIT_STATE;

//
// Pass A search space: pk-types we ask OpenSSL about for each digest, paired
// with the provider key-management name used to confirm the type is actually
// present in the linked build.
//
// EVP_MD_do_all_provided x mPassAPkTypes enumerates every (digest, pk)
// signature combination the provider can form via the legacy sigid table, but
// only for pk-types the provider implements (see PkTypeIsAvailable). EdDSA
// pk-types are listed even though OpenSSL never returns a sigid for
// (digest, EdDSA) -- they're harmless no-ops -- so the search space stays a
// literal mirror of "asymmetric key types BaseCryptLib's pipeline supports".
//
typedef struct {
  INT32          PkNid;         ///< OpenSSL pk-type NID passed to OBJ_find_sigid_by_algs.
  CONST CHAR8    *KeyMgmtName;  ///< Provider keymgmt name for the availability probe.
} PASS_A_PK_TYPE;

STATIC CONST PASS_A_PK_TYPE  mPassAPkTypes[] = {
  { EVP_PKEY_RSA,     "RSA"     },
  { EVP_PKEY_EC,      "EC"      },
  { EVP_PKEY_ED25519, "ED25519" },
  { EVP_PKEY_ED448,   "ED448"   },
};

/**
  TRUE iff Md is a fixed-output digest usable through the fixed-length EVP
  finalize path. Extendable-output functions (SHAKE) report size 0 and set
  EVP_MD_FLAG_XOF; they have no single digest length, so they are neither a
  valid CMS content digest nor a legacy composite-signature digest.

  @param[in]  Md  Digest algorithm being inspected.

  @retval TRUE   Fixed-output digest.
  @retval FALSE  XOF or zero-length digest.
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
  TRUE iff the linked OpenSSL provider actually implements the named key-
  management (pk) type. Pass A crosses provider digests with the STATIC legacy
  sigid table, which knows composite OIDs (e.g. ecdsa-with-SHA256) regardless
  of whether this build ships the underlying key type. Probing the provider
  keeps the report from advertising signatures the build cannot perform.

  @param[in]  KeyMgmtName  Provider keymgmt name (e.g. "RSA", "EC").

  @retval TRUE   The provider implements this key type.
  @retval FALSE  Not available in this build.
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
  @param[in]      Nid    OpenSSL algorithm NID.
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
  Pass A callback. For every fixed-output digest the provider publishes, walk
  every provider-available pk-type in mPassAPkTypes and emit the legacy
  (digest, pk) sig OID when the accept predicate says yes. XOF digests and
  pk-types absent from this build are skipped so the static sigid table can
  never surface a composite the provider cannot actually perform.

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

  State = (EMIT_STATE *)Arg;

  //
  // A legacy composite-signature digest is always fixed-output; skipping XOFs
  // stops the static sigid table from surfacing an (XOF, pk) composite the
  // fixed-length signature path could not produce.
  //
  if (!IsFixedOutputDigest (Md)) {
    return;
  }

  DigestNid = EVP_MD_get_type (Md);
  if (DigestNid == NID_undef) {
    return;
  }

  for (PkIdx = 0; PkIdx < ARRAY_SIZE (mPassAPkTypes); PkIdx++) {
    //
    // Only advertise combos whose pk-type the provider actually implements;
    // OBJ_find_sigid_by_algs consults the static table and does not check.
    //
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

/**
  Emit one provider digest as a candidate CMS content pre-hash.

  In CMS SignedData the content is hashed into the message-digest attribute,
  and an ML-DSA signer covers that attribute via the signed attributes (RFC
  9882). That message-digest is computed through OpenSSL's fixed-length EVP
  digest interface, so the set of pre-hash algorithms "possible with ML-DSA"
  is simply the set that interface can produce -- enumerated from the provider
  so UEFI never carries its own digest allowlist.

  An algorithm qualifies when both hold:
    * it has a stable dotted OID to name it in the payload, and
    * it has a fixed output length. Extendable-output functions (SHAKE and
      friends) report size 0 / EVP_MD_FLAG_XOF; EVP_DigestFinal_ex cannot
      drive them to a fixed length without an explicit XOF-length parameter
      the CMS content-digest path does not set, so they are not usable here.
**/
STATIC
VOID
DigestVisitor (
  EVP_MD  *Md,
  VOID    *Arg
  )
{
  INT32  DigestNid;

  //
  // Fixed-output only: XOFs (SHAKE*) report size 0 and cannot be finalized to
  // a fixed length through the CMS content-digest path.
  //
  if (!IsFixedOutputDigest (Md)) {
    return;
  }

  DigestNid = EVP_MD_get_type (Md);
  if (DigestNid != NID_undef) {
    EmitNidAsOid ((EMIT_STATE *)Arg, DigestNid);
  }
}

EFI_STATUS
CryptOpEmitProviderDigestOids (
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  )
{
  EMIT_STATE  State;
  UINTN       Required;

  if (BufferSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&State, sizeof (State));
  State.Buffer     = Buffer;
  State.BufferSize = (Buffer != NULL) ? *BufferSize : 0;

  EVP_MD_do_all_provided (NULL, DigestVisitor, &State);

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

  //
  // Probe pk-type availability once up front; Pass A consults this so a static
  // sigid-table entry is emitted only when the provider implements the key
  // type (see PkTypeIsAvailable).
  //
  for (PkIdx = 0; PkIdx < ARRAY_SIZE (mPassAPkTypes); PkIdx++) {
    PkAvail[PkIdx] = PkTypeIsAvailable (mPassAPkTypes[PkIdx].KeyMgmtName);
  }

  State.PkAvail = PkAvail;

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
