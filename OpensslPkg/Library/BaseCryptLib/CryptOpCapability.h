/** @file
  Private BaseCryptLib (OpensslPkg) header for ECIT capability reporting
  internals.

  Public API is GetCryptoOpCapability(OpIdGuid, ...) declared in
  Library/BaseCryptLib.h. This header is library-private: it lets the
  GUID dispatcher in Info/CryptInfo.c reach the per-op handlers and lets
  per-op handlers reach the shared engine.

  Architecture
  ------------

   * Info/CryptInfo.c carries the GUID -> handler dispatch table.

   * Per-op handlers live in Pk/Crypt<Op>OpCapability.c next to their
     verify pipeline. Each handler defines a single accept predicate and
     hands it to the shared engine; that's the only per-op code.

   * Pk/CryptOpCapabilityCommon.c implements the engine. It walks the
     OpenSSL provider via two complementary passes (digest+key crossed
     through OBJ_find_sigid_by_algs, plus EVP_SIGNATURE name walk) and
     emits accepted OIDs as a CSV-encoded NUL-terminated payload.

  Design rules
  ------------
   * BaseCryptLib must NEVER ship a static OID allowlist for any op. The
     truth source is always the linked OpenSSL provider. New algorithms
     in OpensslLib's deflt_signature[] flow through automatically.

   * Per-op handlers describe their op as a small predicate over the
     provider's published algorithms. They do not enumerate algorithms
     themselves.

   * Headers in this directory are LIBRARY-PRIVATE. Anything callers
     outside BaseCryptLib need belongs in MU_BASECORE/CryptoPkg/Include/...

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef BASE_CRYPT_LIB_OPENSSLPKG_OP_CAPABILITY_H_
#define BASE_CRYPT_LIB_OPENSSLPKG_OP_CAPABILITY_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

/**
  Per-op acceptance predicate. The engine calls this for every signature
  NID the provider can form (digest+key composites and direct sig algs).
  Return TRUE to include the NID's OID in the payload, FALSE to drop it.

  @param[in]  SigNid  OpenSSL signature NID (e.g. NID_sha256WithRSAEncryption,
                      NID_ml_dsa_65). Always a NID OBJ_find_sigid_algs
                      recognizes.
  @param[in]  Ctx     Opaque caller context passed through unchanged from
                      CryptOpEmitProviderSignatureOids; may be NULL.

  @retval TRUE   Emit this NID's OID in the payload.
  @retval FALSE  Skip this NID.
**/
typedef
BOOLEAN
(EFIAPI *CRYPTO_OP_SIG_ACCEPT_FN)(
  IN INT32  SigNid,
  IN VOID   *Ctx
  );

/**
  Engine entry point used by per-op handlers.

  Walks every signature algorithm the linked OpenSSL provider can form,
  filters through Accept, and writes the accepted OIDs as a CSV-encoded
  NUL-terminated ASCII payload following the standard ECIT sizing
  contract.

  Two complementary passes cover OpenSSL's bifurcated signature surface:
  the legacy sigid table (sha*WithRSA, ecdsa-with-sha*) and the provider's
  EVP_SIGNATURE algorithm list (RSA-PSS, EdDSA, ML-DSA, ...). See
  Pk/CryptOpCapabilityCommon.c for the design.

  @param[in]      Accept      Predicate; called once per candidate sig
                              NID. Must not be NULL.
  @param[in]      Ctx         Opaque pointer passed unchanged to Accept.
                              May be NULL.
  @param[out]     Buffer      NULL probes required size, else receives
                              CSV-encoded NUL-terminated payload.
  @param[in,out]  BufferSize  In: capacity. Out: bytes written or required
                              (always includes the trailing NUL).

  @retval EFI_SUCCESS           Sizing probe answered, or full payload written.
  @retval EFI_BUFFER_TOO_SMALL  Buffer non-NULL and capacity insufficient;
                                *BufferSize set to required size.
  @retval EFI_INVALID_PARAMETER Accept or BufferSize is NULL.
**/
EFI_STATUS
CryptOpEmitProviderSignatureOids (
  IN     CRYPTO_OP_SIG_ACCEPT_FN  Accept,
  IN     VOID                     *Ctx,
  OUT    CHAR8                    *Buffer       OPTIONAL,
  IN OUT UINTN                    *BufferSize
  );

/**
  PKCS#7 verify op handler (gCryptoOpPkcs7VerifyGuid).

  Reports the algorithm OIDs the linked OpenSSL provider can verify when
  the BaseCryptLib PKCS#7/CMS verify pipeline hands a signature straight
  to it. The accept predicate is "anything OpenSSL recognizes as a
  signature NID" -- the verify path doesn't filter further.

  @param[out]     Buffer      NULL probes required size, else receives payload.
  @param[in,out]  BufferSize  In: capacity. Out: bytes written or required.

  @retval EFI_SUCCESS           Sizing probe / fetch succeeded.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small; *BufferSize set to required.
**/
EFI_STATUS
EFIAPI
Pkcs7VerifyOpCapability (
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  );

/**
  Authenticode verify op handler (gCryptoOpAuthenticodeVerifyGuid).

  Reports the algorithm OIDs the BaseCryptLib AuthenticodeVerify pipeline
  will accept. Authenticode is strictly a subset of PKCS#7 verify: the
  pipeline rejects signatures whose inner digestAlgorithm is not one of
  SHA-1, SHA-256, SHA-384, SHA-512 (see AuthenticodeExpectedDigestNid in
  Pk/CryptAuthenticode.c). The handler mirrors that policy as the accept
  predicate so the report stays in lockstep with verify behavior with no
  separate allowlist.

  @param[out]     Buffer      NULL probes required size, else receives payload.
  @param[in,out]  BufferSize  In: capacity. Out: bytes written or required.

  @retval EFI_SUCCESS           Sizing probe / fetch succeeded.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small; *BufferSize set to required.
**/
EFI_STATUS
EFIAPI
AuthenticodeVerifyOpCapability (
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  );

#endif // BASE_CRYPT_LIB_OPENSSLPKG_OP_CAPABILITY_H_
