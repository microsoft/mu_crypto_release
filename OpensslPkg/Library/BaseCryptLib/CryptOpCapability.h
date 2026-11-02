/** @file
  Internal interfaces for ECIT capability reporting in OpenSSL BaseCryptLib.

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
  Return TRUE to include the NID's OID in the capability array, FALSE to
  drop it.

  @param[in]  SigNid  OpenSSL signature NID (e.g. NID_sha256WithRSAEncryption,
                      NID_ml_dsa_65). Always a NID OBJ_find_sigid_algs
                      recognizes.
  @param[in]  Ctx     Opaque caller context passed through unchanged from
                      CryptOpGetProviderSignatureCapabilities; may be NULL.

  @retval TRUE   Include this NID's OID in the capability array.
  @retval FALSE  Skip this NID.
**/
typedef
BOOLEAN
(EFIAPI *CRYPTO_OP_SIG_ACCEPT_FN)(
  IN INT32  SigNid,
  IN VOID   *Ctx
  );

/**
  Collect the signature algorithms available from the linked provider.

  Walks every signature algorithm the linked OpenSSL provider can form,
  filters through Accept, and returns the accepted OIDs as one allocated
  capability array.

  Two complementary passes cover OpenSSL's bifurcated signature surface:
  the legacy sigid table (sha*WithRSA, ecdsa-with-sha*) and the provider's
  EVP_SIGNATURE algorithm list (RSA-PSS, EdDSA, ML-DSA, ...). See
  Pk/CryptOpCapabilityCommon.c for the design.

  @param[in]  Accept          Predicate called for each candidate signature NID.
  @param[in]  Ctx             Opaque pointer passed unchanged to Accept.
  @param[out] Capabilities    Allocated array of supported algorithms.
  @param[out] CapabilityCount Number of elements in Capabilities.

  @retval EFI_SUCCESS            The capability array was returned.
  @retval EFI_OUT_OF_RESOURCES   The capability array could not be allocated.
  @retval EFI_INVALID_PARAMETER  An argument is NULL.
**/
EFI_STATUS
CryptOpGetProviderSignatureCapabilities (
  IN  CRYPTO_OP_SIG_ACCEPT_FN   Accept,
  IN  VOID                      *Ctx,
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

/**
  Collect the fixed-output digest algorithms available from the linked
  OpenSSL provider.

  @param[out] Capabilities    Allocated array of supported algorithms.
  @param[out] CapabilityCount Number of elements in Capabilities.

  @retval EFI_SUCCESS            The capability array was returned.
  @retval EFI_OUT_OF_RESOURCES   The capability array could not be allocated.
  @retval EFI_INVALID_PARAMETER  An argument is NULL.
**/
EFI_STATUS
CryptOpGetProviderDigestCapabilities (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

/**
  Create one allocated capability array from OID strings.

  Duplicate OIDs are omitted. The returned array and strings share one
  allocation that the caller releases with FreePool().

  @param[in]  AlgorithmOids   Array of NUL-terminated dotted-decimal OIDs.
  @param[in]  AlgorithmCount  Number of elements in AlgorithmOids.
  @param[out] Capabilities    Allocated array of supported algorithms.
  @param[out] CapabilityCount Number of elements in Capabilities.

  @retval EFI_SUCCESS            The capability array was returned.
  @retval EFI_OUT_OF_RESOURCES   The capability array could not be allocated.
  @retval EFI_INVALID_PARAMETER  An argument is NULL.
**/
EFI_STATUS
CryptOpCreateCapabilities (
  IN  CONST CHAR8               *CONST  *AlgorithmOids OPTIONAL,
  IN  UINTN                             AlgorithmCount,
  OUT BASE_CRYPT_OP_CAPABILITY          **Capabilities,
  OUT UINTN                             *CapabilityCount
  );

/**
  PKCS#7 verify op handler (gCryptoOpCmsVerifyGuid).

  Reports the algorithm OIDs the linked OpenSSL provider can verify when
  the BaseCryptLib PKCS#7/CMS verify pipeline hands a signature straight
  to it. The accept predicate is "anything OpenSSL recognizes as a
  signature NID" -- the verify path doesn't filter further.

  @param[out] Capabilities    Allocated array of supported algorithms.
  @param[out] CapabilityCount Number of elements in Capabilities.

  @retval EFI_SUCCESS            The capability array was returned.
  @retval EFI_OUT_OF_RESOURCES   The capability array could not be allocated.
  @retval EFI_INVALID_PARAMETER  An argument is NULL.
**/
EFI_STATUS
EFIAPI
CmsVerifyOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

/**
  Reports the content-digest algorithms supported for CMS SignedData.

  @param[out] Capabilities    Allocated array of supported algorithms.
  @param[out] CapabilityCount Number of elements in Capabilities.

  @retval EFI_SUCCESS            The capability array was returned.
  @retval EFI_OUT_OF_RESOURCES   The capability array could not be allocated.
  @retval EFI_INVALID_PARAMETER  An argument is NULL.
**/
EFI_STATUS
EFIAPI
CmsContentDigestOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
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

  @param[out] Capabilities    Allocated array of supported algorithms.
  @param[out] CapabilityCount Number of elements in Capabilities.

  @retval EFI_SUCCESS            The capability array was returned.
  @retval EFI_OUT_OF_RESOURCES   The capability array could not be allocated.
  @retval EFI_INVALID_PARAMETER  An argument is NULL.
**/
EFI_STATUS
EFIAPI
AuthenticodeVerifyOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

/**
  Authenticode image-hash op handler (gCryptoOpAuthenticodeHashGuid).

  Reports the dotted OIDs of the digest algorithms Authenticode image
  hashing (GetAuthenticodeHash) can compute in this build. Each candidate is
  probed through the same BaseCryptLib context initialization path used by
  GetAuthenticodeHash. Unlike the verify ops, this reports digest OIDs, not
  signature OIDs.

  @param[out] Capabilities    Allocated array of supported algorithms.
  @param[out] CapabilityCount Number of elements in Capabilities.

  @retval EFI_SUCCESS            The capability array was returned.
  @retval EFI_OUT_OF_RESOURCES   The capability array could not be allocated.
  @retval EFI_INVALID_PARAMETER  An argument is NULL.
**/
EFI_STATUS
EFIAPI
AuthenticodeHashOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

#endif // BASE_CRYPT_LIB_OPENSSLPKG_OP_CAPABILITY_H_
