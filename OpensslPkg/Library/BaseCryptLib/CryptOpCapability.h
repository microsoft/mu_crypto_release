/** @file
  Internal interfaces for provider-backed crypto capability reporting.

  Copyright (c) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef BASE_CRYPT_LIB_OPENSSLPKG_OP_CAPABILITY_H_
#define BASE_CRYPT_LIB_OPENSSLPKG_OP_CAPABILITY_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

/**
  Decide whether an operation accepts a candidate provider signature identifier.

  @param[in] SigNid  OpenSSL signature identifier.
  @param[in] Ctx     Opaque operation-specific context; may be NULL.

  @retval TRUE   Include the candidate in the operation's capability set.
  @retval FALSE  Exclude the candidate.
**/
typedef
BOOLEAN
(EFIAPI *CRYPTO_OP_SIG_ACCEPT_FN)(
  IN INT32  SigNid,
  IN VOID   *Ctx
  );

/**
  Collect provider signature OIDs accepted by the supplied operation filter.

  Results describe algorithms, not exact signature/digest profiles. Descriptors
  and strings share one allocation released once with FreePool(). Empty results
  return NULL/zero. With valid output pointers, errors clear both outputs.

  @param[in]  Accept           Candidate signature filter.
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
  );

/**
  Enumerate unique fixed-output digest OIDs from the default library context.

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
  );

/**
  Copy unique OID strings into a caller-owned capability array.

  Empty or oversized strings are skipped. Descriptors and strings share one
  allocation released once with FreePool(). Empty results return NULL/zero.
  With valid output pointers, errors clear both outputs.

  @param[in]  AlgorithmOids    Input strings; may be NULL when the count is zero.
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
  );

/**
  Report provider signature OIDs for PKCS#7/CMS without trust-policy filtering.

  Descriptors and strings share one allocation released once with FreePool().
  Empty results return NULL/zero. With valid output pointers, errors clear both
  outputs.

  @param[out] Capabilities     Receives the owned capability array.
  @param[out] CapabilityCount  Receives the array element count.

  @retval EFI_SUCCESS           The query completed, possibly with an empty set.
  @retval EFI_INVALID_PARAMETER  An output pointer is NULL.
  @retval EFI_OUT_OF_RESOURCES  Allocation failed or size arithmetic overflowed.
**/
EFI_STATUS
EFIAPI
CmsVerifyOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

/**
  Report fixed-output provider digest OIDs for PKCS#7/CMS content.

  Descriptors and strings share one allocation released once with FreePool().
  Empty results return NULL/zero. With valid output pointers, errors clear both
  outputs.

  @param[out] Capabilities     Receives the owned capability array.
  @param[out] CapabilityCount  Receives the array element count.

  @retval EFI_SUCCESS           The query completed, possibly with an empty set.
  @retval EFI_INVALID_PARAMETER  An output pointer is NULL.
  @retval EFI_OUT_OF_RESOURCES  Allocation failed or size arithmetic overflowed.
**/
EFI_STATUS
EFIAPI
CmsContentDigestOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

/**
  Report Authenticode signature OIDs using the provider's CMS signature set.

  Descriptors and strings share one allocation released once with FreePool().
  Empty results return NULL/zero. With valid output pointers, errors clear both
  outputs.

  @param[out] Capabilities     Receives the owned capability array.
  @param[out] CapabilityCount  Receives the array element count.

  @retval EFI_SUCCESS           The query completed, possibly with an empty set.
  @retval EFI_INVALID_PARAMETER  An output pointer is NULL.
  @retval EFI_OUT_OF_RESOURCES  Allocation failed or size arithmetic overflowed.
**/
EFI_STATUS
EFIAPI
AuthenticodeVerifyOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

/**
  Report SHA-1/256/384/512 image-hash OIDs whose BaseCryptLib contexts initialize.

  Descriptors and strings share one allocation released once with FreePool().
  Empty results return NULL/zero. With valid output pointers, errors clear both
  outputs.

  @param[out] Capabilities     Receives the owned capability array.
  @param[out] CapabilityCount  Receives the array element count.

  @retval EFI_SUCCESS           The query completed, possibly with an empty set.
  @retval EFI_INVALID_PARAMETER  An output pointer is NULL.
  @retval EFI_OUT_OF_RESOURCES  Allocation failed or size arithmetic overflowed.
**/
EFI_STATUS
EFIAPI
AuthenticodeHashOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

#endif // BASE_CRYPT_LIB_OPENSSLPKG_OP_CAPABILITY_H_
