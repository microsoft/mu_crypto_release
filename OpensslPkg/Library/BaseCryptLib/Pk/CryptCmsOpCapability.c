/** @file
  Provider signature and content-digest capabilities for PKCS#7/CMS.

  Copyright (c) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include "CryptOpCapability.h"

/**
  Accept every candidate provider signature without applying feature policy.

  @param[in] SigNid  Candidate signature identifier; unused.
  @param[in] Ctx     Caller context; unused.

  @retval TRUE  Every candidate is accepted.
**/
STATIC
BOOLEAN
EFIAPI
CmsAccept (
  IN INT32  SigNid,
  IN VOID   *Ctx
  )
{
  return TRUE;
}

/**
  Report the provider signature OID set for PKCS#7/CMS verification.

  No trust or feature-policy filtering is applied. Descriptors and strings share
  one allocation released once with FreePool(). Empty results return NULL/zero.
  With valid output pointers, errors clear both outputs.

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
  )
{
  return CryptOpGetProviderSignatureCapabilities (
           CmsAccept,
           NULL,
           Capabilities,
           CapabilityCount
           );
}

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
  )
{
  return CryptOpGetProviderDigestCapabilities (Capabilities, CapabilityCount);
}
