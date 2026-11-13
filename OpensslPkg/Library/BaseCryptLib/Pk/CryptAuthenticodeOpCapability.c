/** @file
  Provider signature capabilities for Authenticode verification.

  Copyright (c) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include "CryptOpCapability.h"

/**
  Report Authenticode signature OIDs using the provider's CMS signature set.

  This does not evaluate certificate trust or image-verification policy.
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
  )
{
  return CmsVerifyOpCapability (Capabilities, CapabilityCount);
}
