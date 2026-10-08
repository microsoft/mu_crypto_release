/** @file
  ECIT capability reporting for Authenticode verification.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include "CryptOpCapability.h"

EFI_STATUS
EFIAPI
AuthenticodeVerifyOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  )
{
  return CmsVerifyOpCapability (Capabilities, CapabilityCount);
}
