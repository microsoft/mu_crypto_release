/** @file
  Unsupported capability reporting for MbedTLS library instances.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseCryptLib.h>

EFI_STATUS
EFIAPI
GetCryptoOpCapability (
  IN  CONST EFI_GUID            *OpIdGuid,
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  )
{
  if (Capabilities != NULL) {
    *Capabilities = NULL;
  }

  if (CapabilityCount != NULL) {
    *CapabilityCount = 0;
  }

  if ((OpIdGuid == NULL) || (Capabilities == NULL) || (CapabilityCount == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_UNSUPPORTED;
}
