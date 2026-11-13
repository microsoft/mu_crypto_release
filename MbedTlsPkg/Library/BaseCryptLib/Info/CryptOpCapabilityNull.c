/** @file
  Unsupported capability reporting for MbedTLS library instances.

  Copyright (c) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseCryptLib.h>

/**
  Report that this MbedTLS instance does not expose capability reporting.

  No allocation is made. Every non-NULL output is cleared, including when another
  argument is NULL.

  @param[in]  OpIdGuid         Operation GUID to query.
  @param[out] Capabilities     Receives NULL.
  @param[out] CapabilityCount  Receives zero.

  @retval EFI_UNSUPPORTED        Capability reporting is unavailable.
  @retval EFI_INVALID_PARAMETER  An argument is NULL.
**/
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
