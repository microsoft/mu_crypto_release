/** @file
  Provider signature and content-digest capabilities for PKCS#7/CMS.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include "CryptOpCapability.h"

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

EFI_STATUS
EFIAPI
CmsContentDigestOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  )
{
  return CryptOpGetProviderDigestCapabilities (Capabilities, CapabilityCount);
}
