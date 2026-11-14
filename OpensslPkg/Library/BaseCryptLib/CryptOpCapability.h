/** @file
  Internal interfaces for provider-backed crypto capability reporting.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef BASE_CRYPT_LIB_OPENSSLPKG_OP_CAPABILITY_H_
#define BASE_CRYPT_LIB_OPENSSLPKG_OP_CAPABILITY_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

typedef
BOOLEAN
(EFIAPI *CRYPTO_OP_SIG_ACCEPT_FN)(
  IN INT32  SigNid,
  IN VOID   *Ctx
  );

EFI_STATUS
CryptOpGetProviderSignatureCapabilities (
  IN  CRYPTO_OP_SIG_ACCEPT_FN   Accept,
  IN  VOID                      *Ctx,
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

EFI_STATUS
CryptOpGetProviderDigestCapabilities (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

EFI_STATUS
CryptOpCreateCapabilities (
  IN  CONST CHAR8               *CONST  *AlgorithmOids OPTIONAL,
  IN  UINTN                             AlgorithmCount,
  OUT BASE_CRYPT_OP_CAPABILITY          **Capabilities,
  OUT UINTN                             *CapabilityCount
  );

EFI_STATUS
EFIAPI
CmsVerifyOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

EFI_STATUS
EFIAPI
CmsContentDigestOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

EFI_STATUS
EFIAPI
AuthenticodeVerifyOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

EFI_STATUS
EFIAPI
AuthenticodeHashOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

#endif // BASE_CRYPT_LIB_OPENSSLPKG_OP_CAPABILITY_H_
