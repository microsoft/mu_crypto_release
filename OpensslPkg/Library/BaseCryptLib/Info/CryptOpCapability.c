/** @file
  Dispatch provider-backed crypto-operation capability queries.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include "CryptOpCapability.h"
#include <Guid/CryptoOpId.h>

typedef
EFI_STATUS
(EFIAPI *CRYPTO_OP_HANDLER)(
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  );

typedef struct {
  CONST EFI_GUID       *OpId;
  CRYPTO_OP_HANDLER    Handler;
} CRYPTO_OP_DISPATCH;

STATIC CONST CRYPTO_OP_DISPATCH  mCryptoOpDispatch[] = {
  { &gCryptoOpCmsVerifyGuid,          CmsVerifyOpCapability          },
  { &gCryptoOpCmsContentDigestGuid,   CmsContentDigestOpCapability   },
  { &gCryptoOpAuthenticodeVerifyGuid, AuthenticodeVerifyOpCapability },
  { &gCryptoOpAuthenticodeHashGuid,   AuthenticodeHashOpCapability   },
};

EFI_STATUS
EFIAPI
GetCryptoOpCapability (
  IN  CONST EFI_GUID            *OpIdGuid,
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  )
{
  UINTN  Index;

  if (Capabilities != NULL) {
    *Capabilities = NULL;
  }

  if (CapabilityCount != NULL) {
    *CapabilityCount = 0;
  }

  if ((OpIdGuid == NULL) || (Capabilities == NULL) || (CapabilityCount == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  for (Index = 0; Index < ARRAY_SIZE (mCryptoOpDispatch); Index++) {
    if (CompareGuid (OpIdGuid, mCryptoOpDispatch[Index].OpId)) {
      return mCryptoOpDispatch[Index].Handler (Capabilities, CapabilityCount);
    }
  }

  return EFI_NOT_FOUND;
}
