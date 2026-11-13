/** @file
  Dispatch provider-backed crypto-operation capability queries.

  Copyright (c) Microsoft Corporation
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

/**
  Dispatch a crypto-operation query to its provider-backed capability handler.

  Successful descriptors and OID strings share one caller-owned allocation,
  released once with FreePool(). Empty sets return NULL/zero. Errors clear both
  available outputs. Results describe algorithms, not trust or feature policy.

  @param[in]  OpIdGuid         Operation GUID declared in Guid/CryptoOpId.h.
  @param[out] Capabilities     Receives the owned capability array.
  @param[out] CapabilityCount  Receives the array element count.

  @retval EFI_SUCCESS           The query completed, possibly with an empty set.
  @retval EFI_INVALID_PARAMETER  An argument is NULL.
  @retval EFI_NOT_FOUND          The operation GUID is unknown.
  @retval EFI_OUT_OF_RESOURCES  The handler could not allocate its result.
**/
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
