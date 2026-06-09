/** @file
  Cryptographic Library Information Implementation.

  This module provides version information for the underlying OpenSSL library.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <Library/BaseLib.h>
#include <Guid/CryptoOpId.h>
#include "InternalCryptLib.h"

/**
  Gets the cryptographic provider version information.

  This function returns the version string of the cryptographic provider.
  For this OpenSSL implementation, it returns the OpenSSL version string.

  @param[out]     Buffer       Pointer to the buffer to receive the version string.
                               If NULL, the required buffer size is returned in BufferSize.
  @param[in,out]  BufferSize   On input, the size of the buffer in bytes.
                               On output, the size of the data copied to the buffer (including null terminator).
                               If Buffer is NULL, returns the required buffer size.

  @retval  EFI_SUCCESS            The version string was successfully copied to the buffer or
                                  the BufferSize was updated when a NULL buffer was provided.
  @retval  EFI_BUFFER_TOO_SMALL   The buffer is too small. BufferSize contains the required size.
  @retval  EFI_INVALID_PARAMETER  BufferSize is NULL.
**/
EFI_STATUS
EFIAPI
GetCryptoProviderVersionString (
  OUT    CHAR8  *Buffer,
  IN OUT UINTN  *BufferSize
  )
{
  CONST CHAR8  *VersionText;
  UINTN        RequiredSize;

  if (BufferSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  VersionText  = OPENSSL_VERSION_TEXT;
  RequiredSize = AsciiStrSize (VersionText);

  if (Buffer == NULL) {
    *BufferSize = RequiredSize;
    return EFI_SUCCESS;
  }

  if (*BufferSize < RequiredSize) {
    *BufferSize = RequiredSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  AsciiStrCpyS (Buffer, *BufferSize, VersionText);
  *BufferSize = RequiredSize;

  return EFI_SUCCESS;
}

#include "CryptOpCapability.h"

//
// Dispatch GetCryptoOpCapability() requests to operation-specific handlers.
//
//

/**
  Per-op handler signature. Same shape as the public
  GetCryptoOpCapability minus the OpIdGuid parameter (dispatch already
  matched it).

  @param[out]     Buffer      NULL probes required size, else receives payload.
  @param[in,out]  BufferSize  In: capacity. Out: bytes written or required.

  @retval EFI_SUCCESS           Sizing probe / fetch succeeded.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small; *BufferSize set to required.
**/
typedef
EFI_STATUS
(EFIAPI *CRYPTO_OP_HANDLER)(
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  );

/**
  Single row of the GUID -> handler dispatch table.

  Kept separate from the typedef so the table itself stays grep-friendly
  and easy to extend.
**/
typedef struct {
  CONST EFI_GUID       *OpId;
  CRYPTO_OP_HANDLER    Handler;
} CRYPTO_OP_DISPATCH;

//
// Crypto operation capability dispatch table.
//
STATIC CONST CRYPTO_OP_DISPATCH  mCryptoOpDispatch[] = {
  { &gCryptoOpPkcs7VerifyGuid,        Pkcs7VerifyOpCapability        },
  { &gCryptoOpAuthenticodeVerifyGuid, AuthenticodeVerifyOpCapability },
};

/**
  Returns the supported algorithm OIDs for a crypto operation.

  @param[in]      OpIdGuid    GUID identifying the crypto operation.
  @param[out]     Buffer      NULL to query the required size, otherwise
                              receives the capability data.
  @param[in,out]  BufferSize  On input, the size of Buffer. On output, the
                              number of bytes written or required.

  @retval EFI_SUCCESS            The capability data or required size was
                                 returned.
  @retval EFI_BUFFER_TOO_SMALL   Buffer is too small.
  @retval EFI_NOT_FOUND          OpIdGuid is not supported.
  @retval EFI_INVALID_PARAMETER  OpIdGuid or BufferSize is NULL.
**/
EFI_STATUS
EFIAPI
GetCryptoOpCapability (
  IN     CONST EFI_GUID  *OpIdGuid,
  OUT    VOID            *Buffer       OPTIONAL,
  IN OUT UINTN           *BufferSize
  )
{
  UINTN  Index;

  if ((OpIdGuid == NULL) || (BufferSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  for (Index = 0; Index < ARRAY_SIZE (mCryptoOpDispatch); Index++) {
    if (CompareGuid (OpIdGuid, mCryptoOpDispatch[Index].OpId)) {
      return mCryptoOpDispatch[Index].Handler ((CHAR8 *)Buffer, BufferSize);
    }
  }

  return EFI_NOT_FOUND;
}
