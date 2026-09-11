/** @file
  ECIT capability reporting -- Authenticode verify op handler.

  AuthenticodeVerify() is built on top of Pkcs7Verify(): it parses the
  Authenticode envelope, validates the embedded image-hash DigestInfo,
  then hands the inner PKCS#7 SignedData to Pkcs7Verify for the actual
  cryptographic check. The signature-algorithm acceptance set is
  therefore identical to the PKCS#7 verify operation.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include "CryptOpCapability.h"

EFI_STATUS
EFIAPI
AuthenticodeVerifyOpCapability (
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  )
{
  return Pkcs7VerifyOpCapability (Buffer, BufferSize);
}
