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
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  )
{
  return Pkcs7VerifyOpCapability (Buffer, BufferSize);
}
