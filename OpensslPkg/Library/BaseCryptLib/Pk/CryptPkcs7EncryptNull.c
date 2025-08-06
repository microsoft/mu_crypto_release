/** @file
  PKCS7 Encryption implementation over OpenSSL

  Copyright (c) 2023, Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
*/

#include "InternalCryptLib.h"

BOOLEAN
EFIAPI
Pkcs7Encrypt (
  IN   UINT8   *X509Stack,
  IN   UINT8   *InData,
  IN   UINTN   InDataSize,
  IN   UINT32  CipherNid,
  IN   UINT32  Flags,
  OUT  UINT8   **ContentInfo,
  OUT  UINTN   *ContentInfoSize
  )
{
  ASSERT (FALSE);
  return FALSE;
}
