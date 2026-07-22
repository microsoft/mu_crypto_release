/** @file
  Unsupported Authenticode hash algorithm discovery.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"

/**
  Unsupported instance of Authenticode hash algorithm discovery.

  @param[in]  AuthData      Authenticode signature blob. Not inspected.
  @param[in]  AuthDataSize  Size of AuthData in bytes.
  @param[out] HashType      Hash algorithm GUID. Not written by this instance.

  @retval EFI_UNSUPPORTED  This instance does not provide hash algorithm discovery.
**/
EFI_STATUS
EFIAPI
GetAuthenticodeHashAlgorithm (
  IN  CONST UINT8  *AuthData,
  IN  UINTN        AuthDataSize,
  OUT EFI_GUID     *HashType
  )
{
  ASSERT (FALSE);
  return EFI_UNSUPPORTED;
}
