/** @file
  GetTrustAnchorX509FromAuthData() / FreeTrustAnchorX509Cache() Null
  implementation.

  Returns EFI_UNSUPPORTED to indicate this interface is not provided by
  the current library instance (e.g., PEI / Runtime / SEC / SMM phases).

Copyright (C) Microsoft Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"

/**
  Null stub for GetTrustAnchorX509FromAuthData().

  @retval EFI_UNSUPPORTED  This interface is not supported.
**/
EFI_STATUS
EFIAPI
GetTrustAnchorX509FromAuthData (
  IN OUT VOID      **CacheHandle  OPTIONAL,
  IN  CONST UINT8  *TbsCertHash,
  IN  UINTN        TbsCertHashSize,
  IN  CONST UINT8  *AuthData,
  IN  UINTN        AuthDataSize,
  OUT UINT8        **TrustAnchorX509,
  OUT UINTN        *TrustAnchorX509Size
  )
{
  ASSERT (FALSE);
  return EFI_UNSUPPORTED;
}

/**
  Null stub for FreeTrustAnchorX509Cache(). No-op.
**/
VOID
EFIAPI
FreeTrustAnchorX509Cache (
  IN  VOID  *CacheHandle  OPTIONAL
  )
{
  ASSERT (FALSE);
}
