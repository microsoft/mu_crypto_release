/** @file
  Common declarations for OneCryptoBin entry points.

  This header declares the shared functions used by different OneCryptoBin
  entry points (DXE, MM, and export entry).

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef ONE_CRYPTO_BIN_H_
#define ONE_CRYPTO_BIN_H_

#include <Uefi.h>
#include <Protocol/OneCrypto.h>
#include <Private/OneCryptoDependencySupport.h>

/**
  OneCrypto Entry Point (No Setup)

  This entry point assumes that library constructors have already been called
  by the build system. This is the case for S*mm (StandaloneMm/SupvMm) binaries
  where the standard UEFI loader will properly initialize all library constructors
  before calling the entry point.

  @param[in]  Depends     Pointer to dependencies structure containing function
                          pointers required by the CRT library.
  @param[out] Crypto      Pointer to receive the initialized ONE_CRYPTO_PROTOCOL.
                          If NULL, this is a size query.
  @param[out] CryptoSize  Pointer to receive the size of ONE_CRYPTO_PROTOCOL.

  @retval EFI_SUCCESS             Protocol initialized successfully.
  @retval EFI_BUFFER_TOO_SMALL    Crypto is NULL (size query).
  @retval EFI_INVALID_PARAMETER   *Crypto is NULL when Crypto is not NULL.
  @retval other                   Error from BaseCryptCrtSetup.
**/
EFI_STATUS
EFIAPI
NoSetupCryptoEntry (
  IN ONE_CRYPTO_DEPENDENCIES  *Depends,
  OUT VOID                    **Crypto,
  OUT UINT32                  *CryptoSize
  );

#endif // ONE_CRYPTO_BIN_H_
