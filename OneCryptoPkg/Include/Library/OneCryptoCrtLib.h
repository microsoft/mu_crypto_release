/** @file
  OneCryptoCrtLib.h

  Header file for OneCryptoCrtLib that provides CRT support functions for
  cryptographic operations through dependency injection.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef ONE_CRYPTO_CRT_LIB_H
#define ONE_CRYPTO_CRT_LIB_H

#include <Uefi.h>
#include <Private/OneCryptoDependencySupport.h>

/**
  Initialize the OneCrypto CRT library with the provided dependencies.

  This function stores a pointer to the dependency structure which provides
  implementations for memory allocation, time services, random number generation,
  and debugging functions. This must be called before any cryptographic operations
  that rely on these dependencies.

  @param[in]  Dependencies  Pointer to ONE_CRYPTO_DEPENDENCIES structure containing
                            function pointers for required services.

  @retval EFI_SUCCESS           Dependencies were set successfully.
  @retval EFI_INVALID_PARAMETER Dependencies is NULL.
**/
EFI_STATUS
EFIAPI
OneCryptoCrtSetup (
  IN VOID  *Dependencies
  );

/**
  Allocates a buffer of a specified size from the pool.

  This function allocates a buffer of size AllocationSize from the pool using
  the AllocatePool function pointer provided through OneCryptoCrtSetup.

  @param[in]  AllocationSize  The number of bytes to allocate.

  @retval  NULL    If dependencies are not initialized or AllocatePool is NULL.
  @retval  Other   A pointer to the allocated buffer.
**/
VOID *
EFIAPI
OneCryptoAllocatePool (
  IN UINTN  AllocationSize
  );

/**
  Allocates and zeros a buffer of a specified size from the pool.

  This function allocates a buffer of size AllocationSize from the pool using
  OneCryptoAllocatePool and then zeros the entire allocated buffer.

  @param[in]  AllocationSize  The number of bytes to allocate and zero.

  @retval  NULL    If the allocation fails or if AllocationSize is 0.
  @retval  Other   A pointer to the allocated and zeroed buffer.
**/
VOID *
EFIAPI
OneCryptoAllocateZeroPool (
  IN UINTN  AllocationSize
  );

/**
  Frees a pool of memory.

  This function frees the memory pool pointed to by Buffer using the FreePool
  function pointer provided through OneCryptoCrtSetup.

  @param[in]  Buffer  Pointer to the memory pool to be freed.
**/
VOID
EFIAPI
OneCryptoFreePool (
  IN VOID  *Buffer
  );

/**
  Get the current time from the platform.

  This function retrieves the current time using the GetTime function pointer
  provided through OneCryptoCrtSetup.

  @param[out]  Time          Pointer to storage for the current time and date.
  @param[out]  Capabilities  Optional pointer to storage for time capabilities.

  @retval EFI_SUCCESS           Time was retrieved successfully.
  @retval EFI_INVALID_PARAMETER Dependencies are not initialized or Time is NULL.
  @retval Other                 Error from the GetTime implementation.
**/
EFI_STATUS
EFIAPI
OneCryptoGetTime (
  OUT  EFI_TIME               *Time,
  OUT  EFI_TIME_CAPABILITIES  *Capabilities OPTIONAL
  );

/**
  Generates a 64-bit random number.

  This function generates a cryptographically secure 64-bit random number using
  the GetRandomNumber64 function pointer provided through OneCryptoCrtSetup.

  @param[out]  Rand  Pointer to storage for the generated 64-bit random number.

  @retval TRUE   Random number was generated successfully.
  @retval FALSE  Failed to generate random number or dependencies not initialized.
**/
BOOLEAN
EFIAPI
OneCryptoGetRandomNumber64 (
  OUT UINT64  *Rand
  );

/**
  Print debug messages.

  This function outputs debug messages using the DebugPrint function pointer
  provided through OneCryptoCrtSetup.

  @param[in]  ErrorLevel  The debug message severity level.
  @param[in]  Format      Printf-style format string for the debug message.
  @param[in]  ...         Variable arguments corresponding to the format string.
**/
VOID
EFIAPI
OneCryptoDebugPrint (
  IN UINTN        ErrorLevel,
  IN CONST CHAR8  *Format,
  ...
  );

#endif // ONE_CRYPTO_CRT_LIB_H
