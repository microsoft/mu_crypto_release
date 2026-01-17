/** @file
  OneCryptoCrtLib.c

  Implementation of OneCryptoCrtLib that manages CRT dependencies for
  cryptographic operations.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Library/OneCryptoCrtLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Private/OneCryptoDependencySupport.h>

//
// Static pointer to hold the dependencies
//
STATIC ONE_CRYPTO_DEPENDENCIES  *mCryptoDependencies = NULL;

/**
  Initialize the OneCrypto CRT library with the provided dependencies.

  This function stores a pointer to the dependency structure which provides
  implementations for memory allocation, time services, random number generation,
  and debugging functions.

  @param[in]  Dependencies  Pointer to ONE_CRYPTO_DEPENDENCIES structure containing
                            function pointers for required services.

  @retval EFI_SUCCESS           Dependencies were set successfully.
  @retval EFI_INVALID_PARAMETER Dependencies is NULL.
**/
EFI_STATUS
EFIAPI
OneCryptoCrtSetup (
  IN VOID  *Dependencies
  )
{
  if (Dependencies == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mCryptoDependencies = (ONE_CRYPTO_DEPENDENCIES *)Dependencies;
  return EFI_SUCCESS;
}

/**
  Allocates a buffer of a specified size from the pool.

  This function allocates a buffer of size AllocationSize from the pool. If the
  global shared dependencies or the AllocatePool function pointer within it is
  NULL, the function returns NULL.

  @param[in]  AllocationSize  The number of bytes to allocate.

  @retval  NULL    If gOneCryptoDepends or gOneCryptoDepends->AllocatePool is NULL.
  @retval  Others  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
OneCryptoAllocatePool (
  IN UINTN  AllocationSize
  )
{
  if ((mCryptoDependencies == NULL) || (mCryptoDependencies->AllocatePool == NULL)) {
    return NULL;
  }

  return mCryptoDependencies->AllocatePool (AllocationSize);
}

/**
  Allocates and zeros a buffer of a specified size from the pool.

  This function allocates a buffer of size AllocationSize from the pool and then
  zeros the entire allocated buffer. If the allocation fails, the function returns NULL.

  @param[in]  AllocationSize  The number of bytes to allocate and zero.

  @retval  NULL    If the allocation fails, or if AllocationSize is 0.
  @retval  Others  A pointer to the allocated and zeroed buffer.
**/
VOID *
EFIAPI
OneCryptoAllocateZeroPool (
  IN UINTN  AllocationSize
  )
{
  VOID  *Buffer;

  Buffer = OneCryptoAllocatePool (AllocationSize);
  if (Buffer != NULL) {
    ZeroMem (Buffer, AllocationSize);
  }

  return Buffer;
}


/**
  Frees a pool of memory.

  This function checks if the global shared dependencies and its FreePool function
  pointer are not NULL. If both are valid, it calls the FreePool function to free
  the memory pool pointed to by Buffer.

  @param[in]  Buffer  Pointer to the memory pool to be freed.
**/
VOID
EFIAPI
OneCryptoFreePool (
  IN VOID  *Buffer
  )
{
  if ((mCryptoDependencies == NULL) || (mCryptoDependencies->FreePool == NULL)) {
    return;
  }

  mCryptoDependencies->FreePool (Buffer);
}

/**
  Retrieves the current time and date information, and the time-keeping capabilities of the hardware platform.

  @param[out] Time          A pointer to storage to receive a snapshot of the current time.
  @param[out] Capabilities  An optional pointer to a buffer to receive the real time clock device's capabilities.

  @retval EFI_SUCCESS       The operation completed successfully.
  @retval EFI_UNSUPPORTED   The operation is not supported.
**/
EFI_STATUS
EFIAPI
OneCryptoGetTime (
  OUT  EFI_TIME               *Time,
  OUT  EFI_TIME_CAPABILITIES  *Capabilities OPTIONAL
  )
{
  if ((mCryptoDependencies == NULL) || (mCryptoDependencies->GetTime == NULL)) {
    return EFI_UNSUPPORTED;
  }

  return mCryptoDependencies->GetTime (Time, Capabilities);
}

/**
  Generates a 64-bit random number.

  This function attempts to generate a 64-bit random number and store it in the
  location pointed to by Rand. If the shared dependency or the GetRandomNumber64
  function pointer is NULL, the function returns FALSE.

  @param[out] Rand  Pointer to the buffer to store the 64-bit random number.

  @retval TRUE   The 64-bit random number was generated successfully.
  @retval FALSE  The shared dependency or the GetRandomNumber64 function pointer
                 is NULL, and the random number could not be generated.
**/
BOOLEAN
EFIAPI
OneCryptoGetRandomNumber64 (
  OUT UINT64  *Rand
  )
{
  if ((mCryptoDependencies == NULL) || (mCryptoDependencies->GetRandomNumber64 == NULL)) {
    return FALSE;
  }

  return mCryptoDependencies->GetRandomNumber64 (Rand);
}

/**
  Prints a debug message to the debug output device if the specified error level is enabled.

  @param  ErrorLevel  The error level of the debug message.
  @param  Format      Format string for the debug message to print.
  @param  ...         Variable argument list whose contents are accessed
                      based on the format string specified by Format.

**/
VOID
EFIAPI
OneCryptoDebugPrint (
  IN  UINTN        ErrorLevel,
  IN  CONST CHAR8  *Format,
  ...
  )
{
  VA_LIST                  Marker;
  CHAR8                    Buffer[256];

  if ((mCryptoDependencies != NULL) && (mCryptoDependencies->DebugPrint != NULL)) {
    VA_START (Marker, Format);
    // Format the string first using AsciiVSPrint
    AsciiVSPrint (Buffer, sizeof(Buffer), Format, Marker);
    VA_END (Marker);
    // Now call DebugPrint with the formatted string (no more varargs)
    mCryptoDependencies->DebugPrint (ErrorLevel, "%a", Buffer);
  }
}
