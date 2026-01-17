/** @file
  OneCryptoDependencySupport.h

  This file contains the definitions and constants used in the shared cryptographic library that
  are shared across different headers.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef ONE_CRYPTO_DEPENDENCY_SUPPORT_H
#define ONE_CRYPTO_DEPENDENCY_SUPPORT_H

#include <Uefi/UefiBaseType.h>
#include <Uefi/UefiSpec.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

//
// Version of the ONE_CRYPTO_DEPENDENCIES interface
// Major.Minor versioning scheme matching OneCryptoProtocol
//
#define ONE_CRYPTO_DEPENDENCIES_VERSION_MAJOR  1
#define ONE_CRYPTO_DEPENDENCIES_VERSION_MINOR  0

//
// The names of the exported functions.
//
#define EXPORTED_ENTRY_NAME  "CryptoEntry"

/**
  Function pointer type for memory allocation.

  Allocates a buffer of the specified size from the memory pool.

  @param[in]  AllocationSize  The number of bytes to allocate.

  @retval NULL    Allocation failed.
  @retval Other   Pointer to the allocated buffer.
**/
typedef VOID *(*ALLOCATE_POOL)(
  UINTN  AllocationSize
  );

/**
  Function pointer type for memory deallocation.

  Returns a buffer previously allocated by ALLOCATE_POOL to the memory pool.

  @param[in]  Buffer  Pointer to the buffer to free. If NULL, this function has no effect.
**/
typedef VOID (*FREE_POOL)(
  VOID  *Buffer
  );

/**
  Function pointer type for assertion checking.

  Tests a condition and triggers a debug break or halt if the condition is false.
  In production builds, this may be compiled out for performance.

  @param[in]  Expression  The boolean condition to test. If FALSE, an assertion is triggered.
**/
typedef VOID (*ASSERT_T)(
  BOOLEAN  Expression
  );

/**
  Function pointer type for debug output printing.

  Prints debug messages to the debug output stream. The message is formatted
  using printf-style format specifiers and is only output if the error level
  meets the current debug filtering criteria.

  @param[in]  ErrorLevel  The debug message severity level (e.g., DEBUG_ERROR, DEBUG_INFO).
  @param[in]  Format      Printf-style format string for the debug message.
  @param[in]  ...         Variable arguments corresponding to the format string.
**/
typedef
VOID
(EFIAPI *DEBUG_PRINT)(
  IN UINTN        ErrorLevel,
  IN CONST CHAR8  *Format,
  ...
  );

/**
  Function pointer type for getting system time.

  Returns the current system time and date information. This is typically used
  by cryptographic functions that need timestamps for certificates, random seeding,
  or time-based operations.

  @param[out]  Time          Pointer to storage for the current time and date.
  @param[out]  Capabilities  Optional pointer to storage for time capabilities.
                              May be NULL if capabilities are not needed.

  @retval EFI_SUCCESS           Time was retrieved successfully.
  @retval EFI_INVALID_PARAMETER Time pointer is NULL.
  @retval EFI_DEVICE_ERROR      The time could not be retrieved due to hardware error.
**/
typedef EFI_STATUS (EFIAPI *GET_TIME)(
  OUT  EFI_TIME               *Time,
  OUT  EFI_TIME_CAPABILITIES  *Capabilities OPTIONAL
  );

/**
  Function pointer type for generating 64-bit random numbers.

  Generates a cryptographically secure 64-bit random number using the platform's
  hardware or software random number generator. This is essential for cryptographic
  operations that require entropy such as key generation, nonces, and salts.

  @param[out]  Rand  Pointer to storage for the generated 64-bit random number.

  @retval TRUE   Random number was generated successfully.
  @retval FALSE  Failed to generate random number due to insufficient entropy
                 or hardware/software error.
**/
typedef
BOOLEAN
(EFIAPI *GET_RANDOM_NUMBER_64)(
  OUT UINT64  *Rand
  );

/**
  Structure to hold function pointers for shared crypto dependencies.

  This structure contains all the function pointers that the shared crypto
  implementation needs from the host environment. The versioning fields allow
  for compatibility checking and future evolution of this interface.
**/
typedef struct  _ONE_CRYPTO_DEPENDENCIES {
  //
  // Versioning
  // Major.Minor
  // Major - Breaking change to this structure
  // Minor - Functions added to the end of this structure
  //
  UINT16                  Major;                ///< Version Major
  UINT16                  Minor;                ///< Version Minor
  UINT32                  Reserved;             ///< Padding for 8-byte alignment
  ALLOCATE_POOL           AllocatePool;         ///< Memory allocation function
  FREE_POOL               FreePool;             ///< Memory deallocation function
  GET_TIME                GetTime;              ///< System time retrieval function
  DEBUG_PRINT             DebugPrint;           ///< Debug message output function
  GET_RANDOM_NUMBER_64    GetRandomNumber64;    ///< 64-bit random number generation function
} ONE_CRYPTO_DEPENDENCIES;

///////////////////////////////////////////////////////////////////////////////
/// Exported Functions
///////////////////////////////////////////////////////////////////////////////

#define ONE_CRYPTO_CONSTRUCTOR_PROTOCOL_SIGNATURE  SIGNATURE_32('O', 'N', 'E', 'C')

/**
  Defines a function pointer type for a constructor function.

  @param[in]  Depends          Pointer to a ONE_CRYPTO_DEPENDENCIES structure containing
                               function pointers for crypto dependencies.
  @param[out] Crypto           Output pointer to the constructed crypto protocol
                               interface. If NULL, only CryptoSize is returned.
  @param[out] CryptoSize       Size in bytes of the ONE_CRYPTO_PROTOCOL structure.

  @retval EFI_SUCCESS          The crypto entry function completed successfully.
  @retval EFI_BUFFER_TOO_SMALL Crypto is NULL, size returned in CryptoSize.
  @retval Others               CryptoEntry function failed.
**/
typedef EFI_STATUS (EFIAPI *CRYPTO_ENTRY)(
  IN ONE_CRYPTO_DEPENDENCIES *Depends,
  OUT VOID **Crypto,
  OUT UINT32 *CryptoSize
  );

//
// Protocol Definition
//
typedef struct _ONE_CRYPTO_CONSTRUCTOR_PROTOCOL {
  UINT32          Signature;
  UINT32          Version;
  CRYPTO_ENTRY    Entry;
} ONE_CRYPTO_CONSTRUCTOR_PROTOCOL;

#endif // ONE_CRYPTO_DEPENDENCY_SUPPORT_H
