/** @file
  SharedCryptoDependencySupport.h

  This file contains the definitions and constants used in the shared cryptographic library that
  are shared across different headers.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef SHARED_DEPENDENCY_SUPPORT_H
#define SHARED_DEPENDENCY_SUPPORT_H

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

//
// FILE_GUID(76ABA88D-9D16-49A2-AA3A-DB6112FAC5CC) of SharedCryptoMmBin.inf
//
#define SHARED_FILE_GUID  { 0x76ABA88D, 0x9D16, 0x49A2, { 0xAA, 0x3A, 0xDB, 0x61, 0x12, 0xFA, 0xC5, 0xCC } }

//
// Version of the SHARED_DEPENDENCIES interface
// Major.Minor.Revision versioning scheme matching SharedCryptoProtocol
//
#define SHARED_DEPENDENCIES_VERSION_MAJOR     1
#define SHARED_DEPENDENCIES_VERSION_MINOR     0
#define SHARED_DEPENDENCIES_VERSION_REVISION  0

//
// The name of the exported function
//
#define CONSTRUCTOR_NAME  "Constructor"

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

  @field Major                 Major version - Breaking change to this structure
  @field Minor                 Minor version - Functions added to the end of this structure
  @field Revision              Revision - Some non breaking change
  @field Reserved              Reserved field for future use, must be zero
  @field AllocatePool          Memory allocation function.
  @field FreePool              Memory deallocation function.
  @field ASSERT                Assertion checking function.
  @field GetTime               System time retrieval function.
  @field DebugPrint            Debug message output function.
  @field GetRandomNumber64     64-bit random number generation function.
**/
typedef struct  _SHARED_DEPENDENCIES {
  // ---------------------------------------------------------------------------
  // Versioning
  // Major.Minor.Revision
  // Major - Breaking change to this structure
  // Minor - Functions added to the end of this structure
  // Revision - Some non breaking change
  //
  // ---------------------------------------------------------------------------
  UINT16                  Major;
  UINT16                  Minor;
  UINT16                  Revision;
  UINT16                  Reserved;
  ALLOCATE_POOL           AllocatePool;
  FREE_POOL               FreePool;
  ASSERT_T                ASSERT;
  GET_TIME                GetTime;
  DEBUG_PRINT             DebugPrint;
  GET_RANDOM_NUMBER_64    GetRandomNumber64;
} SHARED_DEPENDENCIES;

SHARED_DEPENDENCIES  *gSharedDepends;

///////////////////////////////////////////////////////////////////////////////
/// Exported Constructor
///////////////////////////////////////////////////////////////////////////////

#define SHARED_CRYPTO_MM_CONSTRUCTOR_PROTOCOL_SIGNATURE  SIGNATURE_32('S', 'C', 'M', 'C')

/**
 * @typedef CONSTRUCTOR
 * @brief Defines a function pointer type for a constructor function.
 *
 * @param Depends A pointer to a SHARED_DEPENDENCIES structure containing function pointers for crypto dependencies.
 * @param RequestedCrypto Output pointer to the constructed crypto protocol interface.
 *
 * @return EFI_STATUS The status of the constructor function.
 */

typedef EFI_STATUS (EFIAPI *CONSTRUCTOR)(
  IN SHARED_DEPENDENCIES *Depends,
  OUT VOID *RequestedCrypto
  );

//
// Protocol Definition
//
typedef struct _SHARED_CRYPTO_MM_CONSTRUCTOR_PROTOCOL {
  UINT32         Signature;
  UINT32         Version;
  CONSTRUCTOR    Constructor;
} SHARED_CRYPTO_MM_CONSTRUCTOR_PROTOCOL;

#endif // SHARED_DEPENDENCY_SUPPORT_H
