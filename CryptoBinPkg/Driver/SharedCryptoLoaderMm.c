/** @file
  SharedCryptoLoaderMm.c

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

  This file contains the implementation of the SharedCryptoLoader MM driver,
  which is responsible for loading and initializing the shared cryptographic
  library and its dependencies.

  MM ENVIRONMENT RNG STRATEGY:
  
  This MM (Management Mode) loader uses a lazy RNG approach similar to DXE
  but with stricter requirements:
  
  1. RNG PROTOCOL EXPECTATION:
     - Attempts to locate EFI_RNG_PROTOCOL on first use
     - ASSERTS if protocol is not available (unlike DXE which fails gracefully)
     - MM environment should have controlled access to RNG protocols
  
  2. SECURITY RATIONALE:
     - MM phase should not perform operations requiring randomness without proper platform provision
     - Assertion forces platform developers to consider RNG requirements for MM phase
     - No silent fallback to weak entropy sources
  
  3. EXPECTED BEHAVIOR:
     - If EFI_RNG_PROTOCOL available: Full crypto functionality with hardware entropy
     - If EFI_RNG_PROTOCOL unavailable: Assertion failure to alert developers
     - BaseRngLibNull used as fallback library (prevents boot hangs)
  
  4. PLATFORM REQUIREMENTS:
     - For full crypto functionality, provide EFI_RNG_PROTOCOL in MM environment
     - Or override RngLib with platform-specific MM RNG implementation:
       [Components.X64.MM_STANDALONE]
         CryptoBinPkg/Driver/SharedCryptoLoaderMm.inf {
           <LibraryClasses>
             RngLib|YourPlatformPkg/Library/MmRngLib/MmRngLib.inf
         }

**/

#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SafeIntLib.h>
#include <Library/RngLib.h>
#include <Library/HobLib.h>
#include <Guid/FirmwareFileSystem2.h>
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/Rng.h>
#include <Ppi/FirmwareVolumeInfo.h>
#include <Library/FvLib.h>

#include <Protocol/SharedCryptoProtocol.h>
#include <Library/SharedCryptoDependencySupport.h>
#include "SharedLoaderShim.h"

#define EFI_SECTION_PE32  0x10

//
// Exposing gDriverDependencies to reduce phase specific code
//
DRIVER_DEPENDENCIES  *gDriverDependencies = NULL;
//
// The dependencies of the shared library, must live as long
// as the shared code is used
//
SHARED_DEPENDENCIES  *mSharedDepends = NULL;
//
// Crypto protocol for the shared library
// Using VOID* to be agnostic about protocol structure size/layout
//
VOID  *SharedCryptoProtocol = NULL;

//
// Lazy RNG state tracking for MM environment
//
STATIC BOOLEAN mMmRngInitAttempted = FALSE;
STATIC EFI_RNG_PROTOCOL *mMmCachedRngProtocol = NULL;

/**
 * @brief Lazy RNG implementation for MM environment with assertion on failure
 *
 * This function implements lazy initialization of the RNG protocol in MM environment.
 * Unlike the DXE version, this asserts if no RNG protocol is available since
 * MM environment should have controlled protocol access.
 *
 * @param[out] Rand Pointer to buffer to receive the 64-bit random number
 * @return TRUE if random number generated successfully, FALSE with assertion if protocol unavailable
 */
BOOLEAN
EFIAPI
LazyMmGetRandomNumber64 (
  OUT UINT64  *Rand
  )
{
  EFI_STATUS  Status;
  UINT8       *RandBytes;

  if (Rand == NULL) {
    DEBUG ((DEBUG_ERROR, "LazyMmGetRandomNumber64: Null Rand pointer\n"));
    ASSERT (FALSE);
    return FALSE;
  }

  //
  // Only attempt to locate the RNG protocol once
  //
  if (!mMmRngInitAttempted) {
    DEBUG ((DEBUG_INFO, "LazyMmGetRandomNumber64: First call, locating EFI_RNG_PROTOCOL in MM\n"));
    
    Status = gMmst->MmLocateProtocol (
                      &gEfiRngProtocolGuid,
                      NULL,
                      (VOID **)&mMmCachedRngProtocol
                      );
    
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "LazyMmGetRandomNumber64: EFI_RNG_PROTOCOL not available in MM environment, Status=%r\n", Status));
      DEBUG ((DEBUG_ERROR, "LazyMmGetRandomNumber64: MM environment should provide RNG protocol for secure crypto operations\n"));
      mMmCachedRngProtocol = NULL;
      //
      // Assert because MM should have controlled access to RNG
      //
      ASSERT_EFI_ERROR (Status);
    } else {
      DEBUG ((DEBUG_INFO, "LazyMmGetRandomNumber64: EFI_RNG_PROTOCOL located at %p\n", mMmCachedRngProtocol));
    }
    
    mMmRngInitAttempted = TRUE;
  }

  //
  // If we don't have RNG protocol after attempting to locate it, assert
  //
  if (mMmCachedRngProtocol == NULL) {
    DEBUG ((DEBUG_ERROR, "LazyMmGetRandomNumber64: No RNG protocol available in MM environment\n"));
    ASSERT (mMmCachedRngProtocol != NULL);
    return FALSE;
  }

  //
  // Use the cached RNG protocol
  //
  RandBytes = (UINT8 *)Rand;
  Status = mMmCachedRngProtocol->GetRNG (mMmCachedRngProtocol, NULL, sizeof (UINT64), RandBytes);
  
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "LazyMmGetRandomNumber64: GetRNG failed in MM environment, Status=%r\n", Status));
    return FALSE;
  }

  DEBUG ((DEBUG_VERBOSE, "LazyMmGetRandomNumber64: Successfully generated random number in MM\n"));
  return TRUE;
}

/**
 * @brief Asserts that the given EFI_STATUS is not an error.
 *
 * This macro checks if the provided EFI_STATUS value indicates an error.
 * If the status is an error, it triggers an assertion failure.
 *
 * @param Status The EFI_STATUS value to be checked.
 */
VOID
EFIAPI
AssertEfiError (
  BOOLEAN  Expression
  )
{
  ASSERT_EFI_ERROR (Expression);
}

/**
 * @brief Installs shared dependencies required for the application.
 *
 * This function handles the installation of shared dependencies that are
 * necessary for the application to run properly. It ensures that all
 * required libraries and packages are installed and up to date.
 *
 * @param dependencies A list of dependencies to be installed.
 */
VOID
InstallSharedDependencies (
  OUT SHARED_DEPENDENCIES  *SharedDepends
  )
{
  // TODO add a version number in case the dependencies grow
  SharedDepends->AllocatePool      = AllocatePool;
  SharedDepends->FreePool          = FreePool;
  SharedDepends->ASSERT            = AssertEfiError;
  SharedDepends->DebugPrint        = DebugPrint;
  SharedDepends->GetTime           = NULL;
  //
  // Use lazy RNG initialization for MM environment - will assert if protocol unavailable
  //
  SharedDepends->GetRandomNumber64 = LazyMmGetRandomNumber64;
  //
  // Safe integer operations
  //
  SharedDepends->SafeUintnAdd      = SafeUintnAdd;
  SharedDepends->SafeUintnMult     = SafeUintnMult;
  //
  // Memory and utility functions
  //
  SharedDepends->ZeroMem           = ZeroMem;
  SharedDepends->WriteUnaligned32  = WriteUnaligned32;
  DEBUG ((DEBUG_INFO, "InstallSharedDependencies: Using lazy MM RNG initialization with assertion\n"));
}

/**
 * @brief Installs the necessary driver dependencies.
 *
 * This function is responsible for installing all the required dependencies
 * for the driver to function correctly. It ensures that all the necessary
 * libraries and components are present and properly configured.
 *
 * @param driverPath The path to the driver that requires dependencies.
 * @param dependencies A list of dependencies that need to be installed.
 * @return int Returns 0 on success, or a non-zero error code on failure.
 */
VOID
InstallDriverDependencies (
  VOID
  )
{
  gDriverDependencies->AllocatePages  = gMmst->MmAllocatePages;
  gDriverDependencies->FreePages      = gMmst->MmFreePages;
  gDriverDependencies->LocateProtocol = gMmst->MmLocateProtocol;
  gDriverDependencies->AllocatePool   = gMmst->MmAllocatePool;
  gDriverDependencies->FreePool       = gMmst->MmFreePool;
}

/**
 * Entry point for the DXE (Driver Execution Environment) phase.
 *
 * This function is the main entry point for the DXE phase of the UEFI (Unified Extensible Firmware Interface) firmware.
 * It is responsible for initializing the DXE environment and executing the DXE drivers.
 *
 * @param ImageHandle  The firmware allocated handle for the EFI image.
 * @param SystemTable  A pointer to the EFI System Table.
 *
 * @retval EFI_SUCCESS           The entry point is executed successfully.
 * @retval EFI_LOAD_ERROR        Failed to load the DXE environment.
 * @retval EFI_INVALID_PARAMETER One or more parameters are invalid.
 */
EFI_STATUS
EFIAPI
MmEntry (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *MmSystemTable
  )
{
  EFI_STATUS                             Status;
  SHARED_CRYPTO_MM_CONSTRUCTOR_PROTOCOL  *ConstructorProtocol;
  EFI_HANDLE                             ProtocolHandle = NULL;

  DEBUG ((DEBUG_INFO, "SharedCryptoLoaderMm: Entry point called.\n"));

  //
  // Locate the private protocol that provides the constructor
  //
  Status = MmSystemTable->MmLocateProtocol (
                            &gSharedCryptoPrivateProtocolGuid,
                            NULL,
                            (VOID **)&ConstructorProtocol
                            );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to locate SharedCrypto private protocol: %r\n", Status));
    goto Exit;
  }

  if (ConstructorProtocol->Signature != SHARED_CRYPTO_MM_CONSTRUCTOR_PROTOCOL_SIGNATURE) {
    DEBUG ((DEBUG_ERROR, "SharedCrypto private protocol signature is invalid: %x\n", ConstructorProtocol->Signature));
    return EFI_UNSUPPORTED;
  }

  DEBUG ((DEBUG_INFO, "SharedCrypto private protocol found: %g\n", &gSharedCryptoPrivateProtocolGuid));

  //
  // Ensure that the constructor function is not NULL
  //
  ASSERT (ConstructorProtocol->Constructor != NULL);

  //
  // Initialize the Driver dependencies
  //
  if (gDriverDependencies == NULL) {
    gDriverDependencies = AllocatePool (sizeof (*gDriverDependencies));
    if (gDriverDependencies == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    InstallDriverDependencies ();
  }

  //
  // Initialize the Shared dependencies
  //

  if (mSharedDepends == NULL) {
    mSharedDepends = AllocatePool (sizeof (*mSharedDepends));
    if (mSharedDepends == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    InstallSharedDependencies (mSharedDepends);
  }

  //
  // Call library constructor to generate the protocol
  // Constructor will allocate memory and assign it to SharedCryptoProtocol
  // Using VOID** to be agnostic about the actual protocol structure
  //
  Status = ConstructorProtocol->Constructor (mSharedDepends, &SharedCryptoProtocol);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to call LibConstructor: %r\n", Status));
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "SharedCrypto Protocol Constructor called successfully.\n"));

  DEBUG ((DEBUG_INFO, "Installing SharedCrypto Protocol...\n"));
  Status = MmSystemTable->MmInstallProtocolInterface (
                            &ProtocolHandle,
                            &gSharedCryptoMmProtocolGuid,
                            EFI_NATIVE_INTERFACE,
                            SharedCryptoProtocol
                            );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to install protocol: %r\n", Status));
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "SharedCrypto Protocol installed successfully.\n"));

  Status = EFI_SUCCESS;

Exit:

  //
  // The driver dependencies may be freed regardless of the status
  //
  if (gDriverDependencies != NULL) {
    FreePool (gDriverDependencies);
  }

  //
  // The dependendencies that the shared library needs may not be freed unless
  // there was an error. If there is no Error then the memory must live long past this driver.
  //
  if ((Status != EFI_SUCCESS) && (gSharedDepends != NULL)) {
    FreePool (gSharedDepends);
  }

  return Status;
}
