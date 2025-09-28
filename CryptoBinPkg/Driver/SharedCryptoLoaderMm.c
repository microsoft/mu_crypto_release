/** @file
  SharedCryptoLoaderStandaloneMM.c

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

  This file contains the implementation of the SharedCryptoLoader StandaloneMM driver,
  which is responsible for loading and initializing the shared cryptographic
  library and its dependencies.

**/

#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/RngLib.h>
#include <Library/HobLib.h>
#include <Guid/FirmwareFileSystem2.h>
#include <Protocol/FirmwareVolume2.h>
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
//
SHARED_CRYPTO_PROTOCOL  *SharedCryptoProtocol = NULL;

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
  SharedDepends->GetRandomNumber64 = GetRandomNumber64;
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

  Status = MmSystemTable->MmAllocatePool (
                            EfiRuntimeServicesData,
                            sizeof (SHARED_CRYPTO_PROTOCOL),
                            (VOID **)&SharedCryptoProtocol
                            );

  if (EFI_ERROR (Status) || (SharedCryptoProtocol == NULL)) {
    DEBUG ((DEBUG_ERROR, "SharedCryptoBin: Failed to allocate memory for shared crypto protocol: %r\n", Status));
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Provide the requested version to the constructor
  //
  SharedCryptoProtocol->Major    = VERSION_MAJOR;
  SharedCryptoProtocol->Minor    = VERSION_MINOR;
  SharedCryptoProtocol->Revision = VERSION_REVISION;


  //
  // Call library constructor to generate the protocol
  //
  Status = ConstructorProtocol->Constructor (mSharedDepends, SharedCryptoProtocol);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to call LibConstructor: %r\n", Status));
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "SharedCrypto Protocol Constructor called successfully.\n"));
  DEBUG ((DEBUG_INFO, "SharedCrypto Protocol Version: %d.%d.%d\n", SharedCryptoProtocol->Major, SharedCryptoProtocol->Minor, SharedCryptoProtocol->Revision));

  //
  // Validate the protocol structure before installing it
  //
  /*
  Status = ValidateSharedCryptoProtocol (SharedCryptoProtocol);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "SharedCrypto Protocol validation failed: %r\n", Status));
    DUMP_HEX (DEBUG_ERROR, 0, SharedCryptoProtocol, sizeof (SHARED_CRYPTO_PROTOCOL), "CORRUPTED PROTOCOL DUMP");
    goto Exit;
  }*/

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

  DUMP_HEX (DEBUG_INFO, 0, SharedCryptoProtocol, sizeof (SHARED_CRYPTO_PROTOCOL), "");
  

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
