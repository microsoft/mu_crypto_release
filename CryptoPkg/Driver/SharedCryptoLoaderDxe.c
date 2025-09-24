/** @file
  SharedCryptoLoaderDxe.c

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

  This file contains the implementation of the SharedCryptoLoader DXE driver,
  which is responsible for loading and initializing the shared cryptographic
  library and its dependencies.

**/

#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/DebugLib.h>
#include <Library/RngLib.h>
#include <Library/PeCoffGetEntryPointLib.h>

#include <Library/SharedCryptoDependencySupport.h>
#include <Protocol/SharedCryptoProtocol.h>
#include "SharedLoaderShim.h"
#include "PeCoffLib.h"

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
SHARED_CRYPTO_PROTOCOL  mSharedCryptoProtocol;

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
 * @param forceInstall A boolean flag indicating whether to force the
 * installation of dependencies even if they are already present.
 * @return int Returns 0 on success, or a non-zero error code on failure.
 */
VOID
InstallSharedDependencies (
  OUT SHARED_DEPENDENCIES  *SharedDepends
  )
{

  SharedDepends->AllocatePool      = AllocatePool;
  SharedDepends->FreePool          = FreePool;
  SharedDepends->ASSERT            = AssertEfiError;
  SharedDepends->DebugPrint        = DebugPrint;
  SharedDepends->GetTime           = gRT->GetTime;
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
  EFI_SYSTEM_TABLE  SystemTable
  )
{
  gDriverDependencies->AllocatePages  = SystemTable.BootServices->AllocatePages;
  gDriverDependencies->FreePages      = SystemTable.BootServices->FreePages;
  gDriverDependencies->LocateProtocol = SystemTable.BootServices->LocateProtocol;
  gDriverDependencies->AllocatePool   = SystemTable.BootServices->AllocatePool;
  gDriverDependencies->FreePool       = SystemTable.BootServices->FreePool;
}


/**
 * @brief Entry point for the loader using a pre-loaded image.
 *
 * This function serves as an alternative entry point that works with an already loaded image.
 * It uses the EFI_LOADED_IMAGE_PROTOCOL to get the image base and then locates the constructor
 * function from the export directory.
 *
 * @param LoadedImage Pointer to the loaded image protocol containing the image base address.
 * @param Constructor Output parameter that will contain the constructor function pointer.
 * @return EFI_STATUS indicating the result of the operation.
 */
EFI_STATUS
EFIAPI
GetConstructorFromLoadedImage (
  IN EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage,
  OUT CONSTRUCTOR               *Constructor
  )
{
  EFI_STATUS                  Status;
  UINT32                      RVA;
  INTERNAL_IMAGE_CONTEXT      Image;
  EFI_IMAGE_EXPORT_DIRECTORY  *Exports;

  if ((LoadedImage == NULL) || (Constructor == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (LoadedImage->ImageBase == NULL) {
    DEBUG ((DEBUG_ERROR, "LoadedImage->ImageBase is NULL\n"));
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&Image, sizeof (Image));

  //
  // Set up the image context using the loaded image's base address
  // We don't need to load or relocate since the image is already loaded by UEFI
  //
  Image.Context.ImageAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)LoadedImage->ImageBase;
  Image.Context.ImageSize    = (UINT64)LoadedImage->ImageSize;
  Image.Context.Handle       = LoadedImage->ImageBase;
  Image.Context.ImageRead    = PeCoffLoaderImageReadFromMemory;

  //
  // Get image info to validate it's a proper PE/COFF image
  //
  Status = PeCoffLoaderGetImageInfo (&Image.Context);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to get image info from loaded image: %r\n", Status));
    return Status;
  }

  //
  // Confirm that the image is an EFI driver (really should be a MM_STANDLONE_DRIVER)
  //
  if (Image.Context.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER) {
    DEBUG ((DEBUG_ERROR, "Invalid image type: %d\n", Image.Context.ImageType));
    return EFI_UNSUPPORTED;
  }

  //
  // Grab the export directory from the loaded image
  //
  Status = GetExportDirectoryInPeCoffImage (&Image, &Exports);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to get export directory from loaded image: %r\n", Status));
    return Status;
  }

  DEBUG_CODE_BEGIN ();

  //
  // Print out the exported functions for debugging
  //
  PrintExportedFunctions (&Image, Exports);

  DEBUG_CODE_END ();

  //
  // Find the constructor function
  //
  Status = FindExportedFunction (&Image, Exports, CONSTRUCTOR_NAME, &RVA);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to find exported function '%a': %r\n", CONSTRUCTOR_NAME, Status));
    return Status;
  }

  //
  // Setup the Library constructor function
  // Since the image is already loaded and relocated, we can directly use the RVA
  //
  *Constructor = (CONSTRUCTOR)((EFI_PHYSICAL_ADDRESS)LoadedImage->ImageBase + RVA);

  DEBUG ((
    DEBUG_INFO,
    "Crypto Constructor found at address: %p (Base: %p + RVA: 0x%x)\n",
    *Constructor,
    LoadedImage->ImageBase,
    RVA
    ));

  return EFI_SUCCESS;
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
DxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                 Status;
  VOID                       *SectionData;
  UINTN                      SectionSize;
  CONSTRUCTOR                Constructor;
  EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage;
  EFI_HANDLE                 LoadedImageHandle;

  LoadedImageHandle = NULL;
  LoadedImage       = NULL;

  //
  // This must match the INF for SharedCryptoBin
  //
  EFI_GUID  SharedLibGuid = {
    0x76ABA88D, 0x9D16, 0x49A2, { 0xAA, 0x3A, 0xDB, 0x61, 0x12, 0xFA, 0xC5, 0xCC }
  };

  //
  // Initialize the Driver dependencies
  //
  if (gDriverDependencies == NULL) {
    gDriverDependencies = AllocatePool (sizeof (*gDriverDependencies));
    if (gDriverDependencies == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    InstallDriverDependencies (*SystemTable);
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
  // Print out the GUID of the shared library
  //
  DEBUG ((DEBUG_INFO, "Searching for Shared library GUID: %g\n", SharedLibGuid));

  //
  // Get the section data from any FV that contains the shared library
  //
  Status = GetSectionFromAnyFv (&SharedLibGuid, EFI_SECTION_PE32, 0, &SectionData, &SectionSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to find section with known GUID: %r\n", Status));
    return EFI_NOT_READY;
  }

  //
  // Load the PE32 image using LoadImage
  //
  Status = SystemTable->BootServices->LoadImage (
                                        FALSE,
                                        ImageHandle,
                                        NULL,
                                        SectionData,
                                        SectionSize,
                                        &LoadedImageHandle
                                        );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to load image: %r\n", Status));
    goto Exit;
  }

  //
  // Get the loaded image protocol to access the entry point
  //
  Status = SystemTable->BootServices->HandleProtocol (
                                        LoadedImageHandle,
                                        &gEfiLoadedImageProtocolGuid,
                                        (VOID **)&LoadedImage
                                        );

  if (EFI_ERROR (Status) || (LoadedImage == NULL)) {
    DEBUG ((
      DEBUG_ERROR,
      "Failed to get loaded image protocol: %r\n",
      Status
      ));
    goto Exit;
  }

  //
  // With the loaded image, we can locate the exported constructor function
  //
  Status = GetConstructorFromLoadedImage (LoadedImage, &Constructor);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to get entry point from loaded image: %r\n", Status));
    goto Exit;
  }

  //
  // Provide the requested version to the constructor
  //
  mSharedCryptoProtocol.Major    = VERSION_MAJOR;
  mSharedCryptoProtocol.Minor    = VERSION_MINOR;
  mSharedCryptoProtocol.Revision = VERSION_REVISION;

  //
  // Call library constructor to generate the protocol
  //
  Status = Constructor (mSharedDepends, &mSharedCryptoProtocol);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to call LibConstructor: %r\n", Status));
    goto Exit;
  }

  Status = SystemTable->BootServices->InstallMultipleProtocolInterfaces (
                                        &ImageHandle,
                                        &gSharedCryptoDxeProtocolGuid,
                                        (SHARED_CRYPTO_PROTOCOL *)&mSharedCryptoProtocol,
                                        NULL
                                        );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to install protocol: %r\n", Status));
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "SharedCrypto Protocol installed successfully.\n"));

  Status = EFI_SUCCESS;

Exit:

  //
  // The SectionData may be freed regardless of the status
  //
  if (SectionData != NULL) {
    FreePool (SectionData);
  }

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
