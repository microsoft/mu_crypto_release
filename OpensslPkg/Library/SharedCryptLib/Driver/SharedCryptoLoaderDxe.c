#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/DebugLib.h>
#include <Library/RngLib.h>

#include <SharedCrtLibSupport.h>
#include <SharedCryptoProtocol.h>
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
SHARED_CRYPTO_PROTOCOL  mSharedCryptoProtocol;

UINT64
EFIAPI
GetVersion (
  VOID
  )
{
  return PACK_VERSION (VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION);
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
 * @param forceInstall A boolean flag indicating whether to force the
 * installation of dependencies even if they are already present.
 * @return int Returns 0 on success, or a non-zero error code on failure.
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
  EFI_STATUS   Status;
  VOID         *SectionData;
  UINTN        SectionSize;
  CONSTRUCTOR  Constructor;

  //
  // This must match the INF for SharedCryptoBin
  //
  EFI_GUID  SharedLibGuid = {
    0x76ABA88D, 0x9D16, 0x49A2, { 0xAA, 0x3A, 0xDB, 0x61, 0x12, 0xFA, 0xC5, 0xCB }
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
  // Load the binary and get the entry point
  // TODO: This should be able to be replaced if we rewrite the Uefi Loader
  // and create a new entry point
  //
  Status = LoaderEntryPoint (SectionData, SectionSize, &Constructor);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to load shared library: %r\n", Status));
    goto Exit;
  }

  //
  // Provide the requested version to the constructor
  //
  mSharedCryptoProtocol.GetVersion = GetVersion;

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
              &gSharedCryptoProtocolGuid,
              (SHARED_CRYPTO_PROTOCOL *)&mSharedCryptoProtocol,
              NULL
              );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to install protocol: %r\n", Status));
    goto Exit;
  }

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
