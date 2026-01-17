/** @file
  OneCryptoLoaderDxe.c

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

  This file contains the implementation of the OneCryptoLoader DXE driver,
  which is responsible for loading and initializing the shared cryptographic
  library and its dependencies.

**/
#include <Uefi.h>

#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/DebugLib.h>
#include <Library/RngLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/PeCoffExtendedLib.h>
#include <Library/PeCoffLib.h>
#include <Protocol/Rng.h>
#include <Protocol/OneCrypto.h>
#include <Protocol/LoadedImage.h>
#include <Private/OneCryptoDependencySupport.h>
#include <Guid/OneCryptoFileGuid.h>

#define EFI_SECTION_PE32  0x10

//
// The dependencies of the shared library, must live as long
// as the shared code is used
//
ONE_CRYPTO_DEPENDENCIES  *mOneCryptoDepends = NULL;
//
// Crypto protocol for the shared library
// Using VOID* to be agnostic about protocol structure size/layout
//
VOID  *mOneCryptoProtocol = NULL;

//
// Lazy RNG state tracking
//
STATIC EFI_RNG_PROTOCOL  *mCachedRngProtocol = NULL;

/**
 * @brief Lazy RNG implementation that locates EFI_RNG_PROTOCOL on first use
 *
 * This function implements lazy initialization of the RNG protocol to avoid
 * boot-time hangs. It only attempts to locate the protocol when RNG is first
 * needed, and caches the result for subsequent calls.
 *
 * @param[out] Rand Pointer to buffer to receive the 64-bit random number
 * @return TRUE if random number generated successfully, FALSE otherwise
 */
BOOLEAN
EFIAPI
LazyPlatformGetRandomNumber64 (
  OUT UINT64  *Rand
  )
{
  EFI_STATUS  Status;
  UINT8       *RandBytes;

  if (Rand == NULL) {
    DEBUG ((DEBUG_ERROR, "LazyPlatformGetRandomNumber64: Null Rand pointer\n"));
    return FALSE;
  }

  //
  // Only attempt to locate the RNG protocol once
  //
  if (mCachedRngProtocol == NULL) {
    DEBUG ((DEBUG_INFO, "LazyPlatformGetRandomNumber64: locating EFI_RNG_PROTOCOL\n"));

    Status = gBS->LocateProtocol (
                    &gEfiRngProtocolGuid,
                    NULL,
                    (VOID **)&mCachedRngProtocol
                    );

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, "LazyPlatformGetRandomNumber64: EFI_RNG_PROTOCOL not available, Status=%r\n", Status));
    }
  }

  //
  // If we don't have RNG protocol, fail gracefully
  //
  if (mCachedRngProtocol == NULL) {
    DEBUG ((DEBUG_VERBOSE, "LazyPlatformGetRandomNumber64: No RNG protocol available\n"));
    return FALSE;
  }

  //
  // Use the cached RNG protocol
  //
  RandBytes = (UINT8 *)Rand;
  Status    = mCachedRngProtocol->GetRNG (mCachedRngProtocol, NULL, sizeof (UINT64), RandBytes);

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "LazyPlatformGetRandomNumber64: GetRNG failed, Status=%r\n", Status));
    return FALSE;
  }

  return TRUE;
}

/**
 * @brief Installs shared dependencies required for the application.
 *
 * This function handles the installation of shared dependencies that are
 * necessary for the application to run properly. It ensures that all
 * required libraries and packages are installed and up to date.
 *
 * @param dependencies A list of dependencies to be installed.
 *
 * @return int Returns 0 on success, or a non-zero error code on failure.
 */
VOID
InstallSharedDependencies (
  OUT ONE_CRYPTO_DEPENDENCIES  *OneCryptoDepends
  )
{
  //
  // Set version information for compatibility checking
  //
  OneCryptoDepends->Major        = ONE_CRYPTO_DEPENDENCIES_VERSION_MAJOR;
  OneCryptoDepends->Minor        = ONE_CRYPTO_DEPENDENCIES_VERSION_MINOR;
  OneCryptoDepends->Reserved     = 0;
  OneCryptoDepends->AllocatePool = AllocatePool;
  OneCryptoDepends->FreePool     = FreePool;
  OneCryptoDepends->DebugPrint   = DebugPrint;
  OneCryptoDepends->GetTime      = gRT->GetTime;
  //
  // Use lazy RNG initialization - will try to locate RNG protocol on first use
  //
  OneCryptoDepends->GetRandomNumber64 = LazyPlatformGetRandomNumber64;
}

/**
 * @brief Entry point for the loader using a pre-loaded image.
 *
 * This function serves as an alternative entry point that works with an already loaded image.
 * It uses the EFI_LOADED_IMAGE_PROTOCOL to get the image base and then locates the constructor
 * function from the export directory.
 *
 * @param LoadedImage Pointer to the loaded image protocol containing the image base address.
 * @param Entry Output parameter that will contain the crypto entry function pointer.
 * @return EFI_STATUS indicating the result of the operation.
 */
EFI_STATUS
EFIAPI
GetEntryFromLoadedImage (
  IN EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage,
  OUT CRYPTO_ENTRY              *Entry
  )
{
  EFI_STATUS                  Status;
  UINT32                      RVA;
  INTERNAL_IMAGE_CONTEXT      Image;
  EFI_IMAGE_EXPORT_DIRECTORY  *Exports;

  if ((LoadedImage == NULL) || (Entry == NULL)) {
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
  Status = FindExportedFunction (&Image, Exports, EXPORTED_ENTRY_NAME, &RVA);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to find exported function '%a': %r\n", EXPORTED_ENTRY_NAME, Status));
    return Status;
  }

  //
  // Setup the Library constructor function
  // Since the image is already loaded and relocated, we can directly use the RVA
  //
  *Entry = (CRYPTO_ENTRY)((EFI_PHYSICAL_ADDRESS)LoadedImage->ImageBase + RVA);

  DEBUG ((
    DEBUG_ERROR,
    "Crypto Entry found at address: %p (Base: %p + RVA: 0x%x)\n",
    *Entry,
    LoadedImage->ImageBase,
    RVA
    ));

  return EFI_SUCCESS;
}

/**
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
  CRYPTO_ENTRY               Entry;
  EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage;
  EFI_HANDLE                 LoadedImageHandle;

  LoadedImageHandle = NULL;
  LoadedImage       = NULL;

  //
  // This must match the INF for OneCryptoBin
  //
  EFI_GUID  OneCryptoBinGuid = ONE_CRYPTO_BINARY_GUID;

  DEBUG ((DEBUG_INFO, "OneCryptoLoaderDxe: Setting up shared dependencies\n"));

  //
  // Initialize the Shared dependencies
  //
  if (mOneCryptoDepends == NULL) {
    mOneCryptoDepends = AllocatePool (sizeof (*mOneCryptoDepends));
    if (mOneCryptoDepends == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    InstallSharedDependencies (mOneCryptoDepends);
  }

  //
  // Print out the GUID of the shared library
  //
  DEBUG ((DEBUG_INFO, "OneCryptoLoaderDxe: Searching for Shared library GUID: %g\n", OneCryptoBinGuid));

  //
  // Get the section data from any FV that contains the shared library
  //
  Status = GetSectionFromAnyFv (&OneCryptoBinGuid, EFI_SECTION_PE32, 0, &SectionData, &SectionSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxe: Failed to find section with known GUID: %r\n", Status));
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
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxe: Failed to load image: %r\n", Status));
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
      "OneCryptoLoaderDxe: Failed to get loaded image protocol: %r\n",
      Status
      ));
    goto Exit;
  }

  //
  // With the loaded image, we can locate the exported crypto entry function
  //
  Status = GetEntryFromLoadedImage (LoadedImage, &Entry);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxe: Failed to get entry point from loaded image: %r\n", Status));
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "OneCryptoLoaderDxe: About to call crypto entry at %p\n", Entry));

  //
  // First, query the size needed for the crypto protocol
  //
  UINT32  CryptoSize = 0;
  Status = Entry (mOneCryptoDepends, NULL, &CryptoSize);
  if (Status != EFI_BUFFER_TOO_SMALL || CryptoSize == 0) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxe: Failed to query crypto protocol size: %r\n", Status));
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "OneCryptoLoaderDxe: OneCrypto Protocol size: %d bytes\n", CryptoSize));

  //
  // Allocate memory for the crypto protocol
  //
  mOneCryptoProtocol = AllocatePool (CryptoSize);
  if (mOneCryptoProtocol == NULL) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxe: Failed to allocate memory for crypto protocol\n"));
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  //
  // Call library constructor to initialize the protocol
  //
  Status = Entry (mOneCryptoDepends, &mOneCryptoProtocol, &CryptoSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxe: Failed to call crypto entry: %r\n", Status));
    FreePool (mOneCryptoProtocol);
    mOneCryptoProtocol = NULL;
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "OneCryptoLoaderDxe: Crypto entry completed successfully\n"));
  Status = SystemTable->BootServices->InstallMultipleProtocolInterfaces (
                                        &ImageHandle,
                                        &gOneCryptoProtocolGuid,
                                        mOneCryptoProtocol,
                                        NULL
                                        );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxe: Failed to install protocol: %r\n", Status));
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "OneCryptoLoaderDxe: OneCrypto Protocol installed successfully.\n"));

  Status = EFI_SUCCESS;

Exit:

  //
  // The SectionData may be freed regardless of the status
  //
  if (SectionData != NULL) {
    FreePool (SectionData);
  }

  //
  // The dependencies that the OneCrypto needs may not be freed unless there was an error.
  // If there is no error then the memory must live long past this driver to fulfill
  // crypto requests.
  //
  if ((Status != EFI_SUCCESS) && (mOneCryptoDepends != NULL)) {
    FreePool (mOneCryptoDepends);
  }

  return Status;
}
