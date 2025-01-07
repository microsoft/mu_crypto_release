#include <Uefi.h>
#include <Uefi/UefiSpec.h>

#include <Library/PeCoffLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/CacheMaintenanceLib.h>

#include <Protocol/MemoryAttribute.h>

#include "PeCoffLib.h"
#include "SharedLoaderShim.h"
#include "MemoryProtections.h"

#include <SharedCryptoProtocol.h>

#define EFI_SECTION_PE32  0x10


EFI_STATUS
EFIAPI
LoaderEntryPoint (
  IN VOID                 *DllSectionData,
  IN UINTN                DllSectionDataSize,
  IN SHARED_DEPENDENCIES  *Depends
  )
{
  EFI_STATUS                  Status;
  UINT32                      RVA;
  INTERNAL_IMAGE_CONTEXT      Image;
  EFI_IMAGE_EXPORT_DIRECTORY  *Exports;
  CONSTRUCTOR                 Constructor;
  SHARED_CRYPTO_PROTOCOL CryptoProtocol;

  // First we must walk all the FV's and find the one that contains the shared library

  ZeroMem (&Image, sizeof (Image));

  DEBUG ((DEBUG_INFO, "Found section with known GUID, size: %u bytes\n", DllSectionDataSize));

  //
  // FTODO - Ideally we would be using LoadImage(..) to load the image, but for now we'll use the PeCoffLoader directly
  //        This is because LoadImage(..) returns a handle to the image instead of the structure we need
  //        to extract the export directory
  //
  //        We'll need to refactor this code to use LoadImage(..) in the future once we have a way to extract the export directory
  //        from the provided handle given by LoadImage(..)
  //

  Image.Context.Handle    = DllSectionData;
  Image.Context.ImageRead = PeCoffLoaderImageReadFromMemory;
  Status                  = PeCoffLoaderGetImageInfo (&Image.Context);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to get image info: %r\n", Status));
    return Status;
  }

  //
  // Confirm that the image is an EFI application
  //
  if ((Image.Context.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION)) {
    DEBUG ((DEBUG_ERROR, "Invalid image type: %d\n", Image.Context.ImageType));
    return EFI_UNSUPPORTED;
  }

  //
  // Set the correct memory types for the image
  //
  Image.Context.ImageCodeMemoryType = EfiRuntimeServicesCode;
  Image.Context.ImageDataMemoryType = EfiLoaderData;

  //
  // Calculate the number of pages needed to load the image
  //
  if (Image.Context.SectionAlignment > EFI_PAGE_SIZE) {
    Image.Size = (UINTN)Image.Context.ImageSize + Image.Context.SectionAlignment;
  } else {
    Image.Size = (UINTN)Image.Context.ImageSize;
  }

  //
  // Calculate the number of pages needed to load the image
  //
  Image.NumberOfPages = EFI_SIZE_TO_PAGES (Image.Size);

  DEBUG ((DEBUG_INFO, "Image size: %u bytes\n", Image.Size));
  DEBUG ((DEBUG_INFO, "Number of pages: %u\n", Image.NumberOfPages));

  //
  // Allocate Executable memory for the image
  //
  Status = gDriverDependencies->AllocatePages (
                                  AllocateAnyPages,
                                  (EFI_MEMORY_TYPE)(Image.Context.ImageCodeMemoryType),
                                  Image.NumberOfPages,
                                  &Image.PageBase
                                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to allocate memory for image: %r\n", Status));
    return Status;
  }

  //
  // Since we're going to align the buffer on a section boundary, we need to save the original address
  // Set the image address to the base of the allocated memory
  //
  Image.Context.ImageAddress = (EFI_PHYSICAL_ADDRESS)Image.PageBase;

  //
  // Align buffer on section boundary
  //
  Image.Context.ImageAddress += Image.Context.SectionAlignment - 1;
  Image.Context.ImageAddress &= ~((EFI_PHYSICAL_ADDRESS)Image.Context.SectionAlignment - 1);

  //
  // Load the image into the allocated memory
  //
  Status = PeCoffLoaderLoadImage (&Image.Context);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to load image: %r\n", Status));
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "%a:%d\n", __func__, __LINE__));

  //
  // Relocate the image in memory
  //
  Status = PeCoffLoaderRelocateImage (&Image.Context);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to relocate image: %r\n", Status));
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "%a:%d\n", __func__, __LINE__));

  //
  // Grab the export directory from the image
  //
  Status = GetExportDirectoryInPeCoffImage (&Image, &Exports);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to get export directory: %r\n", Status));
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "%a:%d\n", __func__, __LINE__));

  DEBUG_CODE_BEGIN ();

  //
  // Assuming we have the export directory, print out the exported functions
  //
  PrintExportedFunctions (&Image, Exports);

  DEBUG_CODE_END ();

  //
  // Find the constructor function
  //
  Status = FindExportedFunction (&Image, Exports, CONSTRUCTOR_NAME, &RVA);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to find exported function: %r\n", Status));
    goto Exit;
  }

  EFI_IMAGE_IMPORT_DESCRIPTOR  *ImageImportDirectory;

  Status = GetImportDirectoryInPeCoffImage (&Image, &ImageImportDirectory);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to get import directory: %r\n", Status));
    goto Exit;
  }

  DUMP_HEX (DEBUG_ERROR, 0, ImageImportDirectory, sizeof (EFI_IMAGE_IMPORT_DESCRIPTOR), "");

  //
  // While we're setting up the Image,
  //
  Status = ProtectUefiDll (&Image);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  //
  // Setup the Library constructor function
  //
  Constructor = (CONSTRUCTOR)((EFI_PHYSICAL_ADDRESS)Image.Context.ImageAddress + RVA);

  InvalidateInstructionCacheRange ((VOID *)(UINTN)Image.Context.ImageAddress, (UINTN)Image.Context.ImageSize);
  Status = Constructor (Depends, &CryptoProtocol);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to call LibConstructor: %r\n", Status));
    goto Exit;
  }

  Status = EFI_SUCCESS;

Exit:
  if (Image.Context.ImageAddress != 0) {
    gDriverDependencies->FreePages (Image.PageBase, Image.NumberOfPages);
  }

  DEBUG ((DEBUG_INFO, "Exiting with status: %r\n", Status));

  return Status;
}
