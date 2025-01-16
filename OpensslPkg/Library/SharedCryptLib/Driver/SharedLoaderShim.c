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

#include <Protocol/SharedCryptoProtocol.h>

#define EFI_SECTION_PE32  0x10

/**
 * @brief Entry point for the loader.
 *
 * This function serves as the main entry point for the loader module. It is responsible for
 * initializing the loader, setting up necessary resources, and starting the loading process.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of command-line arguments.
 * @return An integer status code indicating the result of the loader initialization and execution.
 *         Typically, a return value of 0 indicates success, while non-zero values indicate errors.
 */
EFI_STATUS
EFIAPI
LoaderEntryPoint (
  IN VOID                 *DllSectionData,
  IN UINTN                DllSectionDataSize,
  OUT CONSTRUCTOR         *Constructor
  )
{
  EFI_STATUS                  Status;
  UINT32                      RVA;
  INTERNAL_IMAGE_CONTEXT      Image;
  EFI_IMAGE_EXPORT_DIRECTORY  *Exports;

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

  //
  // Relocate the image in memory
  //
  Status = PeCoffLoaderRelocateImage (&Image.Context);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to relocate image: %r\n", Status));
    goto Exit;
  }

  //
  // Grab the export directory from the image
  //
  Status = GetExportDirectoryInPeCoffImage (&Image, &Exports);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to get export directory: %r\n", Status));
    goto Exit;
  }

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
  InvalidateInstructionCacheRange ((VOID *)(UINTN)Image.Context.ImageAddress, (UINTN)Image.Context.ImageSize);
  *Constructor = (CONSTRUCTOR)((EFI_PHYSICAL_ADDRESS)Image.Context.ImageAddress + RVA);

  Status = EFI_SUCCESS;

Exit:
  //
  // Only Free if the Status was not successful
  // We need this memory to last long past the execution of the driver
  // otherwise the protocol would cause the system to break
  //
  if (Status != EFI_SUCCESS && Image.Context.ImageAddress != 0) {
    gDriverDependencies->FreePages (Image.PageBase, Image.NumberOfPages);
    Image.Context.ImageAddress = 0;
  }

  DEBUG ((DEBUG_INFO, "Memory %a cleared\n", (Status != EFI_SUCCESS && Image.Context.ImageAddress != 0) ? "was" : "was not"));
  DEBUG ((DEBUG_INFO, "Exiting with status: %r\n", Status));

  return Status;
}
