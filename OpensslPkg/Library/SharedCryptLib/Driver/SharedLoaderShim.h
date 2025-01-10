#ifndef SHAREDLOADER_SHIM_H
#define SHAREDLOADER_SHIM_H

#include <Uefi.h>
#include <SharedCrtLibSupport.h>

//
// These represent the dependencies that the driver needs to function
// correctly regardless of the phase it is loaded in.
//
typedef struct _DRIVER_DEPENDENCIES {
  EFI_LOCATE_PROTOCOL    LocateProtocol;
  EFI_ALLOCATE_PAGES     AllocatePages;
  EFI_FREE_PAGES         FreePages;
  EFI_ALLOCATE_POOL      AllocatePool;
  EFI_FREE_POOL          FreePool;
} DRIVER_DEPENDENCIES;

//
// Global variable to hold the driver dependencies
//
extern DRIVER_DEPENDENCIES  *gDriverDependencies;

/**
 * @brief Phase-agnostic entry point for the driver.
 *
 * This function sets up the loader that will
 *  - Locate the DLLs that the driver depends on
 *  - Loads the DLL
 *  - Publishes the driver's protocol
 *
 * @param DllSectionData - The section data of the DLL
 * @param DllSectionDataSize - The size of the DLL section data
 *
 * @return EFI_STATUS
 * @retval EFI_SUCCESS The driver was loaded successfully
 * @retval EFI_OUT_OF_RESOURCES The driver was not loaded due to lack of resources
 * @retval EFI_INVALID_PARAMETER The driver was not loaded due to invalid parameters
 * @retval EFI_NOT_FOUND The driver was not loaded due to missing dependencies
 * @retval EFI_UNSUPPORTED The driver was not loaded due to unsupported features
 *
 */
EFI_STATUS
EFIAPI
LoaderEntryPoint (
  IN VOID          *DllSectionData,
  IN UINTN         DllSectionDataSize,
  OUT CONSTRUCTOR  *Constructor
  );

#endif // SHAREDLOADER_SHIM_H
