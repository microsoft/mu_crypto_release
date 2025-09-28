#ifndef SHAREDLOADER_SHIM_H
#define SHAREDLOADER_SHIM_H

#include <Uefi.h>
#include "Library/SharedCryptoDependencySupport.h"
#include <Protocol/LoadedImage.h>

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

#endif // SHAREDLOADER_SHIM_H
