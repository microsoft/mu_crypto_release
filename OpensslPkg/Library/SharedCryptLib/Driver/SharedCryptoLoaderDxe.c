//#include "LoaderShim.h"
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/DebugLib.h>
#include <Library/RngLib.h>
#include <SharedCrtLibSupport.h>

#define EFI_SECTION_PE32  0x10

SHARED_DEPENDENCIES  *gDriverDependencies = NULL;

VOID
InstallDriverDependencies (
  EFI_SYSTEM_TABLE  SystemTable
  )
{
    gDriverDependencies->AllocatePool = AllocatePool;
    gDriverDependencies->FreePool = FreePool;
    //gDriverDependencies->ASSERT = ASSERT_EFI_ERROR;
    gDriverDependencies->DebugPrint = DebugPrint;
    gDriverDependencies->GetTime = gRT->GetTime;
    gDriverDependencies->GetRandomNumber64 = GetRandomNumber64;

}

EFI_STATUS
EFIAPI
DxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_GUID    CommonGuid = { 0x76ABA88D, 0x9D16, 0x49A2, { 0xAA, 0x3A, 0xDB, 0x61, 0x12, 0xFA, 0xC5, 0xCB } };
  EFI_STATUS  Status;
  VOID        *SectionData;
  UINTN       SectionSize;

  if (gDriverDependencies == NULL) {
    gDriverDependencies = AllocatePool (sizeof (*gDriverDependencies));
    if (gDriverDependencies == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    InstallDriverDependencies (*SystemTable);
  }

  //
  // Print out the GUID of the shared library
  //
  DEBUG ((DEBUG_INFO, "Searching for Shared library GUID: %g\n", CommonGuid));

  //
  // Get the section data from any FV that contains the shared library
  //
  Status = GetSectionFromAnyFv (&CommonGuid, EFI_SECTION_PE32, 0, &SectionData, &SectionSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to find section with known GUID: %r\n", Status));
    return Status;
  }

  /*
  Status = LoaderEntryPoint (SectionData, SectionSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to load shared library: %r\n", Status));
    goto Exit;
  }*/

  Status = EFI_SUCCESS;

//Exit:

  if (gDriverDependencies != NULL) {
    FreePool (gDriverDependencies);
  }

  if (SectionData != NULL) {
    FreePool (SectionData);
  }

  return Status;
}