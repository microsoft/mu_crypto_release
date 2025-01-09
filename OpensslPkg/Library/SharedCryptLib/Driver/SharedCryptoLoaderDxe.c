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

SHARED_DEPENDENCIES  *gSharedDepends = NULL;
DRIVER_DEPENDENCIES  *gDriverDependencies = NULL;

//
// The version we're requesting
//
UINT64
EFIAPI
GetVersion(
  VOID
  )
{
  DEBUG((DEBUG_INFO, ""))
  return PACK_VERSION(VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION);
}

VOID
EFIAPI
AssertEfiError (
  BOOLEAN  Expression
  )
{
  ASSERT_EFI_ERROR (Expression);
}

VOID
InstallSharedDependencies (
  EFI_SYSTEM_TABLE  SystemTable
  )
{
  gSharedDepends->AllocatePool      = AllocatePool;
  gSharedDepends->FreePool          = FreePool;
  gSharedDepends->ASSERT            = AssertEfiError;
  gSharedDepends->DebugPrint        = DebugPrint;
  gSharedDepends->GetTime           = SystemTable.RuntimeServices->GetTime;
  gSharedDepends->GetRandomNumber64 = GetRandomNumber64;


  DUMP_HEX(DEBUG_ERROR, 0, gSharedDepends, sizeof(SHARED_DEPENDENCIES), "");

}

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

EFI_STATUS
EFIAPI
DxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_GUID    CommonGuid = {
    0x76ABA88D, 0x9D16, 0x49A2, { 0xAA, 0x3A, 0xDB, 0x61, 0x12, 0xFA, 0xC5, 0xCB }
  };
  EFI_STATUS  Status;
  VOID        *SectionData;
  UINTN       SectionSize;

  SHARED_CRYPTO_PROTOCOL CryptoProtocol;

  CryptoProtocol.GetVersion = GetVersion;

  if (gDriverDependencies == NULL) {
    gDriverDependencies = AllocatePool (sizeof (*gDriverDependencies));
    if (gDriverDependencies == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    InstallDriverDependencies (*SystemTable);
  }

  if (gSharedDepends == NULL) {
    gSharedDepends = AllocatePool (sizeof (*gSharedDepends));
    if (gSharedDepends == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    InstallSharedDependencies (*SystemTable);
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
    return EFI_NOT_READY;
  }

  Status = LoaderEntryPoint (SectionData, SectionSize, gSharedDepends);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to load shared library: %r\n", Status));
    goto Exit;
  }

  Status = EFI_SUCCESS;

Exit:

  if (gDriverDependencies != NULL) {
    FreePool (gDriverDependencies);
  }

  if (gSharedDepends != NULL) {
    FreePool (gSharedDepends);
  }

  if (SectionData != NULL) {
    FreePool (SectionData);
  }

  return Status;
}
