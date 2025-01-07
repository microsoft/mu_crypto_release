#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Protocol/MemoryAttribute.h>

#include "MemoryProtections.h"
#include "SharedLoaderShim.h"

/*
  .Data Section must be RW-X
  .Code Section must be RX-W
  Everything else can be RO
*/
EFI_STATUS
ProtectUefiDll (
  INTERNAL_IMAGE_CONTEXT  *Image
  )
{
  EFI_MEMORY_ATTRIBUTE_PROTOCOL  *MemoryAttribute;
  EFI_STATUS                     Status;
  UINT64                         Attributes;

  PHYSICAL_ADDRESS      *Data;
  UINT32                DataSize;
  EFI_PHYSICAL_ADDRESS  *Text;
  UINT32                TextSize;

  Status = gDriverDependencies->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&MemoryAttribute);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to locate Memory Attribute Protocol: %r\n", Status));
    //
    // Potentially the platform doesn't have this protocol / doesn't set memory protections. So we can't error out.
    // However we need to be careful
    //
    MemoryAttribute = NULL;
  }

  Status = GetSectionByName (Image, ".data", &Data, &DataSize);
  ASSERT_EFI_ERROR (Status);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to find the .data section\n"));
    return Status;
  }

  DEBUG ((DEBUG_INFO, ".data base(0x%x) size(%u)\n", Data, DataSize));

  Status = GetSectionByName (Image, ".text", &Text, &TextSize);
  ASSERT_EFI_ERROR (Status);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to find the .text section\n"));
    return Status;
  }

  DEBUG ((DEBUG_INFO, ".text base(0x%x) size(%u)\n", Text, TextSize));

  if (MemoryAttribute != NULL) {
    DEBUG ((DEBUG_INFO, "Using Memory Attributes Protocol to clear XP\n"));

    Status = MemoryAttribute->GetMemoryAttributes (MemoryAttribute, Image->PageBase, Image->Size, &Attributes);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Failed to retrieve memory attributes\n"));
      return Status;
    }

    PHYSICAL_ADDRESS  PageStart;
    UINT32            PageSize;

    Status = ConvertSectionToPage(*Text, TextSize, &PageStart, &PageSize);
    if (EFI_ERROR(Status)) {
      DEBUG((DEBUG_ERROR, "Failed to convert section to page: %r\n", Status));
      return Status;
    }

    // TODO why can't I clear only PageStart?

    //
    // Remove the eXecutable Protections from the allocated memory
    //
    Status = MemoryAttribute->ClearMemoryAttributes (
                                MemoryAttribute,
                                Image->PageBase,
                                Image->Size,
                                EFI_MEMORY_XP
                                );

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Failed to clear EFI_MEMORY_XP (%r) \n", Status));
      ASSERT (FALSE);
    }
  } else {
        // Write a fallback
  }

  DEBUG ((DEBUG_INFO, "Memory Attributes: 0x%x\n", Attributes));
  DEBUG ((DEBUG_INFO, "XP Memory: %a\n", (Attributes & EFI_MEMORY_XP) ? "Yes" : "No"));

  return EFI_SUCCESS;
}