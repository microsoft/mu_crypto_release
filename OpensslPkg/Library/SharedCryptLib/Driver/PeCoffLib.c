/** @file
  This library provides the implementation of the PE/COFF loader functions for the SharedLoader module.
  Copyright (c) Microsoft Corporation
  Copyright (c) 2020 - 2022, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "Uefi.h"
#include <Library/DebugLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

#include "PeCoffLib.h"

/**
  Get the Export Directory in a PE/COFF image.
  This function retrieves the Export Directory in a PE/COFF image.
  @param[in]  Image                     A pointer to the base address of the PE/COFF image.
  @param[in]  PeCoffLoaderImageContext   A pointer to the PE_COFF_LOADER_IMAGE_CONTEXT structure.q
  @param[out] ImageExportDirectory      A pointer to the Export Directory structure.
  @retval EFI_SUCCESS                    The Export Directory is found.
  @retval EFI_INVALID_PARAMETER          A parameter is invalid.
  @retval EFI_UNSUPPORTED                The image is not a valid PE/COFF image.
  @retval EFI_NOT_FOUND                  The Export Directory is not found.
**/
EFI_STATUS
GetExportDirectoryInPeCoffImage (
  IN  INTERNAL_IMAGE_CONTEXT      *Image,
  OUT EFI_IMAGE_EXPORT_DIRECTORY  **ImageExportDirectory
  )
{
  UINT16                               Magic;
  UINT32                               NumberOfRvaAndSizes;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  OptionalHeaderPtrUnion;
  EFI_IMAGE_DATA_DIRECTORY             *DirectoryEntry;
  EFI_IMAGE_EXPORT_DIRECTORY           *ExportDirectory;

  if ((Image == NULL) || (ImageExportDirectory == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  DirectoryEntry  = NULL;
  ExportDirectory = NULL;

  //
  // NOTE: For backward compatibility, use the Machine field to identify a PE32/PE32+
  //       image instead of using the Magic field. Some systems might generate a PE32+
  //       image with PE32 magic.
  //
  switch (Image->Context.Machine) {
    case EFI_IMAGE_MACHINE_IA32:
      //
      // Assume PE32 image with IA32 Machine field.
      //
      Magic = EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC;
      break;
    case EFI_IMAGE_MACHINE_X64:
    case EFI_IMAGE_MACHINE_AARCH64:
      //
      // Assume PE32+ image with X64 Machine field
      //
      Magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
      break;
    default:
      //
      // For unknown Machine field, use Magic in optional header
      //
      DEBUG ((DEBUG_WARN, "%a: The machine type for this image is not valid for a PRM module.\n", __FUNCTION__));
      return EFI_UNSUPPORTED;
  }

  OptionalHeaderPtrUnion.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)(
                                                           (UINTN)Image->Context.ImageAddress +
                                                           Image->Context.PeCoffHeaderOffset
                                                           );

  //
  // Check the PE/COFF Header Signature. Determine if the image is valid and/or a TE image.
  //
  if (OptionalHeaderPtrUnion.Pe32->Signature != EFI_IMAGE_NT_SIGNATURE) {
    DEBUG ((DEBUG_ERROR, "%a: The PE signature is not valid for the current image.\n", __FUNCTION__));
    return EFI_UNSUPPORTED;
  }

  if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // Use the PE32 offset to get the Export Directory Entry
    //
    NumberOfRvaAndSizes = OptionalHeaderPtrUnion.Pe32->OptionalHeader.NumberOfRvaAndSizes;
    DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&(OptionalHeaderPtrUnion.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT]);
  } else if (OptionalHeaderPtrUnion.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    //
    // Use the PE32+ offset get the Export Directory Entry
    //
    NumberOfRvaAndSizes = OptionalHeaderPtrUnion.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
    DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&(OptionalHeaderPtrUnion.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT]);
  } else {
    return EFI_UNSUPPORTED;
  }

  if ((NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_EXPORT) || (DirectoryEntry->VirtualAddress == 0)) {
    //
    // The export directory is not present
    //
    return EFI_NOT_FOUND;
  } else if (((UINT32)(~0) - DirectoryEntry->VirtualAddress) < DirectoryEntry->Size) {
    //
    // The directory address overflows
    //
    DEBUG ((DEBUG_ERROR, "%a: The export directory entry in this image results in overflow.\n", __FUNCTION__));
    return EFI_UNSUPPORTED;
  } else {
    DEBUG ((DEBUG_INFO, "%a: Export Directory Entry found in the image at 0x%x.\n", __FUNCTION__, (UINTN)OptionalHeaderPtrUnion.Pe32));
    DEBUG ((DEBUG_INFO, "  %a: Directory Entry Virtual Address = 0x%x.\n", __FUNCTION__, DirectoryEntry->VirtualAddress));

    ExportDirectory = (EFI_IMAGE_EXPORT_DIRECTORY *)((UINTN)Image->Context.ImageAddress + DirectoryEntry->VirtualAddress);
    DEBUG ((
      DEBUG_INFO,
      "  %a: Export Directory Table found successfully at 0x%x. Name address = 0x%x. Name = %a.\n",
      __FUNCTION__,
      (UINTN)ExportDirectory,
      ((UINTN)Image->Context.ImageAddress + ExportDirectory->Name),
      (CHAR8 *)((UINTN)Image->Context.ImageAddress + ExportDirectory->Name)
      ));
  }

  *ImageExportDirectory = ExportDirectory;

  return EFI_SUCCESS;
}

/**
  Print the exported functions in a PE/COFF image.
  This function prints the exported functions in a PE/COFF image.
  @param[in]  Image             A pointer to the internal image context
  @param[in] ExportDirectory    A pointer to the Export Directory structure.
**/
VOID
PrintExportedFunctions (
  IN  INTERNAL_IMAGE_CONTEXT     *Image,
  IN EFI_IMAGE_EXPORT_DIRECTORY  *ExportDirectory
  )
{
  UINT32  *AddressOfNames;
  CHAR8   *FunctionName;
  UINT32  Index;

  if ((Image == NULL) || (ExportDirectory == NULL)) {
    DEBUG ((DEBUG_ERROR, "%a: Invalid parameter.\n", __FUNCTION__));
    return;
  }

  AddressOfNames = (UINT32 *)((UINTN)Image->Context.ImageAddress + ExportDirectory->AddressOfNames);

  DEBUG ((DEBUG_INFO, "Exported Functions:\n"));
  for (Index = 0; Index < ExportDirectory->NumberOfNames; Index++) {
    FunctionName = (CHAR8 *)((UINTN)Image->Context.ImageAddress + AddressOfNames[Index]);
    DEBUG ((DEBUG_INFO, "  %a\n", FunctionName));
  }
}

/**
  Find an exported function in a PE/COFF image.
  This function finds an exported function in a PE/COFF image.
  @param[in]  Image            A pointer to the internal image context
  @param[in]  ExportDirectory  A pointer to the Export Directory structure.
  @param[in]  FunctionName     A pointer to the function name.
  @param[out] FunctionAddress  A pointer to the function address.
  @retval EFI_SUCCESS           The function is found.
  @retval EFI_INVALID_PARAMETER A parameter is invalid.
  @retval EFI_NOT_FOUND         The function is not found.
**/
EFI_STATUS
FindExportedFunction (
  IN  INTERNAL_IMAGE_CONTEXT      *Image,
  IN  EFI_IMAGE_EXPORT_DIRECTORY  *ExportDirectory,
  IN  CHAR8                       *FunctionName,
  OUT UINT32                      *FunctionAddress
  )
{
  UINT32  *AddressOfNames;
  UINT16  *AddressOfNameOrdinals;
  UINT32  *AddressOfFunctions;
  CHAR8   *CurrentFunctionName;
  UINT32  Index;

  if ((Image == NULL) || (ExportDirectory == NULL) || (FunctionName == NULL) || (FunctionAddress == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  AddressOfNames        = (UINT32 *)((UINTN)Image->Context.ImageAddress + ExportDirectory->AddressOfNames);
  AddressOfNameOrdinals = (UINT16 *)((UINTN)Image->Context.ImageAddress + ExportDirectory->AddressOfNameOrdinals);
  AddressOfFunctions    = (UINT32 *)((UINTN)Image->Context.ImageAddress + ExportDirectory->AddressOfFunctions);

  for (Index = 0; Index < ExportDirectory->NumberOfNames; Index++) {
    CurrentFunctionName = (CHAR8 *)((UINTN)Image->Context.ImageAddress + AddressOfNames[Index]);
    if (AsciiStrCmp (CurrentFunctionName, FunctionName) == 0) {
      *FunctionAddress = AddressOfFunctions[AddressOfNameOrdinals[Index]];
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

/**
  Get the range of memory that should be executable from the binary.
  This function retrieves the range of memory (code section) that should be executable from the binary.
  @param[in]  Image                     A pointer to the internal image context
  @param[out] CodeBase                  A pointer to the base address of the code section.
  @param[out] CodeSize                  A pointer to the size of the code section.
  @retval EFI_SUCCESS                   The code section range is found.
  @retval EFI_INVALID_PARAMETER         A parameter is invalid.
  @retval EFI_UNSUPPORTED               The image is not a valid PE/COFF image.
**/
EFI_STATUS
GetExecutableMemoryRange (
  IN  INTERNAL_IMAGE_CONTEXT  *Image,
  OUT PHYSICAL_ADDRESS        **CodeBase,
  OUT UINT32                  *CodeSize
  )
{
  UINT16                               Magic;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  OptionalHeaderPtrUnion;

  if ((Image == NULL) || (CodeBase == NULL) || (CodeSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Determine the magic value based on the machine type
  //
  switch (Image->Context.Machine) {
    case EFI_IMAGE_MACHINE_IA32:
      Magic = EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC;
      break;
    case EFI_IMAGE_MACHINE_X64:
    case EFI_IMAGE_MACHINE_AARCH64:
      Magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
      break;
    default:
      return EFI_UNSUPPORTED;
  }

  OptionalHeaderPtrUnion.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINTN)Image->Context.ImageAddress + Image->Context.PeCoffHeaderOffset);

  //
  // Check the PE/COFF Header Signature
  //
  if (OptionalHeaderPtrUnion.Pe32->Signature != EFI_IMAGE_NT_SIGNATURE) {
    return EFI_UNSUPPORTED;
  }

  if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    *CodeBase = (VOID *)((UINTN)Image->Context.ImageAddress + OptionalHeaderPtrUnion.Pe32->OptionalHeader.BaseOfCode);
    *CodeSize = OptionalHeaderPtrUnion.Pe32->OptionalHeader.SizeOfCode;
  } else if (OptionalHeaderPtrUnion.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    *CodeBase = (VOID *)((UINTN)Image->Context.ImageAddress + OptionalHeaderPtrUnion.Pe32Plus->OptionalHeader.BaseOfCode);
    *CodeSize = OptionalHeaderPtrUnion.Pe32Plus->OptionalHeader.SizeOfCode;
  } else {
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}

/**
  Get the start address and size of a given section in a PE/COFF image.
  This function retrieves the start address and size of a given section in a PE/COFF image.
  @param[in]  Image            A pointer to the internal image context
  @param[in]  SectionName      A pointer to the section name.
  @param[out] SectionBase      A pointer to the base address of the section.
  @param[out] SectionSize      A pointer to the size of the section.
  @retval EFI_SUCCESS           The section is found.
  @retval EFI_INVALID_PARAMETER A parameter is invalid.
  @retval EFI_NOT_FOUND         The section is not found.
**/
EFI_STATUS
GetSectionByName (
  IN  INTERNAL_IMAGE_CONTEXT  *Image,
  IN  CHAR8                   *SectionName,
  OUT PHYSICAL_ADDRESS        **SectionBase,
  OUT UINT32                  *SectionSize
  )
{
  EFI_IMAGE_FILE_HEADER     *FileHeader;
  EFI_IMAGE_SECTION_HEADER  *SectionHeader;
  UINT16                    NumberOfSections;
  UINT16                    Index;

  if ((Image == NULL) || (SectionName == NULL) || (SectionBase == NULL) || (SectionSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  FileHeader = (EFI_IMAGE_FILE_HEADER *)((UINTN)Image->Context.ImageAddress + Image->Context.PeCoffHeaderOffset + sizeof (UINT32));

  SectionHeader = (EFI_IMAGE_SECTION_HEADER *)((UINTN)Image->Context.ImageAddress +
                                               Image->Context.PeCoffHeaderOffset +
                                               sizeof (UINT32) +
                                               sizeof (EFI_IMAGE_FILE_HEADER) +
                                               FileHeader->SizeOfOptionalHeader);

  NumberOfSections = FileHeader->NumberOfSections;

  for (Index = 0; Index < NumberOfSections; Index++) {
    if (AsciiStrnCmp ((CHAR8 *)SectionHeader[Index].Name, SectionName, EFI_IMAGE_SIZEOF_SHORT_NAME) == 0) {
      *SectionBase = (PHYSICAL_ADDRESS *)((UINTN)Image->Context.ImageAddress + SectionHeader[Index].VirtualAddress);
      *SectionSize = SectionHeader[Index].Misc.VirtualSize;
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

/**
  Convert section base and size to page start and page size.
  This function converts the section base and size to page start and page size.
  @param[in]  SectionBase      The base address of the section.
  @param[in]  SectionSize      The size of the section.
  @param[out] PageStart        The start address of the page.
  @param[out] PageSize         The size of the page.
  @retval EFI_SUCCESS           The conversion is successful.
  @retval EFI_INVALID_PARAMETER A parameter is invalid.
**/
EFI_STATUS
ConvertSectionToPage (
  IN  PHYSICAL_ADDRESS  SectionBase,
  IN  UINT32            SectionSize,
  OUT PHYSICAL_ADDRESS  *PageStart,
  OUT UINT32            *PageSize
  )
{
  if ((SectionBase == (PHYSICAL_ADDRESS)NULL) || (PageStart == (PHYSICAL_ADDRESS)NULL) || (PageSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *PageStart = SectionBase & ~(EFI_PAGE_SIZE - 1);
  //TODO This is unsafe
  *PageSize  = (UINT32)((((UINT64)SectionBase + (UINT64)SectionSize + EFI_PAGE_SIZE - 1) & ~(EFI_PAGE_SIZE - 1)) - (UINT64)*PageStart);

  return EFI_SUCCESS;
}


/**
  Get the Import Directory in a PE/COFF image.
  This function retrieves the Import Directory in a PE/COFF image.
  @param[in]  Image                     A pointer to the base address of the PE/COFF image.
  @param[out] ImageImportDirectory      A pointer to the Import Directory structure.
  @retval EFI_SUCCESS                    The Import Directory is found.
  @retval EFI_INVALID_PARAMETER          A parameter is invalid.
  @retval EFI_UNSUPPORTED                The image is not a valid PE/COFF image.
  @retval EFI_NOT_FOUND                  The Import Directory is not found.
**/
EFI_STATUS
GetImportDirectoryInPeCoffImage (
  IN  INTERNAL_IMAGE_CONTEXT      *Image,
  OUT EFI_IMAGE_IMPORT_DESCRIPTOR **ImageImportDirectory
  )
{
  UINT16                               Magic;
  UINT32                               NumberOfRvaAndSizes;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  OptionalHeaderPtrUnion;
  EFI_IMAGE_DATA_DIRECTORY             *DirectoryEntry;
  EFI_IMAGE_IMPORT_DESCRIPTOR          *ImportDirectory;

  if ((Image == NULL) || (ImageImportDirectory == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  DirectoryEntry  = NULL;
  ImportDirectory = NULL;

  switch (Image->Context.Machine) {
    case EFI_IMAGE_MACHINE_IA32:
      Magic = EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC;
      break;
    case EFI_IMAGE_MACHINE_X64:
    case EFI_IMAGE_MACHINE_AARCH64:
      Magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
      break;
    default:
      return EFI_UNSUPPORTED;
  }

  OptionalHeaderPtrUnion.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINTN)Image->Context.ImageAddress + Image->Context.PeCoffHeaderOffset);

  if (OptionalHeaderPtrUnion.Pe32->Signature != EFI_IMAGE_NT_SIGNATURE) {
    return EFI_UNSUPPORTED;
  }

  if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    NumberOfRvaAndSizes = OptionalHeaderPtrUnion.Pe32->OptionalHeader.NumberOfRvaAndSizes;
    DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&(OptionalHeaderPtrUnion.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_IMPORT]);
  } else if (OptionalHeaderPtrUnion.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    NumberOfRvaAndSizes = OptionalHeaderPtrUnion.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
    DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&(OptionalHeaderPtrUnion.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_IMPORT]);
  } else {
    return EFI_UNSUPPORTED;
  }

  if ((NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_IMPORT) || (DirectoryEntry->VirtualAddress == 0)) {
    return EFI_NOT_FOUND;
  } else if (((UINT32)(~0) - DirectoryEntry->VirtualAddress) < DirectoryEntry->Size) {
    return EFI_UNSUPPORTED;
  } else {
    ImportDirectory = (EFI_IMAGE_IMPORT_DESCRIPTOR *)((UINTN)Image->Context.ImageAddress + DirectoryEntry->VirtualAddress);
  }

  *ImageImportDirectory = ImportDirectory;

  return EFI_SUCCESS;
}

/**
  Set the Import Directory in a PE/COFF image.
  This function sets the Import Directory in a PE/COFF image.
  @param[in]  Image                     A pointer to the base address of the PE/COFF image.
  @param[in]  ImageImportDirectory      A pointer to the Import Directory structure.
  @retval EFI_SUCCESS                    The Import Directory is set.
  @retval EFI_INVALID_PARAMETER          A parameter is invalid.
  @retval EFI_UNSUPPORTED                The image is not a valid PE/COFF image.
**/
EFI_STATUS
SetImportDirectoryInPeCoffImage (
  IN  INTERNAL_IMAGE_CONTEXT      *Image,
  IN  EFI_IMAGE_IMPORT_DESCRIPTOR *ImageImportDirectory
  )
{
  UINT16                               Magic;
  UINT32                               NumberOfRvaAndSizes;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  OptionalHeaderPtrUnion;
  EFI_IMAGE_DATA_DIRECTORY             *DirectoryEntry;

  if ((Image == NULL) || (ImageImportDirectory == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  DirectoryEntry = NULL;

  switch (Image->Context.Machine) {
    case EFI_IMAGE_MACHINE_IA32:
      Magic = EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC;
      break;
    case EFI_IMAGE_MACHINE_X64:
    case EFI_IMAGE_MACHINE_AARCH64:
      Magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
      break;
    default:
      return EFI_UNSUPPORTED;
  }

  OptionalHeaderPtrUnion.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINTN)Image->Context.ImageAddress + Image->Context.PeCoffHeaderOffset);

  if (OptionalHeaderPtrUnion.Pe32->Signature != EFI_IMAGE_NT_SIGNATURE) {
    return EFI_UNSUPPORTED;
  }

  if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    NumberOfRvaAndSizes = OptionalHeaderPtrUnion.Pe32->OptionalHeader.NumberOfRvaAndSizes;
    DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&(OptionalHeaderPtrUnion.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_IMPORT]);
  } else if (OptionalHeaderPtrUnion.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    NumberOfRvaAndSizes = OptionalHeaderPtrUnion.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
    DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&(OptionalHeaderPtrUnion.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_IMPORT]);
  } else {
    return EFI_UNSUPPORTED;
  }

  if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_IMPORT) {
    return EFI_UNSUPPORTED;
  }

  DirectoryEntry->VirtualAddress = (UINT32)((UINTN)ImageImportDirectory - (UINTN)Image->Context.ImageAddress);
  DirectoryEntry->Size = sizeof(EFI_IMAGE_IMPORT_DESCRIPTOR);

  return EFI_SUCCESS;
}