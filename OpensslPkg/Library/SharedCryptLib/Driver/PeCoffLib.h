#ifndef SHARED_LOADER_PE_COFF_LIB_H__
#define SHARED_LOADER_PE_COFF_LIB_H__

#include <Uefi.h>
#include <Library/PeCoffLib.h>

typedef struct _INTERNAL_IMAGE_CONTEXT {
  //
  // Size of the Image in Bytes
  //
  UINTN                           Size;
  //
  // Number of Pages required
  //
  UINTN                           NumberOfPages;
  //
  // The allocated memory base
  // this may or may not align to the image start
  //
  EFI_PHYSICAL_ADDRESS            PageBase;
  //
  // The image context required by PeCoff functions
  //
  PE_COFF_LOADER_IMAGE_CONTEXT    Context;
} INTERNAL_IMAGE_CONTEXT;

/**
  Get the Export Directory in a PE/COFF image.
  This function retrieves the Export Directory in a PE/COFF image.
  @param[in]  Image                     A pointer to the base address of the PE/COFF image.
  @param[in]  PeCoffLoaderImageContext   A pointer to the PE_COFF_LOADER_IMAGE_CONTEXT structure.
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
  );

/**
  Print the exported functions in a PE/COFF image.
  This function prints the exported functions in a PE/COFF image.
  @param[in] Image              A pointer to the base address of the PE/COFF image.
  @param[in] ExportDirectory    A pointer to the Export Directory structure.
**/
VOID
PrintExportedFunctions (
  IN  INTERNAL_IMAGE_CONTEXT     *Image,
  IN EFI_IMAGE_EXPORT_DIRECTORY  *ExportDirectory
  );

/**
  Find an exported function in a PE/COFF image.
  This function finds an exported function in a PE/COFF image.
  @param[in]  Image            A pointer to the base address of the PE/COFF image.
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
  );

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
  );

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
  );

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
  );

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
  );

#endif // SHARED_LOADER_PE_COFF_LIB_H__
