/** @file
  PE/COFF loader library header for OneCrypto loaders.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef ONE_CRYPTO_PE_COFF_LIB_H__
#define ONE_CRYPTO_PE_COFF_LIB_H__

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
  @param[in]  Image                      A pointer to the base address of the PE/COFF image.
  @param[in]  PeCoffLoaderImageContext   A pointer to the PE_COFF_LOADER_IMAGE_CONTEXT structure.
  @param[out] ImageExportDirectory       A pointer to the Export Directory structure.
  @retval EFI_SUCCESS                    The Export Directory is found.
  @retval EFI_INVALID_PARAMETER          A parameter is invalid.
  @retval EFI_UNSUPPORTED                The image is not a valid PE/COFF image.
  @retval EFI_NOT_FOUND                  The Export Directory is not found.
**/
EFI_STATUS
EFIAPI
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
  @param[in]  Image             A pointer to the base address of the PE/COFF image.
  @param[in]  ExportDirectory   A pointer to the Export Directory structure.
  @param[in]  FunctionName      A pointer to the function name.
  @param[out] FunctionAddress   A pointer to the function address.
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

#endif // ONE_CRYPTO_PE_COFF_LIB_H__
