/** @file
  This sample application that is the simplest UEFI application possible.
  It simply prints "Hello Uefi!" to the UEFI Console Out device and stalls the CPU for 30 seconds.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
// #include <Library/StandaloneMmDriverEntryPoint.h> # Intentionally not included
#include <Library/MmServicesTableLib.h>
#include <Private/SharedCrtLibSupport.h>
#include "Shared/SharedOpenssl.h"
#include <Library/SharedCryptoDependencySupport.h>

// #if defined(_MSC_VER)
#define COMMON_EXPORT_API  __declspec(dllexport)


SHARED_CRYPTO_MM_CONSTRUCTOR_PROTOCOL *ProtocolInstance = NULL;


COMMON_EXPORT_API
EFI_STATUS
EFIAPI
Constructor (
  IN SHARED_DEPENDENCIES *Depends,
  OUT VOID  *RequestedCrypto
  )
{
  //
  // Map the provided depencencies to our global instance
  //
  gSharedDepends = Depends;

  // TODO DEBUG_ERROR = DEBUG_INFO?
  // CRASHPOINT
  //
  DEBUG((DEBUG_ERROR, "SharedCryptoBin: Constructor entry called\n"));

  //
  // Build the Crypto
  //
  CryptoInit (RequestedCrypto);

  return EFI_SUCCESS;
}

/**
  MM Entry Point for the Shared Crypto MM Driver.

  @param[in] ImageHandle      The firmware allocated handle for the EFI image.
  @param[in] MmSystemTable    A pointer to the MM System Table.

  @retval EFI_SUCCESS         The entry point executed successfully.
  @retval EFI_OUT_OF_RESOURCES Failed to allocate memory.
  @retval other               Error returned by protocol installation.
**/
EFI_STATUS
EFIAPI
MmEntry (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *MmSystemTable
  )
{
  EFI_STATUS Status;
  EFI_HANDLE Handle = NULL;

  if (MmSystemTable == NULL) {
    DEBUG((DEBUG_ERROR, "SharedCryptoBin: MmSystemTable is NULL\n"));
    return EFI_INVALID_PARAMETER;
  }

  Status = MmSystemTable->MmAllocatePool (
                    EfiRuntimeServicesData,
                    sizeof (SHARED_CRYPTO_MM_CONSTRUCTOR_PROTOCOL),
                    (VOID **)&ProtocolInstance
                    );

  if (EFI_ERROR(Status) || ProtocolInstance == NULL) {
    DEBUG((DEBUG_ERROR, "SharedCryptoBin: Failed to allocate memory for constructor protocol: %r\n", Status));
    return EFI_OUT_OF_RESOURCES;
  }

  ProtocolInstance->Signature = SHARED_CRYPTO_MM_CONSTRUCTOR_PROTOCOL_SIGNATURE;
  ProtocolInstance->Version = 1;
  ProtocolInstance->Constructor = Constructor;

  Status = MmSystemTable->MmInstallProtocolInterface (
                    &Handle,
                    &gSharedCryptoPrivateProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    ProtocolInstance
                    );

  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "SharedCryptoBin: Failed to install protocol: %r\n", Status));
    MmSystemTable->MmFreePool(ProtocolInstance);
    ProtocolInstance = NULL;
    return Status;
  }

  DEBUG((DEBUG_INFO, "SharedCryptoBin: Protocol installed successfully\n"));

  return EFI_SUCCESS;
}