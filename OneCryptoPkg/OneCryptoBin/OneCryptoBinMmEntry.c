/** @file
  MM Entry Point for OneCryptoBin.

  This file implements the MM driver entry point for StandaloneMm and SupvMm
  environments. It installs the private protocol that MM loaders use to
  discover the crypto binary.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
// #include <Library/StandaloneMmDriverEntryPoint.h> # Intentionally not included
#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Protocol/OneCrypto.h>

#include "OneCryptoBin.h"

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
  EFI_STATUS                       Status;
  EFI_HANDLE                       Handle;
  ONE_CRYPTO_CONSTRUCTOR_PROTOCOL  *ProtocolInstance;

  if (MmSystemTable == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Handle = NULL;

  Status = MmSystemTable->MmAllocatePool (
                            EfiRuntimeServicesData,
                            sizeof (ONE_CRYPTO_CONSTRUCTOR_PROTOCOL),
                            (VOID **)&ProtocolInstance
                            );

  if (EFI_ERROR (Status) || (ProtocolInstance == NULL)) {
    return EFI_OUT_OF_RESOURCES;
  }

  ProtocolInstance->Signature = ONE_CRYPTO_CONSTRUCTOR_PROTOCOL_SIGNATURE;
  ProtocolInstance->Version   = 1;
  //
  // Use NoSetupCryptoEntry because MmEntry is called by the standard UEFI loader,
  // which has already executed library constructors (including BaseCryptInit).
  //
  ProtocolInstance->Entry = NoSetupCryptoEntry;

  Status = MmSystemTable->MmInstallProtocolInterface (
                            &Handle,
                            &gOneCryptoPrivateProtocolGuid,
                            EFI_NATIVE_INTERFACE,
                            ProtocolInstance
                            );

  if (EFI_ERROR (Status)) {
    MmSystemTable->MmFreePool (ProtocolInstance);
    return Status;
  }

  return EFI_SUCCESS;
}
