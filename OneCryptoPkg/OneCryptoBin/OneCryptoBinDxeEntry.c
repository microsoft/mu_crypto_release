/** @file
  DXE Entry Point for OneCryptoBin.

  This file implements the DXE driver entry point that installs the private protocol
  for protocol-based DXE loaders to discover the crypto binary. This approach avoids
  PE/COFF export parsing which may not work on AARCH64 and other architectures.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Protocol/OneCrypto.h>

#include "OneCryptoBin.h"

/**
  DXE Entry Point for the Shared Crypto DXE Driver.

  This entry point installs the private protocol that the protocol-based DXE loader
  uses to discover the crypto binary. This approach avoids PE/COFF export parsing
  which may not work on AARCH64 and other architectures where the toolchain doesn't
  generate export tables in the same way as MSVC.

  @param[in] ImageHandle      The firmware allocated handle for the EFI image.
  @param[in] SystemTable      A pointer to the EFI System Table.

  @retval EFI_SUCCESS         The entry point executed successfully.
  @retval EFI_OUT_OF_RESOURCES Failed to allocate memory.
  @retval other               Error returned by protocol installation.
**/
EFI_STATUS
EFIAPI
DxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                       Status;
  EFI_HANDLE                       Handle;
  ONE_CRYPTO_CONSTRUCTOR_PROTOCOL  *ProtocolInstance;

  Handle = NULL;

  Status = gBS->AllocatePool (
                  EfiBootServicesData,
                  sizeof (ONE_CRYPTO_CONSTRUCTOR_PROTOCOL),
                  (VOID **)&ProtocolInstance
                  );

  if (EFI_ERROR (Status) || (ProtocolInstance == NULL)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoBinDxe: Failed to allocate protocol instance\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  ProtocolInstance->Signature = ONE_CRYPTO_CONSTRUCTOR_PROTOCOL_SIGNATURE;
  ProtocolInstance->Version   = 1;
  //
  // Use NoSetupCryptoEntry because DxeEntry is called by the standard UEFI loader,
  // which has already executed library constructors (including BaseCryptInit).
  //
  ProtocolInstance->Entry = NoSetupCryptoEntry;

  Status = gBS->InstallProtocolInterface (
                  &Handle,
                  &gOneCryptoPrivateProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  ProtocolInstance
                  );

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoBinDxe: Failed to install private protocol: %r\n", Status));
    gBS->FreePool (ProtocolInstance);
    return Status;
  }

  DEBUG ((DEBUG_INFO, "OneCryptoBinDxe: Private protocol installed successfully\n"));
  return EFI_SUCCESS;
}
