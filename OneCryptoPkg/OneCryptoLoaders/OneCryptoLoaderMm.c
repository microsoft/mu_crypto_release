/** @file
  OneCryptoLoaderMm.c

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

  This file contains the implementation of the OneCryptoLoader MM driver,
  which is responsible for loading and initializing the shared cryptographic
  library and its dependencies.

  RNG REQUIREMENTS:
  - MM environment requires EFI_RNG_PROTOCOL for cryptographic operations needing entropy
  - Platforms must provide RNG support in MM or override RngLib implementation

**/

#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SafeIntLib.h>
#include <Library/RngLib.h>
#include <Library/HobLib.h>
#include <Protocol/Rng.h>
#include <Library/FvLib.h>

#include <Protocol/OneCrypto.h>
#include <Private/OneCryptoDependencySupport.h>

//
// The dependencies of the shared library, must live as long
// as the shared code is used
//
ONE_CRYPTO_DEPENDENCIES  *mOneCryptoDepends = NULL;
//
// Crypto protocol for the shared library
// Using VOID* to be agnostic about protocol structure size/layout
//
VOID  *OneCryptoProtocol = NULL;

//
// Lazy RNG state tracking for MM environment
//
STATIC BOOLEAN           mMmRngInitAttempted   = FALSE;
STATIC EFI_RNG_PROTOCOL  *mMmCachedRngProtocol = NULL;

/**
 * @brief Lazy RNG implementation for MM environment with assertion on failure
 *
 * This function implements lazy initialization of the RNG protocol in MM environment.
 * Unlike the DXE version, this asserts if no RNG protocol is available since
 * MM environment should have controlled protocol access.
 *
 * @param[out] Rand Pointer to buffer to receive the 64-bit random number
 * @return TRUE if random number generated successfully, FALSE with assertion if protocol unavailable
 */
BOOLEAN
EFIAPI
LazyMmGetRandomNumber64 (
  OUT UINT64  *Rand
  )
{
  EFI_STATUS  Status;
  UINT8       *RandBytes;

  if (Rand == NULL) {
    DEBUG ((DEBUG_ERROR, "LazyMmGetRandomNumber64: Null Rand pointer\n"));
    ASSERT (FALSE);
    return FALSE;
  }

  //
  // Only attempt to locate the RNG protocol once
  //
  if (!mMmRngInitAttempted) {
    DEBUG ((DEBUG_INFO, "LazyMmGetRandomNumber64: First call, locating EFI_RNG_PROTOCOL in MM\n"));

    Status = gMmst->MmLocateProtocol (
                      &gEfiRngProtocolGuid,
                      NULL,
                      (VOID **)&mMmCachedRngProtocol
                      );

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "LazyMmGetRandomNumber64: EFI_RNG_PROTOCOL not available in MM environment, Status=%r\n", Status));
      DEBUG ((DEBUG_ERROR, "LazyMmGetRandomNumber64: MM environment should provide RNG protocol for secure crypto operations\n"));
      mMmCachedRngProtocol = NULL;
      //
      // Assert because MM should have controlled access to RNG
      //
      ASSERT_EFI_ERROR (Status);
    } else {
      DEBUG ((DEBUG_INFO, "LazyMmGetRandomNumber64: EFI_RNG_PROTOCOL located at %p\n", mMmCachedRngProtocol));
    }

    mMmRngInitAttempted = TRUE;
  }

  //
  // If we don't have RNG protocol after attempting to locate it, assert
  //
  if (mMmCachedRngProtocol == NULL) {
    DEBUG ((DEBUG_ERROR, "LazyMmGetRandomNumber64: No RNG protocol available in MM environment\n"));
    ASSERT (mMmCachedRngProtocol != NULL);
    return FALSE;
  }

  //
  // Use the cached RNG protocol
  //
  RandBytes = (UINT8 *)Rand;
  Status    = mMmCachedRngProtocol->GetRNG (mMmCachedRngProtocol, NULL, sizeof (UINT64), RandBytes);

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "LazyMmGetRandomNumber64: GetRNG failed in MM environment, Status=%r\n", Status));
    return FALSE;
  }

  DEBUG ((DEBUG_VERBOSE, "LazyMmGetRandomNumber64: Successfully generated random number in MM\n"));
  return TRUE;
}

/**
 * @brief Stub implementation of MicroSecondDelay for MM environment
 *
 * This doesn't appear to be needed since sleep is only used in
 * HTTP / QUIC / CMP - none of which are used by UEFI firmware.
 *
 * @param[in] MicroSeconds The number of microseconds to delay (ignored)
 * @return The input MicroSeconds value (no actual delay occurs)
 */
UINTN
EFIAPI
StubMicroSecondDelay (
  IN UINTN  MicroSeconds
  )
{
  //
  // Stub implementation - returns immediately.
  //
  return MicroSeconds;
}

/**
 * @brief Installs shared dependencies required for the application.
 *
 * This function handles the installation of shared dependencies that are
 * necessary for the application to run properly. It ensures that all
 * required libraries and packages are installed and up to date.
 *
 * @param dependencies A list of dependencies to be installed.
 */
VOID
InstallSharedDependencies (
  OUT ONE_CRYPTO_DEPENDENCIES  *OneCryptoDepends
  )
{
  //
  // Set version information for compatibility checking
  //
  OneCryptoDepends->Major        = ONE_CRYPTO_DEPENDENCIES_VERSION_MAJOR;
  OneCryptoDepends->Minor        = ONE_CRYPTO_DEPENDENCIES_VERSION_MINOR;
  OneCryptoDepends->Reserved     = 0;
  OneCryptoDepends->AllocatePool = AllocatePool;
  OneCryptoDepends->FreePool     = FreePool;
  OneCryptoDepends->DebugPrint   = DebugPrint;
  OneCryptoDepends->GetTime      = NULL;
  //
  // Use lazy RNG initialization for MM environment - will assert if protocol unavailable
  //
  OneCryptoDepends->GetRandomNumber64 = LazyMmGetRandomNumber64;
  //
  // Use stub for MicroSecondDelay - not needed in MM environment
  //
  OneCryptoDepends->MicroSecondDelay = StubMicroSecondDelay;
}

/**
 * Entry point for the DXE (Driver Execution Environment) phase.
 *
 * This function is the main entry point for the DXE phase of the UEFI (Unified Extensible Firmware Interface) firmware.
 * It is responsible for initializing the DXE environment and executing the DXE drivers.
 *
 * @param ImageHandle  The firmware allocated handle for the EFI image.
 * @param SystemTable  A pointer to the EFI System Table.
 *
 * @retval EFI_SUCCESS           The entry point is executed successfully.
 * @retval EFI_LOAD_ERROR        Failed to load the DXE environment.
 * @retval EFI_INVALID_PARAMETER One or more parameters are invalid.
 */
EFI_STATUS
EFIAPI
MmEntry (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *MmSystemTable
  )
{
  EFI_STATUS                       Status;
  ONE_CRYPTO_CONSTRUCTOR_PROTOCOL  *ConstructorProtocol;
  EFI_HANDLE                       ProtocolHandle = NULL;
  UINT32                           CryptoSize     = 0;

  //
  // Locate the private protocol that provides the constructor
  //
  Status = MmSystemTable->MmLocateProtocol (
                            &gOneCryptoPrivateProtocolGuid,
                            NULL,
                            (VOID **)&ConstructorProtocol
                            );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderMm: Failed to locate OneCrypto private protocol: %r\n", Status));
    goto Exit;
  }

  if (ConstructorProtocol->Signature != ONE_CRYPTO_CONSTRUCTOR_PROTOCOL_SIGNATURE) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderMm: OneCrypto private protocol signature is invalid: %x\n", ConstructorProtocol->Signature));
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "OneCryptoLoaderMm: OneCrypto private protocol found: %g\n", &gOneCryptoPrivateProtocolGuid));

  //
  // Ensure that the crypto entry function is not NULL
  //
  if (ConstructorProtocol->Entry == NULL) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderMm: Crypto entry function is NULL\n"));
    Status = EFI_UNSUPPORTED;
    goto Exit;
  }

  //
  // Initialize the Shared dependencies
  //

  if (mOneCryptoDepends == NULL) {
    mOneCryptoDepends = AllocatePool (sizeof (*mOneCryptoDepends));
    if (mOneCryptoDepends == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Exit;
    }

    InstallSharedDependencies (mOneCryptoDepends);
  }

  //
  // First, query the size needed for the crypto protocol
  //
  Status = ConstructorProtocol->Entry (mOneCryptoDepends, NULL, &CryptoSize);
  if ((Status != EFI_BUFFER_TOO_SMALL) || (CryptoSize == 0)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderMm:Failed to query crypto protocol size: %r\n", Status));
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "OneCryptoLoaderMm: OneCrypto Protocol size: %d bytes\n", CryptoSize));

  //
  // Allocate memory for the crypto protocol
  //
  OneCryptoProtocol = AllocatePool (CryptoSize);
  if (OneCryptoProtocol == NULL) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderMm: Failed to allocate memory for crypto protocol\n"));
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  //
  // Call library constructor to initialize the protocol
  //
  Status = ConstructorProtocol->Entry (mOneCryptoDepends, &OneCryptoProtocol, &CryptoSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderMm: Failed to call LibConstructor: %r\n", Status));
    FreePool (OneCryptoProtocol);
    OneCryptoProtocol = NULL;
    goto Exit;
  }

  DEBUG ((DEBUG_INFO, "OneCrypto Protocol CryptoEntry called successfully.\n"));

  DEBUG ((DEBUG_INFO, "Installing OneCrypto Protocol...\n"));
  Status = MmSystemTable->MmInstallProtocolInterface (
                            &ProtocolHandle,
                            &gOneCryptoProtocolGuid,
                            EFI_NATIVE_INTERFACE,
                            OneCryptoProtocol
                            );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to install protocol: %r\n", Status));
    goto Exit;
  }

  Status = EFI_SUCCESS;

Exit:

  //
  // The dependencies that the OneCrypto needs may not be freed unless there was an error.
  // If there is no error then the memory must live long past this driver to fulfill
  // crypto requests.
  //
  if ((Status != EFI_SUCCESS) && (mOneCryptoDepends != NULL)) {
    FreePool (mOneCryptoDepends);
  }

  return Status;
}
