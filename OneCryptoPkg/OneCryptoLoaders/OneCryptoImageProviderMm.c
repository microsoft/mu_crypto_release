/** @file
  OneCryptoImageProviderMm.c

  Locates OneCrypto in the StandaloneMM firmware volumes and serves its bytes to
  the DXE loader over MM communication.

  Supported discovery paths are:
    1) direct PE32 from ONE_CRYPTO_BINARY_GUID, or
    2) compressed payload from ONE_CRYPTO_CONTAINER_FV_GUID.

  If neither exists, this provider returns an EFI error; platform policy may
  assert/fail-fast rather than continue without crypto.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Pi/PiHob.h>
#include <Pi/PiFirmwareFile.h>
#include <Pi/PiFirmwareVolume.h>

#include <Guid/OneCryptoFileGuid.h>
#include <Guid/OneCryptoImageProviderGuid.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/FvLib.h>
#include <Library/HobLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/StandaloneMmMemLib.h>

#include <Protocol/MmReadyToLock.h>

#include <Private/OneCryptoImageProviderMessage.h>

STATIC EFI_GUID  mOneCryptoBinaryGuid        = ONE_CRYPTO_BINARY_GUID;
STATIC EFI_GUID  mOneCryptoContainerFvGuid   = ONE_CRYPTO_CONTAINER_FV_GUID;
EFI_GUID         gOneCryptoImageProviderGuid = ONE_CRYPTO_IMAGE_PROVIDER_GUID;

//
// Located OneCrypto payload: a pointer into resident MM firmware (either the raw
// PE32 image, or the compressed container FV section) plus the format that
// tells DXE how to consume it. Cached after the first successful lookup.
//
STATIC VOID    *mOneCryptoImageData  = NULL;
STATIC UINTN   mOneCryptoImageSize   = 0;
STATIC UINT32  mOneCryptoImageFormat = ONE_CRYPTO_IMAGE_FORMAT_PE32;

//
// Dispatch handle for the registered image-provider MMI handler and the
// ReadyToLock protocol-notify registration used to tear it down after the
// OneCrypto image has been fetched and launched during DXE.
//
STATIC EFI_HANDLE  mDispatchHandle           = NULL;
STATIC VOID        *mReadyToLockRegistration = NULL;

//
// DEBUG-only CRC32 over the located image, computed once and cached. Serves as a
// transport-integrity aid for the DXE receiver (see ONE_CRYPTO_IMAGE_PROVIDER_MSG).
// Left 0 in RELEASE builds, where the receiver performs no check.
//
STATIC UINT32  mOneCryptoImageCrc32 = 0;

/**
  Scan one firmware volume for OneCrypto.

  Two types are recognised:
    - the OneCrypto file carrying a direct PE32 section (uncompressed platforms),
      served as ONE_CRYPTO_IMAGE_FORMAT_PE32; and
    - a compressed GUID_DEFINED section wrapping the nested FV that holds
      OneCrypto, whose raw compressed stream is served as
      ONE_CRYPTO_IMAGE_FORMAT_GUIDED_FV for DXE to decode.

  A direct PE32 is preferred when both are present.

  @param[in]  FvHeader  Firmware volume to scan.

  @retval EFI_SUCCESS    OneCrypto located; module globals populated.
  @retval EFI_NOT_FOUND  Not found in this FV.
**/
STATIC
EFI_STATUS
ScanFvForOneCrypto (
  IN EFI_FIRMWARE_VOLUME_HEADER  *FvHeader
  )
{
  EFI_STATUS                 Status;
  EFI_FFS_FILE_HEADER        *FileHeader;
  EFI_COMMON_SECTION_HEADER  *Section;
  EFI_COMMON_SECTION_HEADER  *ContainerSection;
  VOID                       *SectionData;
  UINTN                      SectionDataSize;
  UINTN                      DataOffset;
  UINTN                      SectionSize;

  ContainerSection = NULL;
  FileHeader       = NULL;

  if (FvHeader == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  while (TRUE) {
    Status = FfsFindNextFile (EFI_FV_FILETYPE_ALL, FvHeader, &FileHeader);
    if (EFI_ERROR (Status)) {
      break;
    }

    //
    // Preferred: the OneCrypto file carrying a direct PE32 image.
    //
    if (CompareGuid (&FileHeader->Name, &mOneCryptoBinaryGuid)) {
      Status = FfsFindSectionData (EFI_SECTION_PE32, FileHeader, &SectionData, &SectionDataSize);
      if (!EFI_ERROR (Status) && (SectionData != NULL) && (SectionDataSize != 0)) {
        mOneCryptoImageData   = SectionData;
        mOneCryptoImageSize   = SectionDataSize;
        mOneCryptoImageFormat = ONE_CRYPTO_IMAGE_FORMAT_PE32;
        DEBUG ((
          DEBUG_INFO,
          "OneCryptoImageProviderMm: Found direct OneCrypto PE32 size=0x%Lx\n",
          (UINT64)SectionDataSize
          ));
        return EFI_SUCCESS;
      }
    }

    //
    // Compressed source: the dedicated OneCrypto container FV, a file tagged
    // with the well-known ONE_CRYPTO_CONTAINER_FV_GUID whose GUID_DEFINED
    // section wraps the nested FV holding OneCrypto. Matching by this file
    // identity keeps discovery deterministic when the boot FV also carries other
    // compressed nested FVs (e.g. the StandaloneMM payload FV). The provider
    // does not inspect the compression scheme -- it serves the raw section and
    // the DXE loader decodes it via ExtractGuidedSectionLib.
    //
    if ((ContainerSection == NULL) &&
        CompareGuid (&FileHeader->Name, &mOneCryptoContainerFvGuid))
    {
      Status = FfsFindSection (EFI_SECTION_GUID_DEFINED, FileHeader, &Section);
      if (!EFI_ERROR (Status)) {
        ContainerSection = Section;
      }
    }
  }

  if (ContainerSection != NULL) {
    if (IS_SECTION2 (ContainerSection)) {
      DataOffset  = ((CONST EFI_GUID_DEFINED_SECTION2 *)ContainerSection)->DataOffset;
      SectionSize = SECTION2_SIZE (ContainerSection);
    } else {
      DataOffset  = ((CONST EFI_GUID_DEFINED_SECTION *)ContainerSection)->DataOffset;
      SectionSize = SECTION_SIZE (ContainerSection);
    }

    if ((DataOffset < SectionSize) && (SectionSize > sizeof (EFI_COMMON_SECTION_HEADER))) {
      //
      // Hand DXE the whole GUID_DEFINED section, header included, so it can
      // decode it with ExtractGuidedSectionLib's registered handler.
      //
      mOneCryptoImageData   = (UINT8 *)ContainerSection;
      mOneCryptoImageSize   = SectionSize;
      mOneCryptoImageFormat = ONE_CRYPTO_IMAGE_FORMAT_GUIDED_FV;
      DEBUG ((
        DEBUG_INFO,
        "OneCryptoImageProviderMm: Serving GUID_DEFINED section to DXE size=0x%Lx\n",
        (UINT64)mOneCryptoImageSize
        ));
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

/**
  Locate OneCrypto across the StandaloneMM FV and FV2 HOBs. The result is cached
  in module globals for subsequent chunked requests.

  @retval EFI_SUCCESS    OneCrypto located.
  @retval EFI_NOT_FOUND  OneCrypto not present in any MM firmware volume.
**/
STATIC
EFI_STATUS
LocateOneCryptoImage (
  VOID
  )
{
  EFI_PEI_HOB_POINTERS  Hob;

  if ((mOneCryptoImageData != NULL) && (mOneCryptoImageSize != 0)) {
    return EFI_SUCCESS;
  }

  //
  // FV3 Hobs supersede FV and FV2
  //
  for (Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV3, GetHobList ());
       Hob.Raw != NULL;
       Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV3, GET_NEXT_HOB (Hob)))
  {
    if ((Hob.FirmwareVolume3 == NULL) || (Hob.FirmwareVolume3->Length == 0)) {
      continue;
    }

    if (!EFI_ERROR (ScanFvForOneCrypto ((EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)Hob.FirmwareVolume3->BaseAddress))) {
      return EFI_SUCCESS;
    }
  }

  for (Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV, GetHobList ());
       Hob.Raw != NULL;
       Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV, GET_NEXT_HOB (Hob)))
  {
    if ((Hob.FirmwareVolume == NULL) || (Hob.FirmwareVolume->Length == 0)) {
      continue;
    }

    if (!EFI_ERROR (ScanFvForOneCrypto ((EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)Hob.FirmwareVolume->BaseAddress))) {
      return EFI_SUCCESS;
    }
  }

  for (Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV2, GetHobList ());
       Hob.Raw != NULL;
       Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV2, GET_NEXT_HOB (Hob)))
  {
    if ((Hob.FirmwareVolume2 == NULL) || (Hob.FirmwareVolume2->Length == 0)) {
      continue;
    }

    if (!EFI_ERROR (ScanFvForOneCrypto ((EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)Hob.FirmwareVolume2->BaseAddress))) {
      return EFI_SUCCESS;
    }
  }

  DEBUG ((DEBUG_ERROR, "OneCryptoImageProviderMm: OneCrypto not found in any MM FV HOB\n"));
  return EFI_NOT_FOUND;
}

/**
  MM communication handler that provides OneCrypto image bytes to DXE.

  Request protocol (ONE_CRYPTO_IMAGE_PROVIDER_MSG):
    - RequestedSize == 0 : size query. Returns TotalImageSize + Format.
    - RequestedSize  > 0 : returns up to RequestedSize bytes at Offset.

  @param[in]      DispatchHandle    Dispatch handle for this handler.
  @param[in]      Context           Handler context (unused).
  @param[in, out] CommBuffer        Message payload buffer.
  @param[in, out] CommBufferSize    Input/output payload buffer size.

  @retval EFI_SUCCESS  Always. Per the PI spec an MMI handler may only return one
                       of EFI_SUCCESS / EFI_WARN_INTERRUPT_SOURCE_QUIESCED /
                       EFI_WARN_INTERRUPT_SOURCE_PENDING / EFI_INTERRUPT_PENDING.
                       The operational result is reported in the response message
                       Status field (ONE_CRYPTO_IMAGE_PROVIDER_MSG.Status).
**/
STATIC
EFI_STATUS
EFIAPI
OneCryptoImageProviderHandler (
  IN EFI_HANDLE  DispatchHandle,
  IN CONST VOID  *Context        OPTIONAL,
  IN OUT VOID    *CommBuffer     OPTIONAL,
  IN OUT UINTN   *CommBufferSize OPTIONAL
  )
{
  ONE_CRYPTO_IMAGE_PROVIDER_MSG  *Msg;
  UINTN                          HeaderSize;
  UINTN                          InputBufferSize;
  UINTN                          MaxPayload;
  UINTN                          Remaining;
  UINTN                          CopySize;
  UINT32                         LocalSignature;
  UINT32                         LocalVersion;
  UINT64                         LocalOffset;
  UINT32                         LocalRequestedSize;
  EFI_STATUS                     Status;

  if ((CommBuffer == NULL) || (CommBufferSize == NULL)) {
    //
    // The MM core always supplies both for a registered handler; a NULL here is
    // a framework contract violation that cannot be reported through the buffer.
    // MMI handlers may only return the PI-defined status codes, so quiesce.
    //
    ASSERT (FALSE);
    return EFI_SUCCESS;
  }

  HeaderSize = OFFSET_OF (ONE_CRYPTO_IMAGE_PROVIDER_MSG, Data);

  //
  // Snapshot *CommBufferSize once before use: on AARCH64 CommBuffer lives in
  // Non-Secure DRAM and could be changed concurrently by Normal World.
  //
  InputBufferSize = *CommBufferSize;
  if (InputBufferSize < HeaderSize) {
    //
    // Too small to hold the response header (which carries Status), so the
    // result cannot be reported back. Quiesce.
    //
    ASSERT (FALSE);
    return EFI_SUCCESS;
  }

  if ((InputBufferSize - HeaderSize) > MAX_UINT32) {
    ASSERT (FALSE);
    return EFI_SUCCESS;
  }

  //
  // Ensure the entire comm buffer lies in Non-Secure memory and does not
  // overlap MMRAM before MM reads request fields from it or writes the
  // response payload back into it.
  //
  if (!MmCommBufferValid ((EFI_PHYSICAL_ADDRESS)(UINTN)CommBuffer, InputBufferSize)) {
    //
    // Comm buffer overlaps MMRAM or is otherwise invalid; not safe to touch, so
    // the result cannot be reported through Status. Quiesce.
    //
    DEBUG ((DEBUG_ERROR, "OneCryptoImageProviderMm: CommBuffer 0x%p size 0x%Lx failed MM validation\n", CommBuffer, (UINT64)InputBufferSize));
    ASSERT (FALSE);
    return EFI_SUCCESS;
  }

  //
  // From here the comm buffer is safe and large enough for the response header.
  // Operational results are reported through Msg->Status; the MMI handler always
  // returns EFI_SUCCESS (PI MM handlers may only return EFI_SUCCESS /
  // EFI_WARN_INTERRUPT_SOURCE_QUIESCED / EFI_WARN_INTERRUPT_SOURCE_PENDING /
  // EFI_INTERRUPT_PENDING).
  //
  Msg = (ONE_CRYPTO_IMAGE_PROVIDER_MSG *)CommBuffer;
  ZeroMem (&Msg->ImageGuid, sizeof (Msg->ImageGuid));
  Msg->TotalImageSize = 0;
  Msg->ReturnedSize   = 0;
  Msg->Status         = (UINT64)EFI_SUCCESS;

  //
  // Snapshot caller-supplied fields before validation/use: on AARCH64 CommBuffer
  // lives in Non-Secure DRAM and could be changed concurrently by Normal World,
  // so every field must be read exactly once into a local.
  //
  LocalSignature     = Msg->Signature;
  LocalVersion       = Msg->Version;
  LocalOffset        = Msg->Offset;
  LocalRequestedSize = Msg->RequestedSize;

  if ((LocalSignature != ONE_CRYPTO_IMAGE_PROVIDER_SIGNATURE) ||
      (LocalVersion != ONE_CRYPTO_IMAGE_PROVIDER_VERSION))
  {
    DEBUG ((DEBUG_ERROR, "OneCryptoImageProviderMm: Invalid request header\n"));
    Msg->Status     = (UINT64)EFI_INVALID_PARAMETER;
    *CommBufferSize = HeaderSize;
    return EFI_SUCCESS;
  }

  Status = LocateOneCryptoImage ();
  if (EFI_ERROR (Status)) {
    Msg->Status     = (UINT64)Status;
    *CommBufferSize = HeaderSize;
    return EFI_SUCCESS;
  }

  //
  // TotalImageSize is UINT32; guard against >4 GiB payloads.
  //
  if (mOneCryptoImageSize > MAX_UINT32) {
    DEBUG ((DEBUG_ERROR, "OneCryptoImageProviderMm: Image size 0x%Lx exceeds UINT32 max\n", (UINT64)mOneCryptoImageSize));
    Msg->Status     = (UINT64)EFI_UNSUPPORTED;
    *CommBufferSize = HeaderSize;
    return EFI_SUCCESS;
  }

  //
  // Compute the transport-integrity CRC32 once and cache it. The resident
  // image never changes, so a single pass suffices for every chunk request.
  //
  if (mOneCryptoImageCrc32 == 0) {
    mOneCryptoImageCrc32 = CalculateCrc32 (mOneCryptoImageData, mOneCryptoImageSize);
  }

  Msg->ImageGuid      = mOneCryptoBinaryGuid;
  Msg->TotalImageSize = (UINT32)mOneCryptoImageSize;
  Msg->Format         = mOneCryptoImageFormat;
  Msg->Crc32          = mOneCryptoImageCrc32;
  Msg->ReturnedSize   = 0;

  //
  // Size query: return total size + format, no payload.
  //
  if (LocalRequestedSize == 0) {
    Msg->Status     = (UINT64)EFI_SUCCESS;
    *CommBufferSize = HeaderSize;
    return EFI_SUCCESS;
  }

  if (LocalOffset > mOneCryptoImageSize) {
    DEBUG ((DEBUG_ERROR, "OneCryptoImageProviderMm: Invalid offset 0x%Lx for size 0x%Lx\n", LocalOffset, (UINT64)mOneCryptoImageSize));
    Msg->Status     = (UINT64)EFI_INVALID_PARAMETER;
    *CommBufferSize = HeaderSize;
    return EFI_SUCCESS;
  }

  MaxPayload = InputBufferSize - HeaderSize;
  Remaining  = mOneCryptoImageSize - (UINTN)LocalOffset;
  CopySize   = LocalRequestedSize;

  if (CopySize > MaxPayload) {
    CopySize = MaxPayload;
  }

  if (CopySize > Remaining) {
    CopySize = Remaining;
  }

  if (CopySize > 0) {
    CopyMem (Msg->Data, (CONST UINT8 *)mOneCryptoImageData + (UINTN)LocalOffset, CopySize);
  }

  Msg->ReturnedSize = (UINT32)CopySize;
  Msg->Status       = (UINT64)EFI_SUCCESS;
  *CommBufferSize   = HeaderSize + CopySize;

  return EFI_SUCCESS;
}

/**
  ReadyToLock notification callback.

  By the time MM ReadyToLock is signaled, the OneCrypto image has already been
  fetched and launched during DXE, so the image-provider MMI handler is no longer
  needed. Unregister it to remove its Non-Secure-reachable attack surface for the
  remainder of boot and runtime.

  This runs outside MMI handler dispatch, so unregistering here is safe (there is
  no self-unregister-during-dispatch hazard).

  @param[in]  Protocol   Installed protocol GUID (unused).
  @param[in]  Interface  Protocol interface (unused).
  @param[in]  Handle     Handle the protocol was installed on (unused).

  @retval EFI_SUCCESS  Always.
**/
STATIC
EFI_STATUS
EFIAPI
OneCryptoImageProviderReadyToLock (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  EFI_STATUS  Status;

  if (mDispatchHandle == NULL) {
    return EFI_SUCCESS;
  }

  Status          = gMmst->MmiHandlerUnRegister (mDispatchHandle);
  mDispatchHandle = NULL;
  DEBUG ((DEBUG_INFO, "OneCryptoImageProviderMm: Image-provider handler unregistered at ReadyToLock: %r\n", Status));

  return EFI_SUCCESS;
}

/**
  Module entry point. Registers the OneCrypto image-provider MM handler.

  @param[in]  ImageHandle    Image handle.
  @param[in]  MmSystemTable  MM system table.

  @retval EFI_SUCCESS  Handler registered.
**/
EFI_STATUS
EFIAPI
MmEntry (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *MmSystemTable
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  DispatchHandle;

  DispatchHandle = NULL;
  Status         = gMmst->MmiHandlerRegister (
                            OneCryptoImageProviderHandler,
                            &gOneCryptoImageProviderGuid,
                            &DispatchHandle
                            );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoImageProviderMm: Failed to register handler: %r\n", Status));
    return Status;
  }

  mDispatchHandle = DispatchHandle;
  DEBUG ((DEBUG_INFO, "OneCryptoImageProviderMm: Handler registered for %g\n", &gOneCryptoImageProviderGuid));

  //
  // The OneCrypto image is fetched and launched during DXE, so the provider is
  // only needed until then. Register a ReadyToLock notification to unregister the
  // handler afterward, removing its Non-Secure-reachable attack surface for the
  // rest of boot and runtime. A failure here is non-fatal: the handler still works,
  // it just will not self-tear-down.
  //
  Status = gMmst->MmRegisterProtocolNotify (
                    &gEfiMmReadyToLockProtocolGuid,
                    OneCryptoImageProviderReadyToLock,
                    &mReadyToLockRegistration
                    );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoImageProviderMm: Failed to register ReadyToLock notify: %r\n", Status));
  }

  return EFI_SUCCESS;
}
