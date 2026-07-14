/** @file
  OneCryptoLoaderDxeFromMm.c

  DXE loader that fetches OneCrypto image bytes from StandaloneMM via
  EFI_MM_COMMUNICATION2_PROTOCOL, then LoadImage()s the fetched PE32 image.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Guid/OneCryptoFileGuid.h>
#include <Guid/OneCryptoImageProviderGuid.h>

#include <Pi/PiFirmwareFile.h>
#include <Pi/PiFirmwareVolume.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/FvLib.h>
#include <Library/ExtractGuidedSectionLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PeCoffExtendedLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/PeCoffLib.h>
#include <Library/RngLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <Private/OneCryptoDependencySupport.h>
#include <Private/OneCryptoImageProviderMessage.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/MmCommunication.h>
#include <Protocol/MmCommunication2.h>
#include <Protocol/OneCrypto.h>
#include <Protocol/Rng.h>

//
// Target size for the MM communication buffer we allocate. The real MM
// communication region is a fixed, platform-defined size (e.g. PcdMmBufferSize
// on ARM); SendImageProviderRequest adapts down to it via the
// EFI_BAD_BUFFER_SIZE handshake, so this is only an upper bound on how big a
// chunk we attempt, not a per-platform requirement.
//
#define ONE_CRYPTO_COMM_BUFFER_TARGET_SIZE  0x30000

STATIC EFI_GUID  mOneCryptoBinaryGuid = ONE_CRYPTO_BINARY_GUID;

// The dependencies of the shared library, must live as long as the shared code is used.
STATIC ONE_CRYPTO_DEPENDENCIES  *mOneCryptoDepends = NULL;

// Crypto protocol for the shared library. Using VOID* to be agnostic about protocol structure size/layout.
STATIC VOID  *mOneCryptoProtocol = NULL;

// Lazy RNG state tracking.
STATIC EFI_RNG_PROTOCOL  *mCachedRngProtocol = NULL;

/**
  Lazy RNG implementation that locates EFI_RNG_PROTOCOL on first use.
**/
BOOLEAN
EFIAPI
LazyPlatformGetRandomNumber64 (
  OUT UINT64  *Rand
  )
{
  EFI_STATUS  Status;

  if (Rand == NULL) {
    DEBUG ((DEBUG_ERROR, "LazyPlatformGetRandomNumber64: Null Rand pointer\n"));
    return FALSE;
  }

  if (mCachedRngProtocol == NULL) {
    Status = gBS->LocateProtocol (&gEfiRngProtocolGuid, NULL, (VOID **)&mCachedRngProtocol);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, "LazyPlatformGetRandomNumber64: EFI_RNG_PROTOCOL not available: %r\n", Status));
      return FALSE;
    }
  }

  Status = mCachedRngProtocol->GetRNG (mCachedRngProtocol, NULL, sizeof (UINT64), (UINT8 *)Rand);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "LazyPlatformGetRandomNumber64: GetRNG failed: %r\n", Status));
    return FALSE;
  }

  return TRUE;
}

/**
  Installs shared dependencies required for the crypto entrypoint.
**/
STATIC
VOID
InstallSharedDependencies (
  OUT ONE_CRYPTO_DEPENDENCIES  *OneCryptoDepends
  )
{
  OneCryptoDepends->Major             = ONE_CRYPTO_DEPENDENCIES_VERSION_MAJOR;
  OneCryptoDepends->Minor             = ONE_CRYPTO_DEPENDENCIES_VERSION_MINOR;
  OneCryptoDepends->Reserved          = 0;
  OneCryptoDepends->AllocatePool      = AllocatePool;
  OneCryptoDepends->FreePool          = FreePool;
  OneCryptoDepends->DebugPrint        = DebugPrint;
  OneCryptoDepends->GetTime           = gRT->GetTime;
  OneCryptoDepends->GetRandomNumber64 = LazyPlatformGetRandomNumber64;
  OneCryptoDepends->MicroSecondDelay  = gBS->Stall;
}

/**
  Gets exported CryptoEntry from a loaded image.
**/
STATIC
EFI_STATUS
EFIAPI
GetEntryFromLoadedImage (
  IN EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage,
  OUT CRYPTO_ENTRY              *Entry
  )
{
  EFI_STATUS                  Status;
  UINT32                      Rva;
  INTERNAL_IMAGE_CONTEXT      Image;
  EFI_IMAGE_EXPORT_DIRECTORY  *Exports;

  if ((LoadedImage == NULL) || (Entry == NULL) || (LoadedImage->ImageBase == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&Image, sizeof (Image));
  Image.Context.ImageAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)LoadedImage->ImageBase;
  Image.Context.ImageSize    = (UINT64)LoadedImage->ImageSize;
  Image.Context.Handle       = LoadedImage->ImageBase;
  Image.Context.ImageRead    = PeCoffLoaderImageReadFromMemory;

  Status = PeCoffLoaderGetImageInfo (&Image.Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Image.Context.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER) {
    DEBUG ((DEBUG_ERROR, "Invalid image type: %d\n", Image.Context.ImageType));
    return EFI_UNSUPPORTED;
  }

  Status = GetExportDirectoryInPeCoffImage (&Image, &Exports);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = FindExportedFunction (&Image, Exports, EXPORTED_ENTRY_NAME, &Rva);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  *Entry = (CRYPTO_ENTRY)((EFI_PHYSICAL_ADDRESS)LoadedImage->ImageBase + Rva);
  return EFI_SUCCESS;
}

/**
  Sends one image-provider request to MM and adapts to the platform MM
  communication buffer size.

  The MM communication buffer is a fixed, platform-defined region whose size is
  not knowable a priori (on ARM it is PcdMmBufferSize). This routine therefore
  transmits only the bytes each request needs -- the MM communicate header, the
  provider message header, and RequestedSize payload bytes -- rather than the
  whole local allocation. If the transport reports EFI_BAD_BUFFER_SIZE it also
  returns its maximum region size, which this routine adopts: it clamps the
  requested payload to what the region can carry and retries, and writes the
  adopted size back through CommBufferAllocSize so the caller sizes subsequent
  chunk requests to the platform maximum.

  @param[in]      MmComm               MM communication protocol.
  @param[in, out] CommBuffer           Communication buffer (may be reallocated).
  @param[in, out] CommBufferAllocSize  Effective communication buffer size; on
                                       exit, clamped to the platform maximum if
                                       the transport reported one.
  @param[in]      Offset               Image offset being requested.
  @param[in]      RequestedSize        Payload bytes requested (0 = size query).
  @param[out]     Msg                  Located provider message within CommBuffer.
  @param[out]     MsgSize              Size of the returned message payload.

  @retval EFI_SUCCESS          Request completed.
  @retval EFI_BAD_BUFFER_SIZE  The platform MM buffer cannot carry even a
                               one-byte payload.
  @retval Others               Transport or protocol error.
**/
STATIC
EFI_STATUS
SendImageProviderRequest (
  IN EFI_MM_COMMUNICATION2_PROTOCOL  *MmComm,
  IN OUT VOID                        **CommBuffer,
  IN OUT UINTN                       *CommBufferAllocSize,
  IN UINT64                          Offset,
  IN UINT32                          RequestedSize,
  OUT ONE_CRYPTO_IMAGE_PROVIDER_MSG  **Msg,
  OUT UINTN                          *MsgSize
  )
{
  EFI_MM_COMMUNICATE_HEADER      *CommHeader;
  ONE_CRYPTO_IMAGE_PROVIDER_MSG  *LocalMsg;
  UINTN                          CommHeaderOverhead;
  UINTN                          MsgHeaderSize;
  UINTN                          MessageLength;
  UINTN                          CommSize;
  UINTN                          MaxPayload;
  UINT32                         ThisRequest;
  EFI_STATUS                     Status;

  CommHeaderOverhead = OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data);
  MsgHeaderSize      = OFFSET_OF (ONE_CRYPTO_IMAGE_PROVIDER_MSG, Data);
  ThisRequest        = RequestedSize;

  //
  // Issue the request, transmitting only the bytes it needs. On
  // EFI_BAD_BUFFER_SIZE the transport reports its fixed region size in CommSize
  // (see ArmPkg MmCommunicationDxe): adopt it, clamp the payload to fit, and
  // retry. Because every retry strictly reduces the request against a fixed
  // region, the loop converges.
  //
  while (TRUE) {
    MessageLength = MsgHeaderSize + ThisRequest;
    CommSize      = CommHeaderOverhead + MessageLength;

    //
    // Defensive: grow the local buffer if a request ever needs more than it
    // holds. The caller sizes requests from *CommBufferAllocSize, so the normal
    // shrink-to-fit path never trips this.
    //
    if (CommSize > *CommBufferAllocSize) {
      FreePool (*CommBuffer);
      *CommBuffer = AllocateZeroPool (CommSize);
      if (*CommBuffer == NULL) {
        *CommBufferAllocSize = 0;
        return EFI_OUT_OF_RESOURCES;
      }

      *CommBufferAllocSize = CommSize;
    }

    CommHeader = (EFI_MM_COMMUNICATE_HEADER *)(*CommBuffer);
    ZeroMem (CommHeader, CommSize);

    CopyGuid (&CommHeader->HeaderGuid, &gOneCryptoImageProviderGuid);
    CommHeader->MessageLength = MessageLength;

    LocalMsg                = (ONE_CRYPTO_IMAGE_PROVIDER_MSG *)CommHeader->Data;
    LocalMsg->Signature     = ONE_CRYPTO_IMAGE_PROVIDER_SIGNATURE;
    LocalMsg->Version       = ONE_CRYPTO_IMAGE_PROVIDER_VERSION;
    LocalMsg->Offset        = Offset;
    LocalMsg->RequestedSize = ThisRequest;

    Status = MmComm->Communicate (MmComm, *CommBuffer, *CommBuffer, &CommSize);
    DEBUG ((
      DEBUG_INFO,
      "OneCryptoLoaderDxeFromMm: MmComm->Communicate offset=0x%Lx req=0x%x status=%r commSize=0x%Lx\n",
      Offset,
      ThisRequest,
      Status,
      (UINT64)CommSize
      ));

    if (Status != EFI_BAD_BUFFER_SIZE) {
      break;
    }

    //
    // The transport rejected the size and returned its fixed region size in
    // CommSize. The region must hold at least the headers plus one payload byte
    // to make any progress.
    //
    if (CommSize <= (CommHeaderOverhead + MsgHeaderSize)) {
      DEBUG ((
        DEBUG_ERROR,
        "OneCryptoLoaderDxeFromMm: MM comm region too small max=0x%Lx needs>0x%Lx\n",
        (UINT64)CommSize,
        (UINT64)(CommHeaderOverhead + MsgHeaderSize)
        ));
      return EFI_BAD_BUFFER_SIZE;
    }

    MaxPayload           = CommSize - CommHeaderOverhead - MsgHeaderSize;
    *CommBufferAllocSize = CommSize;

    //
    // If clamping to the region does not actually reduce the request, the
    // rejection is not one we can adapt to -- fail rather than spin.
    //
    if (ThisRequest <= MaxPayload) {
      return EFI_BAD_BUFFER_SIZE;
    }

    ThisRequest = (UINT32)MaxPayload;
  }

  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (CommSize < (CommHeaderOverhead + MsgHeaderSize)) {
    DEBUG ((
      DEBUG_ERROR,
      "OneCryptoLoaderDxeFromMm: Response too small commSize=0x%Lx required>=0x%Lx\n",
      (UINT64)CommSize,
      (UINT64)(CommHeaderOverhead + MsgHeaderSize)
      ));
    return EFI_PROTOCOL_ERROR;
  }

  *Msg     = (ONE_CRYPTO_IMAGE_PROVIDER_MSG *)((EFI_MM_COMMUNICATE_HEADER *)(*CommBuffer))->Data;
  *MsgSize = CommSize - CommHeaderOverhead;
  return EFI_SUCCESS;
}

/**
  Decodes the compressed GUID_DEFINED section handed over by the MM provider,
  locates the OneCrypto file within the decompressed nested FV, and returns a
  standalone copy of its PE32 image bytes.

  @param[in]  GuidedSection      The GUID_DEFINED section (header included).
  @param[in]  GuidedSectionSize  Size of the GUID_DEFINED section.
  @param[out] Pe32Data           Newly allocated buffer holding the OneCrypto PE32.
  @param[out] Pe32Size           Size of the returned PE32 image.

  @retval EFI_SUCCESS  PE32 image extracted and returned in Pe32Data.
**/
STATIC
EFI_STATUS
ExtractOneCryptoPe32FromGuidedFv (
  IN  VOID   *GuidedSection,
  IN  UINTN  GuidedSectionSize,
  OUT VOID   **Pe32Data,
  OUT UINTN  *Pe32Size
  )
{
  EFI_STATUS                  Status;
  UINT32                      DecodedSize;
  UINT32                      ScratchSize;
  UINT16                      SectionAttribute;
  UINT32                      AuthenticationStatus;
  VOID                        *Decoded;
  VOID                        *Scratch;
  EFI_FIRMWARE_VOLUME_HEADER  *FvHeader;
  EFI_COMMON_SECTION_HEADER   *FvSection;
  EFI_FFS_FILE_HEADER         *FileHeader;
  VOID                        *SectionData;
  UINTN                       SectionDataSize;
  VOID                        *Pe32Copy;

  *Pe32Data = NULL;
  *Pe32Size = 0;
  Decoded   = NULL;
  Scratch   = NULL;

  //
  // Need at least a GUID_DEFINED section header before the handler can inspect it.
  //
  if ((GuidedSection == NULL) || (GuidedSectionSize < sizeof (EFI_GUID_DEFINED_SECTION))) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Query the registered guided-section handler for the decode + scratch buffer
  // sizes.
  //
  Status = ExtractGuidedSectionGetInfo (GuidedSection, &DecodedSize, &ScratchSize, &SectionAttribute);
  if (EFI_ERROR (Status) || (DecodedSize == 0)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: ExtractGuidedSectionGetInfo failed: %r size=0x%x\n", Status, DecodedSize));
    return EFI_COMPROMISED_DATA;
  }

  Decoded = AllocatePool (DecodedSize);
  if (Decoded == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Cleanup;
  }

  if (ScratchSize != 0) {
    Scratch = AllocatePool (ScratchSize);
    if (Scratch == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Cleanup;
    }
  }

  //
  // Decode via the registered guided-section handler. The section is
  // PROCESSING_REQUIRED, so the handler expands it into our allocated buffer;
  // Decoded then holds the decompressed nested FV.
  //
  Status = ExtractGuidedSectionDecode (GuidedSection, &Decoded, Scratch, &AuthenticationStatus);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: ExtractGuidedSectionDecode failed: %r\n", Status));
    Status = EFI_COMPROMISED_DATA;
    goto Cleanup;
  }

  //
  // The decoded payload must be at least an FV header before we inspect it, or
  // the Signature read below would run off the end of the decoded buffer.
  //
  if (DecodedSize < sizeof (EFI_FIRMWARE_VOLUME_HEADER)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: Decoded payload too small for FV header size=0x%x\n", DecodedSize));
    Status = EFI_VOLUME_CORRUPTED;
    goto Cleanup;
  }

  //
  // The decoded payload is the nested FV -- either the raw FV image, or a
  // FIRMWARE_VOLUME_IMAGE section wrapping it. Resolve to the FV header.
  //
  if (((EFI_FIRMWARE_VOLUME_HEADER *)Decoded)->Signature == EFI_FVH_SIGNATURE) {
    FvHeader = (EFI_FIRMWARE_VOLUME_HEADER *)Decoded;
  } else {
    FvSection = NULL;
    Status    = FindFfsSectionInSections (
                  Decoded,
                  DecodedSize,
                  EFI_SECTION_FIRMWARE_VOLUME_IMAGE,
                  &FvSection
                  );
    if (EFI_ERROR (Status) || (FvSection == NULL)) {
      DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: Decoded payload is not an FV: %r\n", Status));
      Status = EFI_VOLUME_CORRUPTED;
      goto Cleanup;
    }

    if (IS_SECTION2 (FvSection)) {
      FvHeader = (EFI_FIRMWARE_VOLUME_HEADER *)((EFI_COMMON_SECTION_HEADER2 *)FvSection + 1);
    } else {
      FvHeader = (EFI_FIRMWARE_VOLUME_HEADER *)(FvSection + 1);
    }
  }

  //
  // Bound the resolved FV against the decoded buffer before walking its files:
  // FvHeader must sit inside Decoded with room for a full header, and the FV's
  // self-described FvLength must not run past the end of the decoded payload.
  // This stops a malformed nested FV from walking the FFS parser out of bounds.
  //
  if (((UINT8 *)FvHeader < (UINT8 *)Decoded) ||
      ((UINTN)((UINT8 *)FvHeader - (UINT8 *)Decoded) > DecodedSize) ||
      ((DecodedSize - (UINTN)((UINT8 *)FvHeader - (UINT8 *)Decoded)) < sizeof (EFI_FIRMWARE_VOLUME_HEADER)) ||
      (FvHeader->Signature != EFI_FVH_SIGNATURE) ||
      (FvHeader->FvLength > (DecodedSize - (UINTN)((UINT8 *)FvHeader - (UINT8 *)Decoded))))
  {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: Decoded FV out of bounds of payload\n"));
    Status = EFI_VOLUME_CORRUPTED;
    goto Cleanup;
  }

  //
  // Find the OneCrypto file and its PE32 section within the decoded FV.
  //
  FileHeader = NULL;
  Status     = EFI_NOT_FOUND;
  while (TRUE) {
    if (EFI_ERROR (FfsFindNextFile (EFI_FV_FILETYPE_ALL, FvHeader, &FileHeader))) {
      break;
    }

    if (!CompareGuid (&FileHeader->Name, &mOneCryptoBinaryGuid)) {
      continue;
    }

    if (!EFI_ERROR (FfsFindSectionData (EFI_SECTION_PE32, FileHeader, &SectionData, &SectionDataSize)) &&
        (SectionData != NULL) && (SectionDataSize != 0))
    {
      Pe32Copy = AllocateCopyPool (SectionDataSize, SectionData);
      if (Pe32Copy == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto Cleanup;
      }

      *Pe32Data = Pe32Copy;
      *Pe32Size = SectionDataSize;
      Status    = EFI_SUCCESS;
      DEBUG ((
        DEBUG_INFO,
        "OneCryptoLoaderDxeFromMm: Extracted OneCrypto PE32 from decoded FV size=0x%Lx\n",
        (UINT64)SectionDataSize
        ));
      goto Cleanup;
    }
  }

  DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: OneCrypto PE32 not found in decoded FV\n"));

Cleanup:
  if (Decoded != NULL) {
    FreePool (Decoded);
  }

  if (Scratch != NULL) {
    FreePool (Scratch);
  }

  return Status;
}

/**
  Fetches complete OneCrypto PE32 image from MM provider using chunked requests.
**/
STATIC
EFI_STATUS
FetchImageFromMm (
  OUT VOID    **ImageData,
  OUT UINTN   *ImageSize,
  OUT UINT32  *Format
  )
{
  EFI_MM_COMMUNICATION2_PROTOCOL  *MmComm;
  EFI_STATUS                      Status;
  VOID                            *CommBuffer;
  UINTN                           CommBufferAllocSize;
  ONE_CRYPTO_IMAGE_PROVIDER_MSG   *Msg;
  UINTN                           MsgSize;
  VOID                            *LocalImage;
  UINTN                           HeaderSize;
  UINTN                           ChunkCapacity;
  UINTN                           Offset;
  UINTN                           Remaining;
  UINTN                           ThisChunk;
  UINT32                          ExpectedTotal;
  UINT32                          ExpectedCrc;
  UINT32                          ChunkReturnedSize;
  EFI_STATUS                      ChunkStatus;

  *ImageData = NULL;
  *ImageSize = 0;
  *Format    = ONE_CRYPTO_IMAGE_FORMAT_PE32;

  Status = gBS->LocateProtocol (&gEfiMmCommunication2ProtocolGuid, NULL, (VOID **)&MmComm);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: gEfiMmCommunication2ProtocolGuid not found: %r\n", Status));
    return Status;
  }

  //
  // Target comm-buffer size; the transport adapts down to the platform's fixed
  // MM region via SendImageProviderRequest (see ONE_CRYPTO_COMM_BUFFER_TARGET_SIZE).
  //
  CommBufferAllocSize = ONE_CRYPTO_COMM_BUFFER_TARGET_SIZE;
  CommBuffer          = AllocateZeroPool (CommBufferAllocSize);
  if (CommBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  HeaderSize = OFFSET_OF (ONE_CRYPTO_IMAGE_PROVIDER_MSG, Data);

  // Size query.
  Status = SendImageProviderRequest (
             MmComm,
             &CommBuffer,
             &CommBufferAllocSize,
             0,
             0,
             &Msg,
             &MsgSize
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: Size query request failed: %r\n", Status));
    goto Exit;
  }

  //
  // The MMI handler always returns EFI_SUCCESS at the transport level; the
  // operational result is carried in Msg->Status.
  //
  Status = (EFI_STATUS)(UINTN)Msg->Status;
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: Size-query provider status: %r\n", Status));
    goto Exit;
  }

  if ((Msg->TotalImageSize == 0) || (Msg->ReturnedSize != 0)) {
    DEBUG ((
      DEBUG_ERROR,
      "OneCryptoLoaderDxeFromMm: Invalid size-query response total=0x%x returned=0x%x msgSize=0x%Lx\n",
      Msg->TotalImageSize,
      Msg->ReturnedSize,
      (UINT64)MsgSize
      ));
    Status = EFI_PROTOCOL_ERROR;
    goto Exit;
  }

  // Validate ImageGuid in size-query response for consistency with chunk validation.
  if (!CompareGuid (&Msg->ImageGuid, &mOneCryptoBinaryGuid)) {
    DEBUG ((
      DEBUG_ERROR,
      "OneCryptoLoaderDxeFromMm: ImageGuid mismatch in size-query response\n"
      ));
    Status = EFI_COMPROMISED_DATA;
    goto Exit;
  }

  // Snapshot TotalImageSize from the size-query response into a local variable.
  // All subsequent loop logic and the final *ImageSize use this value exclusively
  // to detect mid-transfer tampering and prevent heap-overflow via inflated totals.
  ExpectedTotal = Msg->TotalImageSize;
  *Format       = Msg->Format;

  // Snapshot the transport-integrity CRC32 from the size-query response.
  ExpectedCrc = Msg->Crc32;

  LocalImage = AllocatePool (ExpectedTotal);
  if (LocalImage == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  ChunkCapacity = CommBufferAllocSize - OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data) - HeaderSize;
  if (ChunkCapacity == 0) {
    Status = EFI_BAD_BUFFER_SIZE;
    FreePool (LocalImage);
    goto Exit;
  }

  Offset = 0;
  while (Offset < ExpectedTotal) {
    Remaining = ExpectedTotal - Offset;
    ThisChunk = (Remaining < ChunkCapacity) ? Remaining : ChunkCapacity;

    Status = SendImageProviderRequest (
               MmComm,
               &CommBuffer,
               &CommBufferAllocSize,
               Offset,
               (UINT32)ThisChunk,
               &Msg,
               &MsgSize
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        "OneCryptoLoaderDxeFromMm: Chunk request failed offset=0x%Lx req=0x%Lx status=%r\n",
        (UINT64)Offset,
        (UINT64)ThisChunk,
        Status
        ));
      FreePool (LocalImage);
      goto Exit;
    }

    ChunkCapacity = CommBufferAllocSize - OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data) - HeaderSize;
    if (ChunkCapacity == 0) {
      Status = EFI_BAD_BUFFER_SIZE;
      FreePool (LocalImage);
      goto Exit;
    }

    //
    // Snapshot response fields out of the shared comm buffer before validating
    // or using them: Msg points into memory the provider (and, on AARCH64, any
    // other Non-Secure agent) can mutate concurrently, so each field must be
    // read exactly once to avoid a TOCTOU between the bounds check and the copy.
    //
    ChunkReturnedSize = Msg->ReturnedSize;
    ChunkStatus       = (EFI_STATUS)(UINTN)Msg->Status;

    if (EFI_ERROR (ChunkStatus)) {
      DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: Chunk provider status offset=0x%Lx: %r\n", (UINT64)Offset, ChunkStatus));
      Status = ChunkStatus;
      FreePool (LocalImage);
      goto Exit;
    }

    if ((ChunkReturnedSize == 0) || (ChunkReturnedSize > ThisChunk)) {
      DEBUG ((
        DEBUG_ERROR,
        "OneCryptoLoaderDxeFromMm: Invalid chunk response offset=0x%Lx requested=0x%Lx returned=0x%x msgSize=0x%Lx\n",
        (UINT64)Offset,
        (UINT64)ThisChunk,
        ChunkReturnedSize,
        (UINT64)MsgSize
        ));
      Status = EFI_PROTOCOL_ERROR;
      FreePool (LocalImage);
      goto Exit;
    }

    //
    // Defensive destination bound: LocalImage is exactly ExpectedTotal bytes.
    // Guard the heap write independently of the per-chunk sizing above so a
    // provider (or a future refactor) can never overflow the reassembly buffer.
    //
    if ((Offset + ChunkReturnedSize) > ExpectedTotal) {
      DEBUG ((
        DEBUG_ERROR,
        "OneCryptoLoaderDxeFromMm: Chunk overflows image offset=0x%Lx returned=0x%x total=0x%x\n",
        (UINT64)Offset,
        ChunkReturnedSize,
        ExpectedTotal
        ));
      Status = EFI_PROTOCOL_ERROR;
      FreePool (LocalImage);
      goto Exit;
    }

    CopyMem ((UINT8 *)LocalImage + Offset, Msg->Data, ChunkReturnedSize);
    Offset += ChunkReturnedSize;
  }

  //
  // Transport-integrity check: recompute CRC32 over the reassembled image and
  // compare against the provider's value. This catches accidental corruption or
  // truncation of the chunked MM transfer during bring-up. It is NOT an
  // authenticity check.
  //
  {
    UINT32  ComputedCrc;

    ComputedCrc = CalculateCrc32 (LocalImage, ExpectedTotal);
    if (ComputedCrc != ExpectedCrc) {
      DEBUG ((
        DEBUG_ERROR,
        "OneCryptoLoaderDxeFromMm: CRC32 mismatch computed=0x%x expected=0x%x size=0x%x -- transport corruption\n",
        ComputedCrc,
        ExpectedCrc,
        ExpectedTotal
        ));
      Status = EFI_CRC_ERROR;
      FreePool (LocalImage);
      goto Exit;
    }
  }

  *ImageData = LocalImage;
  *ImageSize = ExpectedTotal;
  Status     = EFI_SUCCESS;

Exit:
  if (CommBuffer != NULL) {
    FreePool (CommBuffer);
  }

  return Status;
}

/**
  DXE entry point.
**/
EFI_STATUS
EFIAPI
DxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                 Status;
  VOID                       *SectionData;
  UINTN                      SectionSize;
  CRYPTO_ENTRY               Entry;
  EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage;
  EFI_HANDLE                 LoadedImageHandle;
  UINT32                     CryptoSize;
  UINT32                     ImageFormat;
  VOID                       *Pe32Data;
  UINTN                      Pe32Size;

  LoadedImageHandle = NULL;
  LoadedImage       = NULL;
  SectionData       = NULL;
  SectionSize       = 0;
  CryptoSize        = 0;
  ImageFormat       = ONE_CRYPTO_IMAGE_FORMAT_PE32;

  if (mOneCryptoDepends == NULL) {
    mOneCryptoDepends = AllocatePool (sizeof (*mOneCryptoDepends));
    if (mOneCryptoDepends == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    InstallSharedDependencies (mOneCryptoDepends);
  }

  Status = FetchImageFromMm (&SectionData, &SectionSize, &ImageFormat);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: FetchImageFromMm failed: %r\n", Status));
    return Status;
  }

  //
  // When the secure-world provider cannot afford to decode the nested FV, it
  // hands over the compressed guided section instead. Decode it here (normal
  // world has ample memory) and extract the OneCrypto PE32 to load.
  //
  if (ImageFormat == ONE_CRYPTO_IMAGE_FORMAT_GUIDED_FV) {
    Status = ExtractOneCryptoPe32FromGuidedFv (SectionData, SectionSize, &Pe32Data, &Pe32Size);
    FreePool (SectionData);
    SectionData = NULL;
    SectionSize = 0;
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: ExtractOneCryptoPe32FromGuidedFv failed: %r\n", Status));
      return Status;
    }

    SectionData = Pe32Data;
    SectionSize = Pe32Size;
  }

  Status = SystemTable->BootServices->LoadImage (
                                        FALSE,
                                        ImageHandle,
                                        NULL,
                                        SectionData,
                                        SectionSize,
                                        &LoadedImageHandle
                                        );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: LoadImage failed: %r\n", Status));
    goto Exit;
  }

  Status = SystemTable->BootServices->HandleProtocol (
                                        LoadedImageHandle,
                                        &gEfiLoadedImageProtocolGuid,
                                        (VOID **)&LoadedImage
                                        );
  if (EFI_ERROR (Status) || (LoadedImage == NULL)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: HandleProtocol(LoadedImage) failed: %r\n", Status));
    goto Exit;
  }

  Status = GetEntryFromLoadedImage (LoadedImage, &Entry);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: GetEntryFromLoadedImage failed: %r\n", Status));
    goto Exit;
  }

  Status = Entry (mOneCryptoDepends, NULL, &CryptoSize);
  if ((Status != EFI_BUFFER_TOO_SMALL) || (CryptoSize == 0)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: Failed to query crypto protocol size: %r\n", Status));
    goto Exit;
  }

  mOneCryptoProtocol = AllocatePool (CryptoSize);
  if (mOneCryptoProtocol == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  Status = Entry (mOneCryptoDepends, &mOneCryptoProtocol, &CryptoSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: Crypto entry failed: %r\n", Status));
    FreePool (mOneCryptoProtocol);
    mOneCryptoProtocol = NULL;
    goto Exit;
  }

  Status = SystemTable->BootServices->InstallMultipleProtocolInterfaces (
                                        &ImageHandle,
                                        &gOneCryptoProtocolGuid,
                                        mOneCryptoProtocol,
                                        NULL
                                        );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "OneCryptoLoaderDxeFromMm: InstallProtocol failed: %r\n", Status));
    goto Exit;
  }

  Status = EFI_SUCCESS;

Exit:
  //
  // On any failure after LoadImage, unload the image and release the crypto
  // protocol buffer so an error path does not leak the loaded image pages or
  // the (allocated but not-yet-installed) protocol.
  //
  if (EFI_ERROR (Status)) {
    if (mOneCryptoProtocol != NULL) {
      FreePool (mOneCryptoProtocol);
      mOneCryptoProtocol = NULL;
    }

    if (LoadedImageHandle != NULL) {
      SystemTable->BootServices->UnloadImage (LoadedImageHandle);
    }
  }

  if (SectionData != NULL) {
    FreePool (SectionData);
  }

  if ((Status != EFI_SUCCESS) && (mOneCryptoDepends != NULL)) {
    FreePool (mOneCryptoDepends);
    mOneCryptoDepends = NULL;
  }

  return Status;
}
