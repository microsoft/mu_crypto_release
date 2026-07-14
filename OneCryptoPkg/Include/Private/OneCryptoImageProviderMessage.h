/** @file

  Shared message format for OneCrypto image-provider MM communication.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef ONE_CRYPTO_IMAGE_PROVIDER_MESSAGE_H_
#define ONE_CRYPTO_IMAGE_PROVIDER_MESSAGE_H_

#define ONE_CRYPTO_IMAGE_PROVIDER_VERSION    1U
#define ONE_CRYPTO_IMAGE_PROVIDER_SIGNATURE  SIGNATURE_32 ('O', 'C', 'I', 'P')

//
// Payload format served by the provider (ONE_CRYPTO_IMAGE_PROVIDER_MSG.Format).
//
// PE32      - Data is the raw OneCrypto PE32 image; DXE LoadImage()s it directly.
// GUIDED_FV - Data is the whole GUID_DEFINED section (header + compressed
//             payload) that wraps the nested FV containing the OneCrypto PE32.
//             Secure world (MM) may lack the memory budget to decompress the FV,
//             so it hands the small compressed section to the resource-rich
//             normal world (DXE), which decodes it via ExtractGuidedSectionLib
//             (LZMA is the only handler registered there today) and extracts
//             the OneCrypto PE32.
//
#define ONE_CRYPTO_IMAGE_FORMAT_PE32       0U
#define ONE_CRYPTO_IMAGE_FORMAT_GUIDED_FV  1U

//
// Chunked request/response for MM communication. One DXE->MM->DXE round trip
// either queries the image size (RequestedSize == 0) or fetches one chunk.
// Fields are IN (DXE writes, MM reads) or OUT (MM writes, DXE reads).
//
typedef struct {
  UINT32      Signature;         ///< IN:  ONE_CRYPTO_IMAGE_PROVIDER_SIGNATURE; identifies the message format.
  UINT32      Version;           ///< IN:  ONE_CRYPTO_IMAGE_PROVIDER_VERSION; rejected by MM if mismatched.
  UINT64      Offset;            ///< IN:  Byte offset into the image at which this chunk begins.
  UINT32      RequestedSize;     ///< IN:  Payload bytes wanted at Offset; 0 requests a size query only.
  UINT32      ReturnedSize;      ///< OUT: Valid bytes written to Data (the length of Data); <= RequestedSize.
  UINT32      TotalImageSize;    ///< OUT: Total image size, constant across chunks; not the size of Data.
  UINT32      Format;            ///< OUT: Encoding of Data (ONE_CRYPTO_IMAGE_FORMAT_*).
  UINT32      Crc32;             ///< OUT: CRC32 over the image for transport integrity (not authenticity); verified by DXE after reassembly.
  UINT32      Reserved;          ///< Reserved; keeps the header 8-byte aligned (must be 0).
  UINT64      Status;            ///< OUT: EFI_STATUS of the request (0 = success); DXE reads this, not the MMI return code.
  EFI_GUID    ImageGuid;         ///< OUT: GUID identifying the OneCrypto binary being served.
  UINT8       Data[];            ///< OUT: Payload bytes for this chunk; exactly ReturnedSize bytes are valid.
} ONE_CRYPTO_IMAGE_PROVIDER_MSG;

#endif // ONE_CRYPTO_IMAGE_PROVIDER_MESSAGE_H_
