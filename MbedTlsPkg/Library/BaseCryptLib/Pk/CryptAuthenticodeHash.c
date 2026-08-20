/** @file
  PE/COFF Authenticode Image Hash computation.

  Implements GetAuthenticodeHash() per the "Windows Authenticode Portable
  Executable Signature Format" specification. The hash covers the entire
  PE/COFF image except for the image checksum, the Certificate Table
  data-directory entry, and the certificate table content itself.

  Caution: This module operates on untrusted input (the PE/COFF image),
  so each header field is validated against FileSize before use.

Copyright (C) Microsoft Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"

#include <IndustryStandard/PeImage.h>
#include <Guid/ImageAuthentication.h>

//
// Function pointer table type for a single hash algorithm.
// We use the BaseCryptLib hash primitives so this implementation is
// independent of the underlying crypto provider (OpenSSL / Mbed TLS).
//
typedef
UINTN
(EFIAPI *AUTH_HASH_GET_CONTEXT_SIZE)(
  VOID
  );

typedef
BOOLEAN
(EFIAPI *AUTH_HASH_INIT)(
  OUT  VOID  *HashContext
  );

typedef
BOOLEAN
(EFIAPI *AUTH_HASH_UPDATE)(
  IN OUT  VOID        *HashContext,
  IN      CONST VOID  *Data,
  IN      UINTN       DataSize
  );

typedef
BOOLEAN
(EFIAPI *AUTH_HASH_FINAL)(
  IN OUT  VOID   *HashContext,
  OUT     UINT8  *HashValue
  );

typedef struct {
  CONST EFI_GUID                *HashGuid;
  UINTN                         DigestSize;
  AUTH_HASH_GET_CONTEXT_SIZE    GetContextSize;
  AUTH_HASH_INIT                Init;
  AUTH_HASH_UPDATE              Update;
  AUTH_HASH_FINAL               Final;
} AUTH_HASH_INFO;

//
// Forward references to BaseCryptLib hash primitives. These are provided
// by the BaseCryptLib hash sources in this same library instance.
//
STATIC CONST AUTH_HASH_INFO  mAuthHashInfo[] = {
  { &gEfiCertSha1Guid,   SHA1_DIGEST_SIZE,   Sha1GetContextSize,   Sha1Init,   Sha1Update,   Sha1Final   },
  { &gEfiCertSha256Guid, SHA256_DIGEST_SIZE, Sha256GetContextSize, Sha256Init, Sha256Update, Sha256Final },
  { &gEfiCertSha384Guid, SHA384_DIGEST_SIZE, Sha384GetContextSize, Sha384Init, Sha384Update, Sha384Final },
  { &gEfiCertSha512Guid, SHA512_DIGEST_SIZE, Sha512GetContextSize, Sha512Init, Sha512Update, Sha512Final },
};

#define AUTH_HASH_INFO_COUNT  (sizeof (mAuthHashInfo) / sizeof (mAuthHashInfo[0]))

/**
  Look up an entry in mAuthHashInfo by HashType GUID.

  @param[in] HashType  Signature-type GUID identifying the hash algorithm.

  @retval Pointer to the AUTH_HASH_INFO on match.
  @retval NULL if HashType does not match a supported algorithm.
**/
STATIC
CONST AUTH_HASH_INFO *
LookupAuthHashInfo (
  IN  CONST EFI_GUID  *HashType
  )
{
  UINTN  Index;

  for (Index = 0; Index < AUTH_HASH_INFO_COUNT; Index++) {
    if (CompareGuid (HashType, mAuthHashInfo[Index].HashGuid)) {
      return &mAuthHashInfo[Index];
    }
  }

  return NULL;
}

/**
  Compute the PE/COFF Authenticode-style image hash of a loaded image,
  as described in the "Windows Authenticode Portable Executable
  Signature Format" specification.

  The caller selects the digest algorithm by HashType (e.g.
  gEfiCertSha256Guid, gEfiCertSha384Guid). The digest is written to
  Digest, which must be large enough to hold the largest supported
  digest (at least SHA512_DIGEST_SIZE bytes).

  Caution: This function may receive untrusted input. The PE/COFF image
  is external input, so this function validates the image's data
  structure before hashing.

  @param[in]   FileBuffer  Pointer to the in-memory PE/COFF image.
  @param[in]   FileSize    Size of FileBuffer in bytes.
  @param[in]   HashType    Signature-type GUID identifying the hash
                           algorithm to use.
  @param[out]  Digest      Caller-provided buffer that receives the
                           computed digest. Must be at least
                           SHA512_DIGEST_SIZE bytes.
  @param[out]  DigestSize  On success, receives the digest length in
                           bytes.

  @retval EFI_SUCCESS            Digest was computed successfully.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL or
                                 FileSize is 0.
  @retval EFI_UNSUPPORTED        HashType is not a recognized image
                                 hash algorithm, or this interface is
                                 not supported by the underlying
                                 library instance.
**/
EFI_STATUS
EFIAPI
GetAuthenticodeHash (
  IN  VOID            *FileBuffer,
  IN  UINTN           FileSize,
  IN  CONST EFI_GUID  *HashType,
  OUT UINT8           *Digest,
  OUT UINTN           *DigestSize
  )
{
  EFI_STATUS                       Status;
  CONST AUTH_HASH_INFO             *HashInfo;
  UINT8                            *ImageBase;
  UINTN                            PeCoffHeaderOffset;
  EFI_IMAGE_DOS_HEADER             *DosHdr;
  EFI_IMAGE_OPTIONAL_HEADER_UNION  *NtHdr;
  UINT16                           Magic;
  UINT32                           NumberOfRvaAndSizes;
  UINT32                           SizeOfHeaders;
  UINT16                           NumberOfSections;
  UINT16                           SizeOfOptionalHeader;
  UINT8                            *CheckSumPtr;
  UINT8                            *SecDirPtr;
  EFI_IMAGE_DATA_DIRECTORY         *SecDir;
  UINT32                           CertSize;
  VOID                             *HashCtx;
  UINTN                            CtxSize;
  UINT8                            *HashBase;
  UINTN                            HashSize;
  UINTN                            SumOfBytesHashed;
  EFI_IMAGE_SECTION_HEADER         *SectionHeaders;
  EFI_IMAGE_SECTION_HEADER         *Section;
  UINTN                            SectionHeadersSize;
  UINTN                            FirstSectionOffset;
  UINTN                            Index;
  UINTN                            Pos;

  HashCtx        = NULL;
  SectionHeaders = NULL;
  Status         = EFI_INVALID_PARAMETER;

  if ((FileBuffer == NULL) || (FileSize == 0) || (HashType == NULL) ||
      (Digest == NULL) || (DigestSize == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  HashInfo = LookupAuthHashInfo (HashType);
  if (HashInfo == NULL) {
    return EFI_UNSUPPORTED;
  }

  ImageBase = (UINT8 *)FileBuffer;

  //
  // Locate the PE header.
  //
  if (FileSize < sizeof (EFI_IMAGE_DOS_HEADER)) {
    return EFI_INVALID_PARAMETER;
  }

  DosHdr = (EFI_IMAGE_DOS_HEADER *)ImageBase;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    PeCoffHeaderOffset = DosHdr->e_lfanew;
  } else {
    PeCoffHeaderOffset = 0;
  }

  if ((PeCoffHeaderOffset > FileSize) ||
      ((FileSize - PeCoffHeaderOffset) < sizeof (UINT32) + sizeof (EFI_IMAGE_FILE_HEADER) + sizeof (UINT16)))
  {
    return EFI_INVALID_PARAMETER;
  }

  NtHdr = (EFI_IMAGE_OPTIONAL_HEADER_UNION *)(ImageBase + PeCoffHeaderOffset);
  if (NtHdr->Pe32.Signature != EFI_IMAGE_NT_SIGNATURE) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // FileHeader is at the same offset for PE32 and PE32+.
  //
  SizeOfOptionalHeader = NtHdr->Pe32.FileHeader.SizeOfOptionalHeader;
  NumberOfSections     = NtHdr->Pe32.FileHeader.NumberOfSections;

  //
  // Make sure the optional header fits.
  //
  if ((FileSize - PeCoffHeaderOffset) <
      sizeof (UINT32) + sizeof (EFI_IMAGE_FILE_HEADER) + (UINTN)SizeOfOptionalHeader)
  {
    return EFI_INVALID_PARAMETER;
  }

  Magic = NtHdr->Pe32.OptionalHeader.Magic;

  if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    if (SizeOfOptionalHeader < sizeof (EFI_IMAGE_OPTIONAL_HEADER32)) {
      return EFI_INVALID_PARAMETER;
    }

    CheckSumPtr         = (UINT8 *)&NtHdr->Pe32.OptionalHeader.CheckSum;
    NumberOfRvaAndSizes = NtHdr->Pe32.OptionalHeader.NumberOfRvaAndSizes;
    SizeOfHeaders       = NtHdr->Pe32.OptionalHeader.SizeOfHeaders;
  } else if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    if (SizeOfOptionalHeader < sizeof (EFI_IMAGE_OPTIONAL_HEADER64)) {
      return EFI_INVALID_PARAMETER;
    }

    CheckSumPtr         = (UINT8 *)&NtHdr->Pe32Plus.OptionalHeader.CheckSum;
    NumberOfRvaAndSizes = NtHdr->Pe32Plus.OptionalHeader.NumberOfRvaAndSizes;
    SizeOfHeaders       = NtHdr->Pe32Plus.OptionalHeader.SizeOfHeaders;
  } else {
    return EFI_UNSUPPORTED;
  }

  //
  // SizeOfHeaders must be within FileSize.
  //
  if ((SizeOfHeaders > FileSize) ||
      (SizeOfHeaders < (PeCoffHeaderOffset + sizeof (UINT32) + sizeof (EFI_IMAGE_FILE_HEADER) + (UINTN)SizeOfOptionalHeader)))
  {
    return EFI_INVALID_PARAMETER;
  }

  //
  // The section headers must lie within the headers region.
  //
  FirstSectionOffset = PeCoffHeaderOffset + sizeof (UINT32) +
                       sizeof (EFI_IMAGE_FILE_HEADER) + (UINTN)SizeOfOptionalHeader;
  SectionHeadersSize = (UINTN)NumberOfSections * sizeof (EFI_IMAGE_SECTION_HEADER);
  if ((SectionHeadersSize / sizeof (EFI_IMAGE_SECTION_HEADER)) != (UINTN)NumberOfSections) {
    return EFI_INVALID_PARAMETER;
  }

  if ((FirstSectionOffset > FileSize) ||
      ((FileSize - FirstSectionOffset) < SectionHeadersSize) ||
      ((FirstSectionOffset + SectionHeadersSize) > SizeOfHeaders))
  {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Allocate and initialize the hash context.
  //
  CtxSize = HashInfo->GetContextSize ();
  HashCtx = AllocatePool (CtxSize);
  if (HashCtx == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  if (!HashInfo->Init (HashCtx)) {
    Status = EFI_DEVICE_ERROR;
    goto Done;
  }

  //
  // Step 1-4: Hash the image header from its base to the start of the
  // CheckSum field.
  //
  HashBase = ImageBase;
  HashSize = (UINTN)(CheckSumPtr - ImageBase);
  if (!HashInfo->Update (HashCtx, HashBase, HashSize)) {
    Status = EFI_DEVICE_ERROR;
    goto Done;
  }

  //
  // Step 5: Skip over the image checksum (4 bytes).
  // Step 6/7: Hash everything from the end of the checksum to either the
  // end of the optional header or the start of the Cert Directory entry.
  //
  if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
    HashBase = CheckSumPtr + sizeof (UINT32);
    HashSize = SizeOfHeaders - (UINTN)(HashBase - ImageBase);
    SecDir   = NULL;
  } else {
    if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      SecDirPtr = (UINT8 *)&NtHdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
      SecDir    = &NtHdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
    } else {
      SecDirPtr = (UINT8 *)&NtHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
      SecDir    = &NtHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
    }

    HashBase = CheckSumPtr + sizeof (UINT32);
    HashSize = (UINTN)(SecDirPtr - HashBase);
  }

  if (HashSize != 0) {
    if (!HashInfo->Update (HashCtx, HashBase, HashSize)) {
      Status = EFI_DEVICE_ERROR;
      goto Done;
    }
  }

  //
  // Step 8/9: Skip the Cert Directory entry. Hash from end of cert dir
  // entry to end of image header.
  //
  if (SecDir != NULL) {
    HashBase = SecDirPtr + sizeof (EFI_IMAGE_DATA_DIRECTORY);
    HashSize = SizeOfHeaders - (UINTN)(HashBase - ImageBase);
    if (HashSize != 0) {
      if (!HashInfo->Update (HashCtx, HashBase, HashSize)) {
        Status = EFI_DEVICE_ERROR;
        goto Done;
      }
    }
  }

  //
  // Step 10: SUM_OF_BYTES_HASHED = SizeOfHeaders.
  //
  SumOfBytesHashed = SizeOfHeaders;

  //
  // Step 11-12: Build a sorted table of section headers.
  //
  if (NumberOfSections != 0) {
    SectionHeaders = AllocateZeroPool (SectionHeadersSize);
    if (SectionHeaders == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    Section = (EFI_IMAGE_SECTION_HEADER *)(ImageBase + FirstSectionOffset);

    //
    // Insertion sort by PointerToRawData.
    //
    for (Index = 0; Index < (UINTN)NumberOfSections; Index++) {
      Pos = Index;
      while ((Pos > 0) && (Section->PointerToRawData < SectionHeaders[Pos - 1].PointerToRawData)) {
        CopyMem (&SectionHeaders[Pos], &SectionHeaders[Pos - 1], sizeof (EFI_IMAGE_SECTION_HEADER));
        Pos--;
      }

      CopyMem (&SectionHeaders[Pos], Section, sizeof (EFI_IMAGE_SECTION_HEADER));
      Section++;
    }

    //
    // Step 13-15: Hash each section in order.
    //
    for (Index = 0; Index < (UINTN)NumberOfSections; Index++) {
      Section = &SectionHeaders[Index];
      if (Section->SizeOfRawData == 0) {
        continue;
      }

      //
      // Validate the section bounds against the file size.
      //
      if ((Section->PointerToRawData > FileSize) ||
          ((FileSize - Section->PointerToRawData) < (UINTN)Section->SizeOfRawData))
      {
        Status = EFI_INVALID_PARAMETER;
        goto Done;
      }

      HashBase = ImageBase + Section->PointerToRawData;
      HashSize = (UINTN)Section->SizeOfRawData;
      if (!HashInfo->Update (HashCtx, HashBase, HashSize)) {
        Status = EFI_DEVICE_ERROR;
        goto Done;
      }

      SumOfBytesHashed += HashSize;
    }
  }

  //
  // Step 16: Hash any trailing bytes between SUM_OF_BYTES_HASHED and the
  // start of the certificate table (or end of file if no cert table).
  //
  if (FileSize > SumOfBytesHashed) {
    HashBase = ImageBase + SumOfBytesHashed;

    if ((SecDir == NULL) || (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY)) {
      CertSize = 0;
    } else {
      CertSize = SecDir->Size;
    }

    if (FileSize > (UINTN)CertSize + SumOfBytesHashed) {
      HashSize = FileSize - (UINTN)CertSize - SumOfBytesHashed;
      if (!HashInfo->Update (HashCtx, HashBase, HashSize)) {
        Status = EFI_DEVICE_ERROR;
        goto Done;
      }
    } else if (FileSize < (UINTN)CertSize + SumOfBytesHashed) {
      Status = EFI_INVALID_PARAMETER;
      goto Done;
    }
  }

  if (!HashInfo->Final (HashCtx, Digest)) {
    Status = EFI_DEVICE_ERROR;
    goto Done;
  }

  *DigestSize = HashInfo->DigestSize;
  Status      = EFI_SUCCESS;

Done:
  if (HashCtx != NULL) {
    FreePool (HashCtx);
  }

  if (SectionHeaders != NULL) {
    FreePool (SectionHeaders);
  }

  return Status;
}

//
// ===========================================================================
// Authenticode hash-algorithm discovery (SpcIndirectDataContent parsing)
// ===========================================================================
//
// The functions below walk the PKCS#7 SignedData ASN.1 structure to recover
// the digest algorithm recorded by the signer, without depending on any
// particular crypto provider. AuthData is untrusted, so every length field
// is decoded with bounds checking.
//

//
// ASN.1 DER tag bytes used while walking the PKCS#7 SignedData structure.
//
#define AUTH_ASN1_TAG_INTEGER     0x02
#define AUTH_ASN1_TAG_OID         0x06
#define AUTH_ASN1_TAG_SEQUENCE    0x30
#define AUTH_ASN1_TAG_SET         0x31
#define AUTH_ASN1_TAG_CTX_CONS_0  0xA0  // [0] EXPLICIT, constructed

//
// OID 1.2.840.113549.1.7.2 (PKCS#7 signedData) - DER value bytes.
//
STATIC CONST UINT8  mAuthPkcs7SignedDataOid[] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02
};

//
// OID 1.3.6.1.4.1.311.2.1.4 (SPC_INDIRECT_DATA_OBJID) - DER value bytes.
//
STATIC CONST UINT8  mAuthSpcIndirectDataOid[] = {
  0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04
};

//
// Digest-algorithm OIDs (DER value bytes) recognized by Authenticode.
//
STATIC CONST UINT8  mAuthOidSha1[] = {
  0x2B, 0x0E, 0x03, 0x02, 0x1A                                  // 1.3.14.3.2.26
};
STATIC CONST UINT8  mAuthOidSha256[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01          // 2.16.840.1.101.3.4.2.1
};
STATIC CONST UINT8  mAuthOidSha384[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02          // 2.16.840.1.101.3.4.2.2
};
STATIC CONST UINT8  mAuthOidSha512[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03          // 2.16.840.1.101.3.4.2.3
};

//
// Mapping of digest-algorithm OID to the signature-type GUID consumed by
// GetAuthenticodeHash().
//
typedef struct {
  CONST UINT8       *Oid;
  UINTN             OidSize;
  CONST EFI_GUID    *HashGuid;
} AUTH_DIGEST_OID_INFO;

STATIC CONST AUTH_DIGEST_OID_INFO  mAuthDigestOidInfo[] = {
  { mAuthOidSha1,   sizeof (mAuthOidSha1),   &gEfiCertSha1Guid   },
  { mAuthOidSha256, sizeof (mAuthOidSha256), &gEfiCertSha256Guid },
  { mAuthOidSha384, sizeof (mAuthOidSha384), &gEfiCertSha384Guid },
  { mAuthOidSha512, sizeof (mAuthOidSha512), &gEfiCertSha512Guid },
};

#define AUTH_DIGEST_OID_INFO_COUNT  (sizeof (mAuthDigestOidInfo) / sizeof (mAuthDigestOidInfo[0]))

/**
  Decode an ASN.1 DER length field starting at *Cursor. On success, the
  decoded length is written to *Length and *Cursor is advanced past the
  length octets.

  Only the definite form is accepted. Lengths > the remaining input are
  rejected.

  @param[in,out] Cursor    Pointer to the cursor pointer; advanced on
                           success.
  @param[in]     End       One past the last valid input byte.
  @param[out]    Length    Receives the decoded content length.

  @retval EFI_SUCCESS            Length parsed.
  @retval EFI_INVALID_PARAMETER  Malformed encoding or out of bounds.
**/
STATIC
EFI_STATUS
Asn1DecodeLength (
  IN OUT CONST UINT8  **Cursor,
  IN     CONST UINT8  *End,
  OUT    UINTN        *Length
  )
{
  CONST UINT8  *P;
  UINTN        Result;
  UINTN        NumOctets;
  UINTN        Index;

  P = *Cursor;
  if (P >= End) {
    return EFI_INVALID_PARAMETER;
  }

  if ((*P & 0x80) == 0) {
    Result = (UINTN)*P;
    P++;
  } else {
    NumOctets = (UINTN)(*P & 0x7F);
    P++;
    //
    // Reject indefinite (0x80) and lengths longer than UINTN.
    //
    if ((NumOctets == 0) || (NumOctets > sizeof (UINTN))) {
      return EFI_INVALID_PARAMETER;
    }

    if ((UINTN)(End - P) < NumOctets) {
      return EFI_INVALID_PARAMETER;
    }

    Result = 0;
    for (Index = 0; Index < NumOctets; Index++) {
      Result = (Result << 8) | P[Index];
    }

    P += NumOctets;
  }

  if ((UINTN)(End - P) < Result) {
    return EFI_INVALID_PARAMETER;
  }

  *Cursor = P;
  *Length = Result;
  return EFI_SUCCESS;
}

/**
  Parse an ASN.1 DER TLV at *Cursor and require Tag. On success, *Body
  points to the value bytes, *BodyLen is the value length, and *Cursor
  is advanced past the entire TLV.

  @param[in,out] Cursor    Cursor pointer.
  @param[in]     End       One past the last valid input byte.
  @param[in]     Tag       Required tag byte.
  @param[out]    Body      Receives a pointer to the value bytes.
  @param[out]    BodyLen   Receives the value length.

  @retval EFI_SUCCESS            TLV parsed.
  @retval EFI_INVALID_PARAMETER  Wrong tag or malformed encoding.
**/
STATIC
EFI_STATUS
Asn1ExpectTagged (
  IN OUT CONST UINT8  **Cursor,
  IN     CONST UINT8  *End,
  IN     UINT8        Tag,
  OUT    CONST UINT8  **Body,
  OUT    UINTN        *BodyLen
  )
{
  CONST UINT8  *P;
  EFI_STATUS   Status;
  UINTN        Length;

  P = *Cursor;
  if ((P >= End) || (*P != Tag)) {
    return EFI_INVALID_PARAMETER;
  }

  P++;
  Status = Asn1DecodeLength (&P, End, &Length);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  *Body    = P;
  *BodyLen = Length;
  *Cursor  = P + Length;
  return EFI_SUCCESS;
}

/**
  Determine the image-hash algorithm used by an Authenticode signature.

  Parses the PKCS#7 SignedData blob's SpcIndirectDataContent
  (OID 1.3.6.1.4.1.311.2.1.4) and reads the digestAlgorithm of its
  embedded messageDigest DigestInfo, mapping it to the corresponding
  signature-type GUID. The recovered GUID can be passed directly to
  GetAuthenticodeHash() as its HashType.

  Caution: AuthData is untrusted. The ASN.1 DER is parsed with
  bounds-checked length decoding to avoid out-of-bounds reads.

  @param[in]   AuthData      Pointer to the PKCS#7 SignedData blob
                             (DER-encoded Authenticode signature).
  @param[in]   AuthDataSize  Size of AuthData in bytes.
  @param[out]  HashType      On success, receives the signature-type
                             GUID identifying the digest algorithm.

  @retval EFI_SUCCESS            The hash algorithm was identified.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL,
                                 AuthDataSize is 0, or AuthData is not a
                                 well-formed Authenticode SignedData
                                 blob.
  @retval EFI_UNSUPPORTED        The digest algorithm is not a
                                 recognized image hash algorithm.
**/
EFI_STATUS
EFIAPI
GetAuthenticodeHashAlgorithm (
  IN  CONST UINT8  *AuthData,
  IN  UINTN        AuthDataSize,
  OUT EFI_GUID     *HashType
  )
{
  EFI_STATUS   Status;
  CONST UINT8  *Cursor;
  CONST UINT8  *End;
  CONST UINT8  *Body;
  UINTN        BodyLen;
  CONST UINT8  *OidBody;
  UINTN        OidLen;
  UINTN        Index;

  if ((AuthData == NULL) || (AuthDataSize == 0) || (HashType == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = AuthData;
  End    = AuthData + AuthDataSize;

  //
  // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT }
  //
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;

  //
  // contentType OID == pkcs7-signedData (1.2.840.113549.1.7.2).
  //
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_OID, &OidBody, &OidLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((OidLen != sizeof (mAuthPkcs7SignedDataOid)) ||
      (CompareMem (OidBody, mAuthPkcs7SignedDataOid, OidLen) != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  //
  // content [0] EXPLICIT -> SignedData.
  //
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_CTX_CONS_0, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;

  //
  // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, ... }
  //
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;

  //
  // version INTEGER (skip).
  //
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_INTEGER, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // digestAlgorithms SET (skip).
  //
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SET, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // encapContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT }.
  //
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;

  //
  // contentType OID == SPC_INDIRECT_DATA (1.3.6.1.4.1.311.2.1.4).
  //
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_OID, &OidBody, &OidLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((OidLen != sizeof (mAuthSpcIndirectDataOid)) ||
      (CompareMem (OidBody, mAuthSpcIndirectDataOid, OidLen) != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  //
  // content [0] EXPLICIT -> SpcIndirectDataContent.
  //
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_CTX_CONS_0, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;

  //
  // SpcIndirectDataContent ::= SEQUENCE { data, messageDigest }.
  //
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;

  //
  // data SpcAttributeTypeAndOptionalValue SEQUENCE (skip).
  //
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // messageDigest DigestInfo ::= SEQUENCE { digestAlgorithm, digest }.
  //
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;

  //
  // digestAlgorithm AlgorithmIdentifier ::= SEQUENCE { algorithm OID, ... }.
  //
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;

  //
  // algorithm OID.
  //
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_OID, &OidBody, &OidLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  for (Index = 0; Index < AUTH_DIGEST_OID_INFO_COUNT; Index++) {
    if ((OidLen == mAuthDigestOidInfo[Index].OidSize) &&
        (CompareMem (OidBody, mAuthDigestOidInfo[Index].Oid, OidLen) == 0))
    {
      CopyGuid (HashType, mAuthDigestOidInfo[Index].HashGuid);
      return EFI_SUCCESS;
    }
  }

  return EFI_UNSUPPORTED;
}

/**
  Compute the digest of the TBSCertificate of an X.509 certificate.

  Extracts the TBSCertificate (the to-be-signed portion) of the given
  DER-encoded certificate and hashes it with the algorithm selected by
  HashType. The TBSCertificate is the exact byte range a certificate
  authority signs, so its digest uniquely identifies the certificate
  independent of the issuer signature.

  The caller selects the digest algorithm by HashType (e.g.
  gEfiCertSha256Guid, gEfiCertSha384Guid). The digest is written to
  Digest, which must be large enough to hold the largest supported
  digest (at least SHA512_DIGEST_SIZE bytes).

  @param[in]   Cert        Pointer to the DER-encoded X.509 certificate.
  @param[in]   CertSize    Size of Cert in bytes.
  @param[in]   HashType    Signature-type GUID identifying the hash
                           algorithm to use.
  @param[out]  Digest      Caller-provided buffer that receives the
                           computed TBSCertificate digest. Must be at
                           least SHA512_DIGEST_SIZE bytes.
  @param[out]  DigestSize  On success, receives the digest length in
                           bytes.

  @retval EFI_SUCCESS            Digest was computed successfully.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL, CertSize is
                                 0, or Cert is not a well-formed X.509
                                 certificate.
  @retval EFI_UNSUPPORTED        HashType is not a recognized image
                                 hash algorithm.
  @retval EFI_OUT_OF_RESOURCES   Could not allocate the hash context.
  @retval EFI_DEVICE_ERROR       A hash primitive failed.
**/
EFI_STATUS
EFIAPI
X509GetTbsCertHash (
  IN  VOID            *Cert,
  IN  UINTN           CertSize,
  IN  CONST EFI_GUID  *HashType,
  OUT UINT8           *Digest,
  OUT UINTN           *DigestSize
  )
{
  EFI_STATUS            Status;
  CONST AUTH_HASH_INFO  *HashInfo;
  UINT8                 *TbsCert;
  UINTN                 TbsCertSize;
  VOID                  *HashCtx;
  UINTN                 CtxSize;

  if ((Cert == NULL) || (CertSize == 0) || (HashType == NULL) ||
      (Digest == NULL) || (DigestSize == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  HashInfo = LookupAuthHashInfo (HashType);
  if (HashInfo == NULL) {
    return EFI_UNSUPPORTED;
  }

  //
  // Extract the TBSCertificate byte range. X509GetTBSCert() returns a
  // pointer into Cert (it does not allocate), so TbsCert must not be
  // freed here.
  //
  TbsCert     = NULL;
  TbsCertSize = 0;
  if (!X509GetTBSCert ((CONST UINT8 *)Cert, CertSize, &TbsCert, &TbsCertSize)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Allocate and initialize the hash context, then hash the
  // TBSCertificate bytes.
  //
  CtxSize = HashInfo->GetContextSize ();
  HashCtx = AllocatePool (CtxSize);
  if (HashCtx == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = EFI_DEVICE_ERROR;
  if (HashInfo->Init (HashCtx) &&
      HashInfo->Update (HashCtx, TbsCert, TbsCertSize) &&
      HashInfo->Final (HashCtx, Digest))
  {
    *DigestSize = HashInfo->DigestSize;
    Status      = EFI_SUCCESS;
  }

  FreePool (HashCtx);
  return Status;
}
