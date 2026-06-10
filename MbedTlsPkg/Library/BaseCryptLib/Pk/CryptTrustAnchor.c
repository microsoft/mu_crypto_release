/** @file
  GetTrustAnchorX509FromAuthData() and the matching cache lifecycle.

  Walks a PKCS#7 SignedData blob, hashes each embedded X.509 certificate's
  TBSCertificate, and returns the certificate whose digest matches a
  caller-supplied hash. Optional cache memoizes (cert -> TBS-hash[s])
  across calls so callers that ask repeatedly do not re-hash the same
  certificates.

  Caution: AuthData is treated as untrusted input. Each ASN.1 length is
  bounds-checked against the remaining input before the parser advances.

  Reference:
    RFC 2315 / RFC 5652 (PKCS#7 / CMS SignedData)
    RFC 5280 (X.509 Certificate)

Copyright (C) Microsoft Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"

//
// ASN.1 DER constants used during the walk.
//
#define ASN1_TAG_SEQUENCE                0x30
#define ASN1_TAG_SET                     0x31
#define ASN1_TAG_OID                     0x06
#define ASN1_TAG_CTX_CONS_0              0xA0  // [0] EXPLICIT / IMPLICIT constructed

//
// signedData OID 1.2.840.113549.1.7.2 = 06 09 2A 86 48 86 F7 0D 01 07 02
//
STATIC CONST UINT8  mPkcs7SignedDataOid[] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02
};

//
// Hash algorithm dispatch table; selected by digest length. The one-shot
// ShaXxxHashAll() entry points handle context allocation, init, update,
// and finalization internally, so the table only needs the digest size
// and the function pointer.
//
typedef
BOOLEAN
(EFIAPI *AUTH_HASH_ALL)(
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  );

typedef struct {
  UINTN            DigestSize;
  AUTH_HASH_ALL    HashAll;
} TRUST_ANCHOR_HASH_INFO;

STATIC CONST TRUST_ANCHOR_HASH_INFO  mHashTable[] = {
  { SHA1_DIGEST_SIZE,   Sha1HashAll   },
  { SHA256_DIGEST_SIZE, Sha256HashAll },
  { SHA384_DIGEST_SIZE, Sha384HashAll },
  { SHA512_DIGEST_SIZE, Sha512HashAll },
};

#define HASH_TABLE_COUNT  (sizeof (mHashTable) / sizeof (mHashTable[0]))

//
// Cache structures. The cache stores up to TRUST_ANCHOR_CACHE_MAX entries;
// each entry is a copy of the certificate DER bytes plus a per-algorithm
// TBSCertificate digest computed lazily on first use. The digests are
// inlined (not heap-allocated) — at four 64-byte slots per entry the
// cost is bounded and the cache lifecycle has no inner allocations to
// fail or leak.
//
#define TRUST_ANCHOR_CACHE_SIGNATURE  SIGNATURE_32 ('T', 'A', 'X', 'C')
#define TRUST_ANCHOR_CACHE_MAX        64

typedef struct {
  UINT8      *CertDer;       // Allocated cert DER copy.
  UINTN      CertDerSize;
  BOOLEAN    TbsHashValid[HASH_TABLE_COUNT];
  UINT8      TbsHash[HASH_TABLE_COUNT][SHA512_DIGEST_SIZE];
} TRUST_ANCHOR_CACHE_ENTRY;

typedef struct {
  UINT32                      Signature;
  UINTN                       Count;
  TRUST_ANCHOR_CACHE_ENTRY    Entries[TRUST_ANCHOR_CACHE_MAX];
} TRUST_ANCHOR_CACHE;

/**
  Map a digest size to an index in mHashTable.

  @param[in]  HashSize  Digest length in bytes.

  @retval Index into mHashTable on match.
  @retval (UINTN)-1 if the size is not supported.
**/
STATIC
UINTN
HashSizeToIndex (
  IN UINTN  HashSize
  )
{
  UINTN  Index;

  for (Index = 0; Index < HASH_TABLE_COUNT; Index++) {
    if (mHashTable[Index].DigestSize == HashSize) {
      return Index;
    }
  }

  return (UINTN)-1;
}

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
  Compute the TBSCertificate digest of an X.509 certificate.

  @param[in]   CertDer       Pointer to the DER-encoded Certificate.
  @param[in]   CertDerSize   Size of the certificate in bytes.
  @param[in]   HashIndex     Algorithm index in mHashTable.
  @param[out]  Digest        Caller-allocated buffer for the digest. Must
                             be at least mHashTable[HashIndex].DigestSize
                             bytes.

  @retval EFI_SUCCESS            Digest computed.
  @retval EFI_INVALID_PARAMETER  CertDer is not a well-formed Certificate.
  @retval EFI_OUT_OF_RESOURCES   Could not allocate hash context.
  @retval EFI_DEVICE_ERROR       Hash primitive failed.
**/
STATIC
EFI_STATUS
HashTbsCertificate (
  IN  CONST UINT8  *CertDer,
  IN  UINTN        CertDerSize,
  IN  UINTN        HashIndex,
  OUT UINT8        *Digest
  )
{
  CONST UINT8  *Cursor;
  CONST UINT8  *End;
  CONST UINT8  *CertBody;
  UINTN        CertBodyLen;
  CONST UINT8  *TbsStart;
  CONST UINT8  *TbsBody;
  UINTN        TbsBodyLen;
  EFI_STATUS   Status;

  Cursor = CertDer;
  End    = CertDer + CertDerSize;

  //
  // Certificate ::= SEQUENCE
  //
  Status = Asn1ExpectTagged (&Cursor, End, ASN1_TAG_SEQUENCE, &CertBody, &CertBodyLen);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // First element of Certificate is TBSCertificate ::= SEQUENCE.
  // Hash that whole TLV (tag + length + value) per RFC 5280 4.1.2.
  //
  TbsStart = CertBody;
  Cursor   = CertBody;
  Status   = Asn1ExpectTagged (&Cursor, CertBody + CertBodyLen, ASN1_TAG_SEQUENCE, &TbsBody, &TbsBodyLen);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (!mHashTable[HashIndex].HashAll (TbsStart, (UINTN)(Cursor - TbsStart), Digest)) {
    return EFI_DEVICE_ERROR;
  }

  return EFI_SUCCESS;
}

/**
  Look up a certificate in the cache by DER bytes. If found, return the
  entry; otherwise append a new entry with a copy of the cert bytes if
  the cache has room.

  @param[in]   Cache         Cache handle.
  @param[in]   CertDer       Pointer to certificate DER bytes.
  @param[in]   CertDerSize   Size of certificate in bytes.

  @retval Pointer to the matching or newly inserted entry on success.
  @retval NULL when the cache is full or memory allocation failed.
**/
STATIC
TRUST_ANCHOR_CACHE_ENTRY *
CacheLookupOrInsert (
  IN TRUST_ANCHOR_CACHE  *Cache,
  IN CONST UINT8         *CertDer,
  IN UINTN               CertDerSize
  )
{
  UINTN                     Index;
  TRUST_ANCHOR_CACHE_ENTRY  *Entry;

  for (Index = 0; Index < Cache->Count; Index++) {
    Entry = &Cache->Entries[Index];
    if ((Entry->CertDerSize == CertDerSize) &&
        (CompareMem (Entry->CertDer, CertDer, CertDerSize) == 0))
    {
      return Entry;
    }
  }

  if (Cache->Count >= TRUST_ANCHOR_CACHE_MAX) {
    return NULL;
  }

  Entry          = &Cache->Entries[Cache->Count];
  Entry->CertDer = AllocateCopyPool (CertDerSize, CertDer);
  if (Entry->CertDer == NULL) {
    return NULL;
  }

  Entry->CertDerSize = CertDerSize;
  ZeroMem (Entry->TbsHashValid, sizeof (Entry->TbsHashValid));
  Cache->Count++;
  return Entry;
}

/**
  Compare a certificate's TBS digest at HashIndex against the supplied
  TbsCertHash, using the cache when available to avoid re-hashing.

  @param[in]   Cache         Cache or NULL.
  @param[in]   CertDer       Pointer to certificate DER bytes.
  @param[in]   CertDerSize   Size of certificate in bytes.
  @param[in]   HashIndex     Algorithm index in mHashTable.
  @param[in]   TbsCertHash   Target digest bytes.
  @param[out]  IsMatch       TRUE on match; FALSE otherwise.

  @retval EFI_SUCCESS  IsMatch was set.
  @retval other        A hashing or allocation error occurred.
**/
STATIC
EFI_STATUS
CertMatchesTbsHash (
  IN  TRUST_ANCHOR_CACHE  *Cache         OPTIONAL,
  IN  CONST UINT8         *CertDer,
  IN  UINTN               CertDerSize,
  IN  UINTN               HashIndex,
  IN  CONST UINT8         *TbsCertHash,
  OUT BOOLEAN             *IsMatch
  )
{
  EFI_STATUS                Status;
  UINTN                     DigestSize;
  TRUST_ANCHOR_CACHE_ENTRY  *Entry;
  UINT8                     LocalDigest[SHA512_DIGEST_SIZE];
  UINT8                     *DigestBuf;

  *IsMatch   = FALSE;
  DigestSize = mHashTable[HashIndex].DigestSize;
  Entry      = (Cache != NULL) ? CacheLookupOrInsert (Cache, CertDer, CertDerSize) : NULL;

  //
  // Hash directly into the cache slot when available; fall back to a
  // stack buffer when the cache is full or absent.
  //
  if ((Entry != NULL) && Entry->TbsHashValid[HashIndex]) {
    DigestBuf = Entry->TbsHash[HashIndex];
  } else {
    DigestBuf = (Entry != NULL) ? Entry->TbsHash[HashIndex] : LocalDigest;
    Status    = HashTbsCertificate (CertDer, CertDerSize, HashIndex, DigestBuf);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if (Entry != NULL) {
      Entry->TbsHashValid[HashIndex] = TRUE;
    }
  }

  if (CompareMem (DigestBuf, TbsCertHash, DigestSize) == 0) {
    *IsMatch = TRUE;
  }

  return EFI_SUCCESS;
}

/**
  Walk a SignedData certificates field and search for a certificate
  whose TBSCertificate digest equals TbsCertHash.

  @param[in]   CertSetBody     Pointer to the contents of the [0]
                               IMPLICIT certificates field.
  @param[in]   CertSetBodyLen  Length of CertSetBody.
  @param[in]   HashIndex       Algorithm index.
  @param[in]   TbsCertHash     Target digest bytes.
  @param[in]   Cache           Optional cache.
  @param[out]  MatchCert       On success, points within CertSetBody to
                               the matching certificate's first byte.
  @param[out]  MatchCertSize   On success, size of the matching cert.

  @retval EFI_SUCCESS    Match found.
  @retval EFI_NOT_FOUND  No certificate matched.
  @retval other          Parse or hashing error.
**/
STATIC
EFI_STATUS
SearchCertificateSet (
  IN  CONST UINT8         *CertSetBody,
  IN  UINTN               CertSetBodyLen,
  IN  UINTN               HashIndex,
  IN  CONST UINT8         *TbsCertHash,
  IN  TRUST_ANCHOR_CACHE  *Cache         OPTIONAL,
  OUT CONST UINT8         **MatchCert,
  OUT UINTN               *MatchCertSize
  )
{
  CONST UINT8  *Cursor;
  CONST UINT8  *End;
  CONST UINT8  *CertStart;
  CONST UINT8  *CertBody;
  UINTN        CertBodyLen;
  EFI_STATUS   Status;
  BOOLEAN      Match;

  Cursor = CertSetBody;
  End    = CertSetBody + CertSetBodyLen;

  while (Cursor < End) {
    if (*Cursor != ASN1_TAG_SEQUENCE) {
      //
      // The certificates field may also contain extendedCertificate or
      // other choices in older PKCS#7. Skip non-SEQUENCE TLVs.
      //
      CertStart = Cursor + 1;
      Status    = Asn1DecodeLength (&CertStart, End, &CertBodyLen);
      if (EFI_ERROR (Status)) {
        return Status;
      }

      Cursor = CertStart + CertBodyLen;
      continue;
    }

    CertStart = Cursor;
    Status    = Asn1ExpectTagged (&Cursor, End, ASN1_TAG_SEQUENCE, &CertBody, &CertBodyLen);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Status = CertMatchesTbsHash (
               Cache,
               CertStart,
               (UINTN)(Cursor - CertStart),
               HashIndex,
               TbsCertHash,
               &Match
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if (Match) {
      *MatchCert     = CertStart;
      *MatchCertSize = (UINTN)(Cursor - CertStart);
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

/**
  Parse a PKCS#7 SignedData blob and return the contents of the
  certificates [0] IMPLICIT field.

  Accepts both the bare SignedData encoding and a ContentInfo wrapper.

  @param[in]   AuthData       Pointer to PKCS#7 / SignedData bytes.
  @param[in]   AuthDataSize   Size in bytes.
  @param[out]  CertSetBody    Receives a pointer into AuthData where the
                              certificates contents start.
  @param[out]  CertSetBodyLen Receives the length of the certificates
                              contents.

  @retval EFI_SUCCESS            Parsed and certificates field located.
  @retval EFI_INVALID_PARAMETER  Malformed input.
  @retval EFI_NOT_FOUND          The optional certificates field is
                                 absent.
**/
STATIC
EFI_STATUS
LocateCertificatesField (
  IN  CONST UINT8  *AuthData,
  IN  UINTN        AuthDataSize,
  OUT CONST UINT8  **CertSetBody,
  OUT UINTN        *CertSetBodyLen
  )
{
  CONST UINT8  *Cursor;
  CONST UINT8  *End;
  CONST UINT8  *Body;
  UINTN        BodyLen;
  CONST UINT8  *OidBody;
  UINTN        OidLen;
  EFI_STATUS   Status;

  Cursor = AuthData;
  End    = AuthData + AuthDataSize;

  //
  // Outer SEQUENCE.
  //
  Status = Asn1ExpectTagged (&Cursor, End, ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Cursor = Body;
  End    = Body + BodyLen;

  //
  // Detect ContentInfo: optional contentType OID followed by [0] EXPLICIT
  // SignedData. If we see an OID first, peel the wrapper.
  //
  if ((Cursor < End) && (*Cursor == ASN1_TAG_OID)) {
    Status = Asn1ExpectTagged (&Cursor, End, ASN1_TAG_OID, &OidBody, &OidLen);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if ((OidLen != sizeof (mPkcs7SignedDataOid)) ||
        (CompareMem (OidBody, mPkcs7SignedDataOid, OidLen) != 0))
    {
      return EFI_INVALID_PARAMETER;
    }

    //
    // [0] EXPLICIT SignedData wrapper.
    //
    Status = Asn1ExpectTagged (&Cursor, End, ASN1_TAG_CTX_CONS_0, &Body, &BodyLen);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Cursor = Body;
    End    = Body + BodyLen;

    //
    // Inner SignedData SEQUENCE.
    //
    Status = Asn1ExpectTagged (&Cursor, End, ASN1_TAG_SEQUENCE, &Body, &BodyLen);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Cursor = Body;
    End    = Body + BodyLen;
  }

  //
  // Now Cursor..End contains the SignedData contents.
  //   version            INTEGER
  //   digestAlgorithms   SET
  //   encapContentInfo   SEQUENCE
  //   certificates [0]   IMPLICIT (optional)  <-- the field we want
  //   crls         [1]   IMPLICIT (optional)
  //   signerInfos        SET
  //
  // Skip version + digestAlgorithms + encapContentInfo by parsing each
  // TLV and discarding its body.
  //
  // version (INTEGER, tag 0x02)
  //
  if (Cursor >= End) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Asn1ExpectTagged (&Cursor, End, *Cursor, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // digestAlgorithms (SET)
  //
  Status = Asn1ExpectTagged (&Cursor, End, ASN1_TAG_SET, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // encapContentInfo (SEQUENCE)
  //
  Status = Asn1ExpectTagged (&Cursor, End, ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Optional certificates [0] IMPLICIT.
  //
  if ((Cursor < End) && (*Cursor == ASN1_TAG_CTX_CONS_0)) {
    Status = Asn1ExpectTagged (&Cursor, End, ASN1_TAG_CTX_CONS_0, &Body, &BodyLen);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    *CertSetBody    = Body;
    *CertSetBodyLen = BodyLen;
    return EFI_SUCCESS;
  }

  return EFI_NOT_FOUND;
}

/**
  Locate, in a PKCS#7 SignedData blob, the X.509 certificate whose
  TBSCertificate digest matches a caller-supplied hash, and return
  that certificate as a newly allocated DER-encoded buffer.

  See BaseCryptLib.h for the full contract.
**/
EFI_STATUS
EFIAPI
GetTrustAnchorX509FromAuthData (
  IN OUT VOID         **CacheHandle  OPTIONAL,
  IN  CONST UINT8     *TbsCertHash,
  IN  UINTN           TbsCertHashSize,
  IN  CONST UINT8     *AuthData,
  IN  UINTN           AuthDataSize,
  OUT UINT8           **TrustAnchorX509,
  OUT UINTN           *TrustAnchorX509Size
  )
{
  EFI_STATUS          Status;
  UINTN               HashIndex;
  CONST UINT8         *CertSetBody;
  UINTN               CertSetBodyLen;
  CONST UINT8         *MatchCert;
  UINTN               MatchCertSize;
  TRUST_ANCHOR_CACHE  *Cache;
  UINT8               *Output;

  if ((TbsCertHash == NULL) || (TbsCertHashSize == 0) ||
      (AuthData == NULL) || (AuthDataSize == 0) ||
      (TrustAnchorX509 == NULL) || (TrustAnchorX509Size == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  HashIndex = HashSizeToIndex (TbsCertHashSize);
  if (HashIndex == (UINTN)-1) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Optional cache. *CacheHandle == NULL means "allocate me one"; the
  // caller releases it later via FreeTrustAnchorX509Cache().
  //
  Cache = NULL;
  if (CacheHandle != NULL) {
    if (*CacheHandle == NULL) {
      Cache = AllocateZeroPool (sizeof (TRUST_ANCHOR_CACHE));
      if (Cache == NULL) {
        return EFI_OUT_OF_RESOURCES;
      }

      Cache->Signature = TRUST_ANCHOR_CACHE_SIGNATURE;
      *CacheHandle     = Cache;
    } else {
      Cache = (TRUST_ANCHOR_CACHE *)*CacheHandle;
      if (Cache->Signature != TRUST_ANCHOR_CACHE_SIGNATURE) {
        return EFI_INVALID_PARAMETER;
      }
    }
  }

  Status = LocateCertificatesField (AuthData, AuthDataSize, &CertSetBody, &CertSetBodyLen);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SearchCertificateSet (
             CertSetBody,
             CertSetBodyLen,
             HashIndex,
             TbsCertHash,
             Cache,
             &MatchCert,
             &MatchCertSize
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Output = AllocateCopyPool (MatchCertSize, MatchCert);
  if (Output == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  *TrustAnchorX509     = Output;
  *TrustAnchorX509Size = MatchCertSize;
  return EFI_SUCCESS;
}

/**
  Release a trust-anchor cache previously allocated by
  GetTrustAnchorX509FromAuthData().

  @param[in]  CacheHandle  Cache handle, or NULL.
**/
VOID
EFIAPI
FreeTrustAnchorX509Cache (
  IN  VOID  *CacheHandle  OPTIONAL
  )
{
  TRUST_ANCHOR_CACHE        *Cache;
  TRUST_ANCHOR_CACHE_ENTRY  *Entry;
  UINTN                     Index;

  if (CacheHandle == NULL) {
    return;
  }

  Cache = (TRUST_ANCHOR_CACHE *)CacheHandle;
  if (Cache->Signature != TRUST_ANCHOR_CACHE_SIGNATURE) {
    ASSERT (FALSE);
    return;
  }

  for (Index = 0; Index < Cache->Count; Index++) {
    Entry = &Cache->Entries[Index];
    if (Entry->CertDer != NULL) {
      FreePool (Entry->CertDer);
    }
  }

  ZeroMem (Cache, sizeof (TRUST_ANCHOR_CACHE));
  FreePool (Cache);
}
