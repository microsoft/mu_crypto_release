/** @file
  Bounds-checked Authenticode image-hash algorithm discovery.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include <Protocol/Hash.h>

#define AUTH_ASN1_TAG_INTEGER     0x02
#define AUTH_ASN1_TAG_OID         0x06
#define AUTH_ASN1_TAG_SEQUENCE    0x30
#define AUTH_ASN1_TAG_SET         0x31
#define AUTH_ASN1_TAG_CTX_CONS_0  0xA0

STATIC CONST UINT8  mAuthPkcs7SignedDataOid[] = {
  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02
};

STATIC CONST UINT8  mAuthSpcIndirectDataOid[] = {
  0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04
};

STATIC CONST UINT8  mAuthOidSha1[] = {
  0x2B, 0x0E, 0x03, 0x02, 0x1A
};
STATIC CONST UINT8  mAuthOidSha256[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};
STATIC CONST UINT8  mAuthOidSha384[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};
STATIC CONST UINT8  mAuthOidSha512[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};

//
// Mapping of digest-algorithm OID to the generic hash-algorithm GUID
// (as defined in Protocol/Hash.h) returned by
// GetAuthenticodeHashAlgorithm().
//
typedef struct {
  CONST UINT8       *Oid;
  UINTN             OidSize;
  CONST EFI_GUID    *HashGuid;
} AUTH_DIGEST_OID_INFO;

STATIC CONST AUTH_DIGEST_OID_INFO  mAuthDigestOidInfo[] = {
  { mAuthOidSha1,   sizeof (mAuthOidSha1),   &gEfiHashAlgorithmSha1Guid   },
  { mAuthOidSha256, sizeof (mAuthOidSha256), &gEfiHashAlgorithmSha256Guid },
  { mAuthOidSha384, sizeof (mAuthOidSha384), &gEfiHashAlgorithmSha384Guid },
  { mAuthOidSha512, sizeof (mAuthOidSha512), &gEfiHashAlgorithmSha512Guid },
};

#define AUTH_DIGEST_OID_INFO_COUNT  (sizeof (mAuthDigestOidInfo) / sizeof (mAuthDigestOidInfo[0]))

/**
  Decode a definite ASN.1 DER length, rejecting lengths beyond the input.
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
  Parse the required tag and advance Cursor past its bounds-checked value.
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
  Discover the image-hash algorithm in untrusted SpcIndirectDataContent.
  The returned GUID identifies the algorithm, not a verified signature.
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

  if ((AuthData == NULL) || (AuthDataSize == 0) || (HashType == NULL) ||
      (AuthDataSize > MAX_UINTN - (UINTN)AuthData))
  {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = AuthData;
  End    = AuthData + AuthDataSize;

  // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT }.
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_OID, &OidBody, &OidLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((OidLen != sizeof (mAuthPkcs7SignedDataOid)) ||
      (CompareMem (OidBody, mAuthPkcs7SignedDataOid, OidLen) != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_CTX_CONS_0, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;

  // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, ... }.
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_INTEGER, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SET, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_OID, &OidBody, &OidLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((OidLen != sizeof (mAuthSpcIndirectDataOid)) ||
      (CompareMem (OidBody, mAuthSpcIndirectDataOid, OidLen) != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_CTX_CONS_0, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;

  // SpcIndirectDataContent ::= SEQUENCE { data, messageDigest }.
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;
  Status = Asn1ExpectTagged (&Cursor, End, AUTH_ASN1_TAG_SEQUENCE, &Body, &BodyLen);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Body;
  End    = Body + BodyLen;
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
