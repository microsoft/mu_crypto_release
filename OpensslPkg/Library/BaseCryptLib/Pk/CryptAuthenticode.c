/** @file
  Authenticode Portable Executable Signature Verification over OpenSSL.

  Caution: This module requires additional review when modified.
  This library will have external input - signature (e.g. PE/COFF Authenticode).
  This external input must be validated carefully to avoid security issue like
  buffer overflow, integer overflow.

  AuthenticodeVerify() will get PE/COFF Authenticode and will do basic check for
  data structure.

Copyright (c) 2011 - 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"

#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>

//
// OID ASN.1 Value for SPC_INDIRECT_DATA_OBJID
//
GLOBAL_REMOVE_IF_UNREFERENCED const UINT8  mSpcIndirectOidValue[] = {
  0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04
};

/**
  Map the caller-supplied image hash byte length to the unique Authenticode-
  allowed DigestInfo digestAlgorithm NID.

  Authenticode (per Microsoft PE/COFF spec) restricts the inner DigestInfo
  digestAlgorithm to the SHA-1 / SHA-2 family.  Because the caller supplies
  only the precomputed image hash and its byte length, the verifier must
  reject blobs whose declared digestAlgorithm could collide on length with
  a different (and possibly weaker) hash family, e.g. SHA-256 vs SHA3-256
  (both 32 bytes) or SHA-384 vs SHA3-384 (both 48 bytes).

  @param[in]  HashSize  Length in bytes of the caller-supplied ImageHash.

  @return  The unique NID expected at DigestInfo.digestAlgorithm for the
           given HashSize, or NID_undef if HashSize does not correspond to
           an Authenticode-allowed hash.

**/
STATIC
int
AuthenticodeExpectedDigestNid (
  IN UINTN  HashSize
  )
{
  switch (HashSize) {
    case 20:
      return NID_sha1;
    case 32:
      return NID_sha256;
    case 48:
      return NID_sha384;
    case 64:
      return NID_sha512;
    default:
      return NID_undef;
  }
}

/**
  Serialize a PKCS#7 SignedData with its eContent removed so the result is a
  CMS-parseable detached signature.

  Authenticode follows PKCS#7 v1.5 (RFC 2315) where the eContent may be any
  ASN.1 type defined by the contentType OID.  CMS (RFC 5652) requires the
  eContent to be an OCTET STRING, so d2i_CMS_ContentInfo cannot parse the
  inline SpcIndirectDataContent form.  Re-encoding the PKCS#7 with the
  eContent removed produces a detached signature that CMS_verify can parse,
  and the original eContent bytes are supplied separately as detached
  content.

  OpenSSL 4.x does not expose an accessor for the inner eContent field of a
  PKCS7 SignedData structure - the PKCS7 module is in maintenance mode in
  favor of CMS, which exposes CMS_set_detached() for the equivalent
  operation.  Direct PKCS7 struct field access is therefore required, and is
  isolated to this helper.

  @param[in,out]  Pkcs7        The PKCS#7 SignedData to re-encode.  The
                               eContent is detached during the call and
                               restored before return so the caller's PKCS7
                               object can be freed normally.
  @param[out]     DetachedDer  On success, receives an OpenSSL-allocated DER
                               buffer; caller frees with OPENSSL_free().

  @return  Length of the produced DER bytes, or 0 on error.

**/
STATIC
INT32
SerializePkcs7AsDetached (
  IN OUT PKCS7  *Pkcs7,
  OUT    UINT8  **DetachedDer
  )
{
  ASN1_TYPE  *OrigContent;
  int        DerLen;

  //
  // Defense-in-depth: AuthenticodeVerify dereferences this chain earlier
  // when locating SpcIndirectDataContent, so a NULL in any of these fields
  // would already have faulted there - but validate explicitly so the
  // helper is self-contained and a future caller without the same upstream
  // invariant returns 0 rather than dereferencing a NULL pointer.
  //
  if ((Pkcs7 == NULL) || (DetachedDer == NULL) ||
      (Pkcs7->d.sign == NULL) ||
      (Pkcs7->d.sign->contents == NULL) ||
      (Pkcs7->d.sign->contents->d.other == NULL))
  {
    return 0;
  }

  //
  // No public accessor exists for Pkcs7->d.sign->contents->d.other in
  // OpenSSL 4.x; direct struct field access is unavoidable.  See function
  // header comment for the rationale.
  //
  OrigContent                      = Pkcs7->d.sign->contents->d.other;
  Pkcs7->d.sign->contents->d.other = NULL;

  DerLen = i2d_PKCS7 (Pkcs7, DetachedDer);

  Pkcs7->d.sign->contents->d.other = OrigContent;

  if (DerLen <= 0) {
    return 0;
  }

  return (INT32)DerLen;
}

/**
  Verifies the validity of a PE/COFF Authenticode Signature as described in "Windows
  Authenticode Portable Executable Signature Format".

  If AuthData is NULL, then return FALSE.
  If ImageHash is NULL, then return FALSE.

  Caution: This function may receive untrusted input.
  PE/COFF Authenticode is external input, so this function will do basic check for
  Authenticode data structure.

  @param[in]  AuthData     Pointer to the Authenticode Signature retrieved from signed
                           PE/COFF image to be verified.
  @param[in]  DataSize     Size of the Authenticode Signature in bytes.
  @param[in]  TrustedCert  Pointer to a trusted/root certificate encoded in DER, which
                           is used for certificate chain verification.
  @param[in]  CertSize     Size of the trusted certificate in bytes.
  @param[in]  ImageHash    Pointer to the original image file hash value. The procedure
                           for calculating the image hash value is described in Authenticode
                           specification.
  @param[in]  HashSize     Size of Image hash value in bytes.

  @retval  TRUE   The specified Authenticode Signature is valid.
  @retval  FALSE  Invalid Authenticode Signature.

**/
BOOLEAN
EFIAPI
AuthenticodeVerify (
  IN  CONST UINT8  *AuthData,
  IN  UINTN        DataSize,
  IN  CONST UINT8  *TrustedCert,
  IN  UINTN        CertSize,
  IN  CONST UINT8  *ImageHash,
  IN  UINTN        HashSize
  )
{
  BOOLEAN                  Status;
  PKCS7                    *Pkcs7;
  CONST UINT8              *Temp;
  CONST UINT8              *SpcIndirectDataContent;
  UINTN                    ContentSize;
  CONST UINT8              *SpcIndirectDataOid;
  ASN1_STRING              *RawSpcContent;
  CONST UINT8              *Asn1Cursor;
  long                     Asn1Len;
  int                      Asn1Tag;
  int                      Asn1Class;
  int                      Asn1Ret;
  X509_SIG                 *DigestInfo;
  CONST X509_ALGOR         *DigestAlgo;
  CONST ASN1_OBJECT        *DigestAlgoOid;
  CONST ASN1_OCTET_STRING  *DigestOctet;
  int                      ExpectedDigestNid;
  UINT8                    *DetachedDer;
  INT32                    DetachedDerLen;

  //
  // Check input parameters.
  //
  if ((AuthData == NULL) || (TrustedCert == NULL) || (ImageHash == NULL)) {
    return FALSE;
  }

  if ((DataSize > INT_MAX) || (CertSize > INT_MAX) || (HashSize > INT_MAX)) {
    return FALSE;
  }

  Status         = FALSE;
  Pkcs7          = NULL;
  DigestInfo     = NULL;
  DetachedDer    = NULL;
  DetachedDerLen = 0;

  //
  // Retrieve & Parse PKCS#7 Data (DER encoding) from Authenticode Signature
  //
  Temp  = AuthData;
  Pkcs7 = d2i_PKCS7 (NULL, &Temp, (int)DataSize);
  if (Pkcs7 == NULL) {
    goto _Exit;
  }

  //
  // Check if it's PKCS#7 Signed Data (for Authenticode Scenario)
  //
  if (!PKCS7_type_is_signed (Pkcs7) || PKCS7_get_detached (Pkcs7)) {
    goto _Exit;
  }

  //
  // NOTE: OpenSSL PKCS7 Decoder didn't work for Authenticode-format signed data due to
  //       some authenticode-specific structure. Use opaque ASN.1 string to retrieve
  //       PKCS#7 ContentInfo here.
  //
  SpcIndirectDataOid = OBJ_get0_data (Pkcs7->d.sign->contents->type);
  if (SpcIndirectDataOid == NULL) {
    goto _Exit;
  }

  if ((OBJ_length (Pkcs7->d.sign->contents->type) != sizeof (mSpcIndirectOidValue)) ||
      (CompareMem (
         SpcIndirectDataOid,
         mSpcIndirectOidValue,
         sizeof (mSpcIndirectOidValue)
         ) != 0))
  {
    //
    // Un-matched SPC_INDIRECT_DATA_OBJID.
    //
    goto _Exit;
  }

  //
  // Parse the outer SpcIndirectDataContent SEQUENCE header to obtain a
  // pointer to and length of its content octets.  These are the bytes whose
  // digest is the PKCS#7 messageDigest attribute, and are also fed to
  // Pkcs7Verify as the detached content.
  //
  RawSpcContent = Pkcs7->d.sign->contents->d.other->value.asn1_string;
  Asn1Cursor    = ASN1_STRING_get0_data (RawSpcContent);
  Asn1Ret       = ASN1_get_object (
                    &Asn1Cursor,
                    &Asn1Len,
                    &Asn1Tag,
                    &Asn1Class,
                    (long)ASN1_STRING_length (RawSpcContent)
                    );
  //
  // Reject the SEQUENCE unless it is universal-class.  ASN1_get_object
  // returns the parsed class separately from the tag number, and an
  // attacker-supplied non-universal SEQUENCE-shaped object would otherwise
  // be accepted here despite changing the structural meaning of the
  // parsed bytes.
  //
  if (((Asn1Ret & 0x80) != 0) ||
      ((Asn1Ret & 0x01) != 0) ||
      (Asn1Tag != V_ASN1_SEQUENCE) ||
      (Asn1Class != V_ASN1_UNIVERSAL))
  {
    goto _Exit;
  }

  SpcIndirectDataContent = Asn1Cursor;
  ContentSize            = (UINTN)Asn1Len;

  //
  // Locate the messageDigest DigestInfo within SpcIndirectDataContent and
  // verify the embedded digest matches the supplied image hash.
  //
  //   SpcIndirectDataContent ::= SEQUENCE {
  //     data          SpcAttributeTypeAndOptionalValue,
  //     messageDigest DigestInfo
  //   }
  //
  //   DigestInfo ::= SEQUENCE {
  //     digestAlgorithm AlgorithmIdentifier,
  //     digest          OCTET STRING
  //   }
  //
  // OpenSSL's X509_SIG type is structurally identical to DigestInfo, so use
  // d2i_X509_SIG to parse the encoded form properly instead of relying on
  // byte-offset arithmetic against the SEQUENCE tail.
  //
  Asn1Ret = ASN1_get_object (
              &Asn1Cursor,
              &Asn1Len,
              &Asn1Tag,
              &Asn1Class,
              (long)ContentSize
              );
  if (((Asn1Ret & 0x80) != 0) ||
      ((Asn1Ret & 0x01) != 0) ||
      (Asn1Tag != V_ASN1_SEQUENCE) ||
      (Asn1Class != V_ASN1_UNIVERSAL))
  {
    goto _Exit;
  }

  //
  // Skip past the SpcAttributeTypeAndOptionalValue content to land on the
  // DigestInfo SEQUENCE header.
  //
  Asn1Cursor += Asn1Len;
  DigestInfo  = d2i_X509_SIG (
                  NULL,
                  &Asn1Cursor,
                  (long)ContentSize - (long)(Asn1Cursor - SpcIndirectDataContent)
                  );
  if (DigestInfo == NULL) {
    goto _Exit;
  }

  X509_SIG_get0 (DigestInfo, &DigestAlgo, &DigestOctet);

  //
  // Validate the declared DigestInfo.digestAlgorithm matches the unique
  // Authenticode-allowed hash NID for the caller-supplied HashSize.  Without
  // this check a signer could declare a length-colliding hash from a
  // different family (e.g. SHA3-256 with HashSize == 32) and the digest
  // byte comparison alone would still match.
  //
  ExpectedDigestNid = AuthenticodeExpectedDigestNid (HashSize);
  if ((DigestAlgo == NULL) ||
      (DigestOctet == NULL) ||
      (ExpectedDigestNid == NID_undef))
  {
    goto _Exit;
  }

  X509_ALGOR_get0 (&DigestAlgoOid, NULL, NULL, DigestAlgo);
  if ((DigestAlgoOid == NULL) ||
      (OBJ_obj2nid (DigestAlgoOid) != ExpectedDigestNid))
  {
    //
    // Declared digestAlgorithm does not match the expected algorithm for
    // HashSize.  Reject to prevent same-length cross-family substitution.
    //
    goto _Exit;
  }

  if (((UINTN)ASN1_STRING_length (DigestOctet) != HashSize) ||
      (CompareMem (ASN1_STRING_get0_data (DigestOctet), ImageHash, HashSize) != 0))
  {
    //
    // Un-matched PE/COFF Hash Value
    //
    goto _Exit;
  }

  //
  // Verify the PKCS#7 Signed Data in the PE/COFF Authenticode Signature.
  //
  // Authenticode uses PKCS#7 v1.5 format where eContent is encoded as a raw
  // SEQUENCE (SpcIndirectDataContent). CMS (RFC 5652) requires eContent to be
  // an OCTET STRING, so d2i_CMS_ContentInfo cannot parse the inline form. To
  // make Pkcs7Verify's CMS-based path work, produce a detached re-encoding
  // of the PKCS#7 and pass the original SpcIndirectDataContent separately as
  // the detached content.
  //
  DetachedDerLen = SerializePkcs7AsDetached (Pkcs7, &DetachedDer);
  if ((DetachedDerLen <= 0) || (DetachedDer == NULL)) {
    goto _Exit;
  }

  Status = Pkcs7Verify (
             DetachedDer,
             (UINTN)DetachedDerLen,
             TrustedCert,
             CertSize,
             SpcIndirectDataContent,
             ContentSize
             );

_Exit:
  //
  // Release Resources
  //
  X509_SIG_free (DigestInfo);
  OPENSSL_free (DetachedDer);
  PKCS7_free (Pkcs7);

  return Status;
}
