/** @file
  PKCS#7 SignedData Verification Wrapper Implementation over OpenSSL.

  Caution: This module requires additional review when modified.
  This library will have external input - signature (e.g. UEFI Authenticated
  Variable). It may by input in SMM mode.
  This external input must be validated carefully to avoid security issue like
  buffer overflow, integer overflow.

  WrapPkcs7Data(), Pkcs7GetSigners(), Pkcs7Verify() will get UEFI Authenticated
  Variable and will do basic check for data structure.

Copyright (c) 2009 - 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"

#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/cms.h>
#include <openssl/err.h>

GLOBAL_REMOVE_IF_UNREFERENCED const UINT8  mOidValue[9] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };

/**
  Check input P7Data is a wrapped ContentInfo structure or not. If not construct
  a new structure to wrap P7Data.

  Caution: This function may receive untrusted input.
  UEFI Authenticated Variable is external input, so this function will do basic
  check for PKCS#7 data structure.

  @param[in]  P7Data       Pointer to the PKCS#7 message to verify.
  @param[in]  P7Length     Length of the PKCS#7 message in bytes.
  @param[out] WrapFlag     If TRUE P7Data is a ContentInfo structure, otherwise
                           return FALSE.
  @param[out] WrapData     If return status of this function is TRUE:
                           1) when WrapFlag is TRUE, pointer to P7Data.
                           2) when WrapFlag is FALSE, pointer to a new ContentInfo
                           structure. It's caller's responsibility to free this
                           buffer.
  @param[out] WrapDataSize Length of ContentInfo structure in bytes.

  @retval     TRUE         The operation is finished successfully.
  @retval     FALSE        The operation is failed due to lack of resources.

**/
BOOLEAN
WrapPkcs7Data (
  IN  CONST UINT8  *P7Data,
  IN  UINTN        P7Length,
  OUT BOOLEAN      *WrapFlag,
  OUT UINT8        **WrapData,
  OUT UINTN        *WrapDataSize
  )
{
  BOOLEAN  Wrapped;
  UINT8    *SignedData;

  //
  // Check whether input P7Data is a wrapped ContentInfo structure or not.
  //
  Wrapped = FALSE;
  if ((P7Data[4] == 0x06) && (P7Data[5] == 0x09)) {
    if (CompareMem (P7Data + 6, mOidValue, sizeof (mOidValue)) == 0) {
      if ((P7Data[15] == 0xA0) && (P7Data[16] == 0x82)) {
        Wrapped = TRUE;
      }
    }
  }

  if (Wrapped) {
    *WrapData     = (UINT8 *)P7Data;
    *WrapDataSize = P7Length;
  } else {
    //
    // Wrap PKCS#7 signeddata to a ContentInfo structure - add a header in 19 bytes.
    //
    *WrapDataSize = P7Length + 19;
    *WrapData     = malloc (*WrapDataSize);
    if (*WrapData == NULL) {
      *WrapFlag = Wrapped;
      return FALSE;
    }

    SignedData = *WrapData;

    //
    // Part1: 0x30, 0x82.
    //
    SignedData[0] = 0x30;
    SignedData[1] = 0x82;

    //
    // Part2: Length1 = P7Length + 19 - 4, in big endian.
    //
    SignedData[2] = (UINT8)(((UINT16)(*WrapDataSize - 4)) >> 8);
    SignedData[3] = (UINT8)(((UINT16)(*WrapDataSize - 4)) & 0xff);

    //
    // Part3: 0x06, 0x09.
    //
    SignedData[4] = 0x06;
    SignedData[5] = 0x09;

    //
    // Part4: OID value -- 0x2A 0x86 0x48 0x86 0xF7 0x0D 0x01 0x07 0x02.
    //
    CopyMem (SignedData + 6, mOidValue, sizeof (mOidValue));

    //
    // Part5: 0xA0, 0x82.
    //
    SignedData[15] = 0xA0;
    SignedData[16] = 0x82;

    //
    // Part6: Length2 = P7Length, in big endian.
    //
    SignedData[17] = (UINT8)(((UINT16)P7Length) >> 8);
    SignedData[18] = (UINT8)(((UINT16)P7Length) & 0xff);

    //
    // Part7: P7Data.
    //
    CopyMem (SignedData + 19, P7Data, P7Length);
  }

  *WrapFlag = Wrapped;
  return TRUE;
}

/**
  Pop single certificate from STACK_OF(X509).

  If X509Stack, Cert, or CertSize is NULL, then return FALSE.

  @param[in]  X509Stack       Pointer to a X509 stack object.
  @param[out] Cert            Pointer to a X509 certificate.
  @param[out] CertSize        Length of output X509 certificate in bytes.

  @retval     TRUE            The X509 stack pop succeeded.
  @retval     FALSE           The pop operation failed.

**/
STATIC
BOOLEAN
X509PopCertificate (
  IN  VOID   *X509Stack,
  OUT UINT8  **Cert,
  OUT UINTN  *CertSize
  )
{
  BIO   *CertBio;
  X509  *X509Cert;

  STACK_OF (X509)  *CertStack;
  BOOLEAN  Status;
  INT32    Result;
  BUF_MEM  *Ptr;
  INT32    Length;
  VOID     *Buffer;

  Status = FALSE;

  if ((X509Stack == NULL) || (Cert == NULL) || (CertSize == NULL)) {
    return Status;
  }

  CertStack = (STACK_OF (X509) *) X509Stack;

  X509Cert = sk_X509_pop (CertStack);

  if (X509Cert == NULL) {
    return Status;
  }

  Buffer = NULL;

  CertBio = BIO_new (BIO_s_mem ());
  if (CertBio == NULL) {
    return Status;
  }

  Result = i2d_X509_bio (CertBio, X509Cert);
  if (Result == 0) {
    goto _Exit;
  }

  BIO_get_mem_ptr (CertBio, &Ptr);
  Length = (INT32)(Ptr->length);
  if (Length <= 0) {
    goto _Exit;
  }

  Buffer = malloc (Length);
  if (Buffer == NULL) {
    goto _Exit;
  }

  Result = BIO_read (CertBio, Buffer, Length);
  if (Result != Length) {
    goto _Exit;
  }

  *Cert     = Buffer;
  *CertSize = Length;

  Status = TRUE;

_Exit:

  BIO_free (CertBio);

  if (!Status && (Buffer != NULL)) {
    free (Buffer);
  }

  return Status;
}

/**
  Get the signer's certificates from PKCS#7 signed data as described in "PKCS #7:
  Cryptographic Message Syntax Standard". The input signed data could be wrapped
  in a ContentInfo structure.

  If P7Data, CertStack, StackLength, TrustedCert or CertLength is NULL, then
  return FALSE. If P7Length overflow, then return FALSE.

  Caution: This function may receive untrusted input.
  UEFI Authenticated Variable is external input, so this function will do basic
  check for PKCS#7 data structure.

  @param[in]  P7Data       Pointer to the PKCS#7 message to verify.
  @param[in]  P7Length     Length of the PKCS#7 message in bytes.
  @param[out] CertStack    Pointer to Signer's certificates retrieved from P7Data.
                           It's caller's responsibility to free the buffer with
                           Pkcs7FreeSigners().
                           This data structure is EFI_CERT_STACK type.
  @param[out] StackLength  Length of signer's certificates in bytes.
  @param[out] TrustedCert  Pointer to a trusted certificate from Signer's certificates.
                           It's caller's responsibility to free the buffer with
                           Pkcs7FreeSigners().
  @param[out] CertLength   Length of the trusted certificate in bytes.

  @retval  TRUE            The operation is finished successfully.
  @retval  FALSE           Error occurs during the operation.

**/
BOOLEAN
EFIAPI
Pkcs7GetSigners (
  IN  CONST UINT8  *P7Data,
  IN  UINTN        P7Length,
  OUT UINT8        **CertStack,
  OUT UINTN        *StackLength,
  OUT UINT8        **TrustedCert,
  OUT UINTN        *CertLength
  )
{
  PKCS7        *Pkcs7;
  BOOLEAN      Status;
  UINT8        *SignedData;
  CONST UINT8  *Temp;
  UINTN        SignedDataSize;
  BOOLEAN      Wrapped;

  STACK_OF (X509)   *Stack;
  UINT8  Index;
  UINT8  *CertBuf;
  UINT8  *OldBuf;
  UINTN  BufferSize;
  UINTN  OldSize;
  UINT8  *SingleCert;
  UINTN  SingleCertSize;

  if ((P7Data == NULL) || (CertStack == NULL) || (StackLength == NULL) ||
      (TrustedCert == NULL) || (CertLength == NULL) || (P7Length > INT_MAX))
  {
    return FALSE;
  }

  Status = WrapPkcs7Data (P7Data, P7Length, &Wrapped, &SignedData, &SignedDataSize);
  if (!Status) {
    return Status;
  }

  Status     = FALSE;
  Pkcs7      = NULL;
  Stack      = NULL;
  CertBuf    = NULL;
  OldBuf     = NULL;
  SingleCert = NULL;

  //
  // Retrieve PKCS#7 Data (DER encoding)
  //
  if (SignedDataSize > INT_MAX) {
    goto _Exit;
  }

  Temp  = SignedData;
  Pkcs7 = d2i_PKCS7 (NULL, (const unsigned char **)&Temp, (int)SignedDataSize);
  if (Pkcs7 == NULL) {
    goto _Exit;
  }

  //
  // Check if it's PKCS#7 Signed Data (for Authenticode Scenario)
  //
  if (!PKCS7_type_is_signed (Pkcs7)) {
    goto _Exit;
  }

  Stack = PKCS7_get0_signers (Pkcs7, NULL, PKCS7_BINARY);
  if (Stack == NULL) {
    goto _Exit;
  }

  //
  // Convert CertStack to buffer in following format:
  // UINT8  CertNumber;
  // UINT32 Cert1Length;
  // UINT8  Cert1[];
  // UINT32 Cert2Length;
  // UINT8  Cert2[];
  // ...
  // UINT32 CertnLength;
  // UINT8  Certn[];
  //
  BufferSize = sizeof (UINT8);
  OldSize    = BufferSize;

  for (Index = 0; ; Index++) {
    Status = X509PopCertificate (Stack, &SingleCert, &SingleCertSize);
    if (!Status) {
      break;
    }

    OldSize    = BufferSize;
    OldBuf     = CertBuf;
    BufferSize = OldSize + SingleCertSize + sizeof (UINT32);
    CertBuf    = malloc (BufferSize);

    if (CertBuf == NULL) {
      goto _Exit;
    }

    if (OldBuf != NULL) {
      CopyMem (CertBuf, OldBuf, OldSize);
      free (OldBuf);
      OldBuf = NULL;
    }

    WriteUnaligned32 ((UINT32 *)(CertBuf + OldSize), (UINT32)SingleCertSize);
    CopyMem (CertBuf + OldSize + sizeof (UINT32), SingleCert, SingleCertSize);

    free (SingleCert);
    SingleCert = NULL;
  }

  if (CertBuf != NULL) {
    //
    // Update CertNumber.
    //
    CertBuf[0] = Index;

    *CertLength  = BufferSize - OldSize - sizeof (UINT32);
    *TrustedCert = malloc (*CertLength);
    if (*TrustedCert == NULL) {
      goto _Exit;
    }

    CopyMem (*TrustedCert, CertBuf + OldSize + sizeof (UINT32), *CertLength);
    *CertStack   = CertBuf;
    *StackLength = BufferSize;
    Status       = TRUE;
  }

_Exit:
  //
  // Release Resources
  //
  if (!Wrapped) {
    free (SignedData);
  }

  if (Pkcs7 != NULL) {
    PKCS7_free (Pkcs7);
  }

  if (Stack != NULL) {
    sk_X509_pop_free (Stack, X509_free);
  }

  if (SingleCert !=  NULL) {
    free (SingleCert);
  }

  if (!Status && (CertBuf != NULL)) {
    free (CertBuf);
    *CertStack = NULL;
  }

  if (OldBuf != NULL) {
    free (OldBuf);
  }

  return Status;
}

/**
  Wrap function to use free() to free allocated memory for certificates.

  @param[in]  Certs        Pointer to the certificates to be freed.

**/
VOID
EFIAPI
Pkcs7FreeSigners (
  IN  UINT8  *Certs
  )
{
  if (Certs == NULL) {
    return;
  }

  free (Certs);
}

/**
  Retrieves all embedded certificates from PKCS#7 signed data as described in "PKCS #7:
  Cryptographic Message Syntax Standard", and outputs two certificate lists chained and
  unchained to the signer's certificates.
  The input signed data could be wrapped in a ContentInfo structure.

  @param[in]  P7Data            Pointer to the PKCS#7 message.
  @param[in]  P7Length          Length of the PKCS#7 message in bytes.
  @param[out] SignerChainCerts  Pointer to the certificates list chained to signer's
                                certificate. It's caller's responsibility to free the buffer
                                with Pkcs7FreeSigners().
                                This data structure is EFI_CERT_STACK type.
  @param[out] ChainLength       Length of the chained certificates list buffer in bytes.
  @param[out] UnchainCerts      Pointer to the unchained certificates lists. It's caller's
                                responsibility to free the buffer with Pkcs7FreeSigners().
                                This data structure is EFI_CERT_STACK type.
  @param[out] UnchainLength     Length of the unchained certificates list buffer in bytes.

  @retval  TRUE         The operation is finished successfully.
  @retval  FALSE        Error occurs during the operation.

**/
BOOLEAN
EFIAPI
Pkcs7GetCertificatesList (
  IN  CONST UINT8  *P7Data,
  IN  UINTN        P7Length,
  OUT UINT8        **SignerChainCerts,
  OUT UINTN        *ChainLength,
  OUT UINT8        **UnchainCerts,
  OUT UINTN        *UnchainLength
  )
{
  BOOLEAN         Status;
  UINT8           *NewP7Data;
  CONST UINT8     *Temp;        // MU_CHANGE
  UINTN           NewP7Length;
  BOOLEAN         Wrapped;
  UINT8           Index;
  PKCS7           *Pkcs7;
  X509_STORE_CTX  *CertCtx;

  STACK_OF (X509)   *CtxChain;
  STACK_OF (X509)   *CtxUntrusted;
  X509  *CtxCert;

  STACK_OF (X509)   *Signers;
  X509             *Signer;
  X509             *Cert;
  X509             *Issuer;
  CONST X509_NAME  *IssuerName;
  UINT8            *CertBuf;
  UINT8            *OldBuf;
  UINTN            BufferSize;
  UINTN            OldSize;
  UINT8            *SingleCert;
  UINTN            CertSize;

  //
  // Initializations
  //
  Status       = FALSE;
  NewP7Data    = NULL;
  Pkcs7        = NULL;
  CertCtx      = NULL;
  CtxChain     = NULL;
  CtxCert      = NULL;
  CtxUntrusted = NULL;
  Cert         = NULL;
  SingleCert   = NULL;
  CertBuf      = NULL;
  OldBuf       = NULL;
  Signers      = NULL;

  //
  // Parameter Checking
  //
  if ((P7Data == NULL) || (SignerChainCerts == NULL) || (ChainLength == NULL) ||
      (UnchainCerts == NULL) || (UnchainLength == NULL) || (P7Length > INT_MAX))
  {
    return Status;
  }

  *SignerChainCerts = NULL;
  *ChainLength      = 0;
  *UnchainCerts     = NULL;
  *UnchainLength    = 0;

  //
  // Construct a new PKCS#7 data wrapping with ContentInfo structure if needed.
  //
  Status = WrapPkcs7Data (P7Data, P7Length, &Wrapped, &NewP7Data, &NewP7Length);
  if (!Status || (NewP7Length > INT_MAX)) {
    goto _Error;
  }

  //
  // Decodes PKCS#7 SignedData
  //
  // MU_CHANGE [BEGIN]
  Temp  = NewP7Data;
  Pkcs7 = d2i_PKCS7 (NULL, (const unsigned char **)&Temp, (int)NewP7Length);
  // MU_CHANGE [END]
  if ((Pkcs7 == NULL) || (!PKCS7_type_is_signed (Pkcs7))) {
    goto _Error;
  }

  //
  // Obtains Signer's Certificate from PKCS#7 data
  // NOTE: Only one signer case will be handled in this function, which means SignerInfos
  //       should include only one signer's certificate.
  //
  Signers = PKCS7_get0_signers (Pkcs7, NULL, PKCS7_BINARY);
  if ((Signers == NULL) || (sk_X509_num (Signers) != 1)) {
    goto _Error;
  }

  Signer = sk_X509_value (Signers, 0);

  CertCtx = X509_STORE_CTX_new ();
  if (CertCtx == NULL) {
    goto _Error;
  }

  if (!X509_STORE_CTX_init (CertCtx, NULL, Signer, Pkcs7->d.sign->cert)) {
    goto _Error;
  }

  //
  // Initialize Chained & Untrusted stack
  //
  CtxChain = X509_STORE_CTX_get0_chain (CertCtx);
  CtxCert  = X509_STORE_CTX_get0_cert (CertCtx);
  if (CtxChain == NULL) {
    if (((CtxChain = sk_X509_new_null ()) == NULL) ||
        (!sk_X509_push (CtxChain, CtxCert)))
    {
      goto _Error;
    }
  }

  CtxUntrusted = X509_STORE_CTX_get0_untrusted (CertCtx);
  if (CtxUntrusted != NULL) {
    (VOID)sk_X509_delete_ptr (CtxUntrusted, Signer);
  }

  //
  // Build certificates stack chained from Signer's certificate.
  //
  Cert = Signer;
  for ( ; ;) {
    //
    // Self-Issue checking
    //
    Issuer = NULL;
    if (X509_STORE_CTX_get1_issuer (&Issuer, CertCtx, Cert) == 1) {
      if (X509_cmp (Issuer, Cert) == 0) {
        break;
      }
    }

    //
    // Found the issuer of the current certificate
    //
    if (CtxUntrusted != NULL) {
      Issuer     = NULL;
      IssuerName = X509_get_issuer_name (Cert);
      Issuer     = X509_find_by_subject (CtxUntrusted, IssuerName);
      if (Issuer != NULL) {
        if (!sk_X509_push (CtxChain, Issuer)) {
          goto _Error;
        }

        (VOID)sk_X509_delete_ptr (CtxUntrusted, Issuer);

        Cert = Issuer;
        continue;
      }
    }

    break;
  }

  //
  // Converts Chained and Untrusted Certificate to Certificate Buffer in following format:
  //      UINT8  CertNumber;
  //      UINT32 Cert1Length;
  //      UINT8  Cert1[];
  //      UINT32 Cert2Length;
  //      UINT8  Cert2[];
  //      ...
  //      UINT32 CertnLength;
  //      UINT8  Certn[];
  //

  if (CtxChain != NULL) {
    BufferSize = sizeof (UINT8);
    CertBuf    = NULL;

    for (Index = 0; ; Index++) {
      Status = X509PopCertificate (CtxChain, &SingleCert, &CertSize);
      if (!Status) {
        break;
      }

      OldSize    = BufferSize;
      OldBuf     = CertBuf;
      BufferSize = OldSize + CertSize + sizeof (UINT32);
      CertBuf    = malloc (BufferSize);

      if (CertBuf == NULL) {
        Status = FALSE;
        goto _Error;
      }

      if (OldBuf != NULL) {
        CopyMem (CertBuf, OldBuf, OldSize);
        free (OldBuf);
        OldBuf = NULL;
      }

      WriteUnaligned32 ((UINT32 *)(CertBuf + OldSize), (UINT32)CertSize);
      CopyMem (CertBuf + OldSize + sizeof (UINT32), SingleCert, CertSize);

      free (SingleCert);
      SingleCert = NULL;
    }

    if (CertBuf != NULL) {
      //
      // Update CertNumber.
      //
      CertBuf[0] = Index;

      *SignerChainCerts = CertBuf;
      *ChainLength      = BufferSize;
    }
  }

  if (CtxUntrusted != NULL) {
    BufferSize = sizeof (UINT8);
    CertBuf    = NULL;

    for (Index = 0; ; Index++) {
      Status = X509PopCertificate (CtxUntrusted, &SingleCert, &CertSize);
      if (!Status) {
        break;
      }

      OldSize    = BufferSize;
      OldBuf     = CertBuf;
      BufferSize = OldSize + CertSize + sizeof (UINT32);
      CertBuf    = malloc (BufferSize);

      if (CertBuf == NULL) {
        Status = FALSE;
        goto _Error;
      }

      if (OldBuf != NULL) {
        CopyMem (CertBuf, OldBuf, OldSize);
        free (OldBuf);
        OldBuf = NULL;
      }

      WriteUnaligned32 ((UINT32 *)(CertBuf + OldSize), (UINT32)CertSize);
      CopyMem (CertBuf + OldSize + sizeof (UINT32), SingleCert, CertSize);

      free (SingleCert);
      SingleCert = NULL;
    }

    if (CertBuf != NULL) {
      //
      // Update CertNumber.
      //
      CertBuf[0] = Index;

      *UnchainCerts  = CertBuf;
      *UnchainLength = BufferSize;
    }
  }

  Status = TRUE;

_Error:
  //
  // Release Resources.
  //
  if (!Wrapped && (NewP7Data != NULL)) {
    free (NewP7Data);
  }

  if (Pkcs7 != NULL) {
    PKCS7_free (Pkcs7);
  }

  sk_X509_free (Signers);

  if (CertCtx != NULL) {
    X509_STORE_CTX_cleanup (CertCtx);
    X509_STORE_CTX_free (CertCtx);
  }

  if (SingleCert != NULL) {
    free (SingleCert);
  }

  if (OldBuf != NULL) {
    free (OldBuf);
  }

  if (!Status && (CertBuf != NULL)) {
    free (CertBuf);
    *SignerChainCerts = NULL;
    *UnchainCerts     = NULL;
  }

  return Status;
}

//
// Per-verification chain capture used by CmsVerify (on behalf of Authenticode).
// The capture context lives on the caller's stack and is attached to the
// X509_STORE via ex_data, so nested or concurrent verifications never
// share mutable state. The verify callback OBSERVES (never alters) the
// verification and, on success, records the chain OpenSSL built in its
// X509_STORE_CTX. CMS_verify drives certificate-chain construction through
// the same X509_STORE / X509_STORE_CTX as the legacy PKCS7 path, so the
// callback fires identically here.
//
// The ex_data *index* below is process-global and immutable once allocated
// (the standard OpenSSL idiom); it is not per-call state.
//
typedef struct {
  STACK_OF (X509)  *Chain;   // captured verified chain (signer..anchor), owned
} CMS_CHAIN_CAPTURE;

STATIC int  mChainCaptureIndex = -1;

/**
  X509_STORE verify callback that captures the built signer chain at the
  end-entity (depth 0) once verification has succeeded. The capture slot is
  retrieved from the store's ex_data. Returns Ok unchanged so it does not
  affect the verification verdict.
**/
STATIC
int
CmsChainCaptureCb (
  int             Ok,
  X509_STORE_CTX  *Ctx
  )
{
  X509_STORE         *Store;
  CMS_CHAIN_CAPTURE  *Capture;

  if (Ok && (mChainCaptureIndex >= 0) &&
      (X509_STORE_CTX_get_error_depth (Ctx) == 0))
  {
    Store = X509_STORE_CTX_get0_store (Ctx);
    if (Store != NULL) {
      Capture = X509_STORE_get_ex_data (Store, mChainCaptureIndex);
      if ((Capture != NULL) && (Capture->Chain == NULL)) {
        //
        // get1_chain returns an up-ref'd copy owned by us.
        //
        Capture->Chain = X509_STORE_CTX_get1_chain (Ctx);
      }
    }
  }

  return Ok;
}

/**
  Serialize an OpenSSL STACK_OF(X509) chain (ordered signer..anchor) into
  the EFI_CERT_STACK form:
    UINT8  CertNumber;
    { UINT32 CertLength; UINT8 Cert[]; } x CertNumber

  @param[in]   Chain          The verified chain (leaf at index 0).
  @param[out]  CertStack      Newly allocated EFI_CERT_STACK; caller frees.
  @param[out]  CertStackSize  Length of CertStack in bytes.

  @retval EFI_SUCCESS            Serialized.
  @retval EFI_NOT_FOUND          Empty chain / too many certs.
  @retval EFI_INVALID_PARAMETER  A certificate failed to encode.
  @retval EFI_OUT_OF_RESOURCES   Allocation failed.
**/
STATIC
EFI_STATUS
SerializeSignerChain (
  IN  STACK_OF (X509)  *Chain,
  OUT UINT8            **CertStack,
  OUT UINTN            *CertStackSize
  )
{
  int            Count;
  int            Index;
  int            DerLen;
  int            Written;
  UINTN          TotalSize;
  UINT8          *Buffer;
  UINT8          *Cursor;
  unsigned char  *P;

  Count = sk_X509_num (Chain);
  if ((Count <= 0) || (Count > MAX_UINT8)) {
    return EFI_NOT_FOUND;
  }

  TotalSize = sizeof (UINT8);
  for (Index = 0; Index < Count; Index++) {
    DerLen = i2d_X509 (sk_X509_value (Chain, Index), NULL);
    if (DerLen <= 0) {
      return EFI_INVALID_PARAMETER;
    }

    TotalSize += sizeof (UINT32) + (UINTN)DerLen;
  }

  Buffer = AllocatePool (TotalSize);
  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Cursor    = Buffer;
  *Cursor++ = (UINT8)Count;
  for (Index = 0; Index < Count; Index++) {
    DerLen = i2d_X509 (sk_X509_value (Chain, Index), NULL);
    WriteUnaligned32 ((UINT32 *)Cursor, (UINT32)DerLen);
    Cursor += sizeof (UINT32);
    P       = Cursor;
    Written = i2d_X509 (sk_X509_value (Chain, Index), &P);
    if (Written != DerLen) {
      //
      // The sizing and encode passes must agree; a mismatch means the
      // buffer layout is inconsistent, so fail rather than emit a
      // malformed EFI_CERT_STACK.
      //
      FreePool (Buffer);
      return EFI_INVALID_PARAMETER;
    }

    Cursor += DerLen;
  }

  *CertStack     = Buffer;
  *CertStackSize = TotalSize;
  return EFI_SUCCESS;
}

/**
  Verifies a PKCS#7/CMS SignedData structure and, when requested, returns
  the signer's cryptographically-verified certificate chain.

  Verification is performed with OpenSSL's CMS_verify so the signature
  algorithm is dispatched through the EVP provider framework (RSA, ECDSA,
  Ed25519, ML-DSA, and future provider algorithms). PKCS#7 SignedData is a
  strict subset of CMS (RFC 5652), so this single routine backs both the
  legacy Pkcs7Verify() entry point and the Authenticode verifier.

  When SignerChain and SignerChainSize are both supplied, an observe-only
  X509_STORE verify callback records the chain OpenSSL builds and, on
  success, it is trimmed to signer..anchor and serialized into
  EFI_CERT_STACK form so a caller can run per-certificate revocation (dbx)
  checks without a second, redundant chain-building pass. Callers that do
  not request the chain pay nothing for the capture.

  If P7Data, TrustedCert or InData is NULL, then return FALSE.
  If P7Length, CertLength or DataLength overflow, then return FALSE.

  Caution: This function may receive untrusted input.
  UEFI Authenticated Variable is external input, so this function will do basic
  check for data structure.

  @param[in]   P7Data          PKCS#7/CMS message to verify.
  @param[in]   P7Length        Length of P7Data in bytes.
  @param[in]   TrustedCert     DER trust anchor for chain verification.
  @param[in]   CertLength      Length of TrustedCert in bytes.
  @param[in]   InData          Content to verify.
  @param[in]   DataLength      Length of InData in bytes.
  @param[out]  SignerChain     Optional. If non-NULL (with SignerChainSize)
                               and verification succeeds, receives a newly
                               allocated EFI_CERT_STACK (signer..anchor);
                               caller frees.
  @param[out]  SignerChainSize Optional. Length of SignerChain in bytes.

  @retval  TRUE  The specified PKCS#7/CMS signed data is valid.
  @retval  FALSE Invalid PKCS#7/CMS signed data.

**/
BOOLEAN
EFIAPI
CmsVerify (
  IN  CONST UINT8  *P7Data,
  IN  UINTN        P7Length,
  IN  CONST UINT8  *TrustedCert,
  IN  UINTN        CertLength,
  IN  CONST UINT8  *InData,
  IN  UINTN        DataLength,
  OUT UINT8        **SignerChain      OPTIONAL,
  OUT UINTN        *SignerChainSize   OPTIONAL
  )
{
  CMS_ContentInfo    *Cms;
  BIO                *DataBio;
  BOOLEAN            Status;
  X509               *Cert;
  X509_STORE         *CertStore;
  UINT8              *SignedData;
  CONST UINT8        *Temp;
  UINTN              SignedDataSize;
  BOOLEAN            Wrapped;
  int                ChainCount;
  int                ChainIndex;
  BOOLEAN            WantChain;
  CMS_CHAIN_CAPTURE  Capture;

  if (SignerChain != NULL) {
    *SignerChain = NULL;
  }

  if (SignerChainSize != NULL) {
    *SignerChainSize = 0;
  }

  //
  // Only capture the chain when the caller actually wants it (both out-params
  // present). Capturing is not free - it dups the built chain via
  // X509_STORE_CTX_get1_chain() and trims it - so Pkcs7Verify() and other
  // verdict-only callers pay nothing for it.
  //
  WantChain     = (BOOLEAN)((SignerChain != NULL) && (SignerChainSize != NULL));
  Capture.Chain = NULL;

  //
  // Check input parameters.
  //
  if ((P7Data == NULL) || (TrustedCert == NULL) || (InData == NULL) ||
      (P7Length > INT_MAX) || (CertLength > INT_MAX) || (DataLength > INT_MAX))
  {
    return FALSE;
  }

  Cms       = NULL;
  DataBio   = NULL;
  Cert      = NULL;
  CertStore = NULL;

  //
  // No manual digest registration is required in OpenSSL 3.x+.  Under the
  // EVP provider framework, EVP_get_digestbyname()/EVP_get_digestbynid()
  // (which is what CMS_verify uses internally to resolve a signer's digest
  // OID to an EVP_MD) invokes OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_-
  // DIGESTS, NULL) on first use.  That in turn lazily populates the legacy
  // OBJ_NAME table via openssl_add_all_digests_int() with the full SHA-1 /
  // SHA-2 family that the default provider exposes.  The legacy alias for
  // "1.3.14.3.2.29" (sha1WithRSAEncryption / id-sha1-with-rsa-signature)
  // is likewise resolved through the provider's algorithm tables, so no
  // EVP_add_digest_alias() registration is required either.
  //

  Status = WrapPkcs7Data (P7Data, P7Length, &Wrapped, &SignedData, &SignedDataSize);
  if (!Status) {
    return Status;
  }

  Status = FALSE;

  //
  // Validate SignedData size.
  //
  if (SignedDataSize > INT_MAX) {
    goto _Exit;
  }

  //
  // Read DER-encoded root certificate and Construct X509 Certificate
  //
  Temp = TrustedCert;
  Cert = d2i_X509 (NULL, &Temp, (long)CertLength);
  if (Cert == NULL) {
    goto _Exit;
  }

  //
  // Setup X509 Store for trusted certificate
  //
  CertStore = X509_STORE_new ();
  if (CertStore == NULL) {
    goto _Exit;
  }

  if (!(X509_STORE_add_cert (CertStore, Cert))) {
    goto _Exit;
  }

  //
  // Allow partial certificate chains, terminated by a non-self-signed but
  // still trusted intermediate certificate. Also disable time checks.
  //
  X509_STORE_set_flags (
    CertStore,
    X509_V_FLAG_PARTIAL_CHAIN | X509_V_FLAG_NO_CHECK_TIME
    );

  //
  // Bypass the certificate purpose checking by enabling any purposes setting.
  //
  X509_STORE_set_purpose (CertStore, X509_PURPOSE_ANY);

  //
  // When the caller asked for the signer chain, attach the per-store capture
  // context and an observe-only callback that records the chain OpenSSL
  // builds. It does not change the verification result.
  //
  if (WantChain) {
    if (mChainCaptureIndex < 0) {
      mChainCaptureIndex = X509_STORE_get_ex_new_index (0, NULL, NULL, NULL, NULL);
    }

    if (mChainCaptureIndex >= 0) {
      X509_STORE_set_ex_data (CertStore, mChainCaptureIndex, &Capture);
      X509_STORE_set_verify_cb (CertStore, CmsChainCaptureCb);
    }
  }

  //
  // Parse the signed data as CMS ContentInfo. CMS is the successor to PKCS#7
  // and is backward-compatible at the ASN.1 level. Using CMS_verify provides
  // crypto-agile signature verification supporting RSA, ECDSA, Ed25519,
  // ML-DSA, and future algorithms through the OpenSSL EVP provider framework.
  //
  Temp = SignedData;
  Cms  = d2i_CMS_ContentInfo (NULL, (const unsigned char **)&Temp, (long)SignedDataSize);
  if (Cms == NULL) {
    goto _Exit;
  }

  //
  // Require the parsed CMS ContentInfo to be of type id-signedData.  Other
  // CMS content types (envelopedData, digestedData, encryptedData, etc.) are
  // not meaningful inputs to this verification path and CMS_verify's
  // behavior on them is unspecified - reject explicitly so a malformed or
  // misclassified blob cannot reach the verification engine.
  //
  if (OBJ_obj2nid (CMS_get0_type (Cms)) != NID_pkcs7_signed) {
    goto _Exit;
  }

  //
  // Pkcs7Verify rejected NULL InData at function entry: this routine treats
  // the supplied (InData, DataLength) as the detached content that the
  // signedAttributes.messageDigest covers.  CMS_verify is invoked without
  // CMS_NO_CONTENT_VERIFY, so the message digest of these bytes must match
  // the signed messageDigest attribute or verification fails.
  //
  DataBio = BIO_new_mem_buf (InData, (int)DataLength);
  if (DataBio == NULL) {
    goto _Exit;
  }

  //
  // Verify the CMS signed data structure.
  //
  Status = (BOOLEAN)CMS_verify (
                      Cms,
                      NULL,
                      CertStore,
                      DataBio,
                      NULL,
                      CMS_BINARY
                      );
  if (!Status) {
    //
    // Drain OpenSSL's per-thread error queue so a later, unrelated call
    // into libcrypto does not see (and potentially act on) stale errors
    // left over from this failure.
    //
    DEBUG ((DEBUG_ERROR, "CMS_verify failed: 0x%lx\n", ERR_peek_last_error ()));
    ERR_clear_error ();
  }

  //
  // Trim the captured chain to the trust path: the image signer up to and
  // including the trust anchor. Under X509_V_FLAG_PARTIAL_CHAIN, OpenSSL may
  // extend the built chain past the anchor using the message's embedded
  // certificates (for example when the anchor is the signer itself).
  //
  // Fast path for the common case (anchor is the topmost certificate, so the
  // chain already ends at it): a pointer compare - get1_chain up-refs the
  // trust store's own object, so the top entry IS Cert - confirmed by
  // X509_cmp. Only when the anchor sits below the top do we walk the chain to
  // find it and drop the certificates above it.
  //
  if (Status && WantChain && (Capture.Chain != NULL)) {
    ChainCount = sk_X509_num (Capture.Chain);
    if ((ChainCount > 1) &&
        (sk_X509_value (Capture.Chain, ChainCount - 1) != Cert) &&
        (X509_cmp (sk_X509_value (Capture.Chain, ChainCount - 1), Cert) != 0))
    {
      for (ChainIndex = 0; ChainIndex < ChainCount - 1; ChainIndex++) {
        if (X509_cmp (sk_X509_value (Capture.Chain, ChainIndex), Cert) == 0) {
          while (sk_X509_num (Capture.Chain) > (ChainIndex + 1)) {
            X509_free (sk_X509_pop (Capture.Chain));
          }

          break;
        }
      }
    }

    //
    // Serialize the trimmed chain into EFI_CERT_STACK form for the caller.
    // Best-effort: if serialization fails the verify verdict still stands;
    // the caller simply gets no chain and can fall back.
    //
    SerializeSignerChain (Capture.Chain, SignerChain, SignerChainSize);
  }

_Exit:
  //
  // Release Resources
  //
  BIO_free (DataBio);
  X509_free (Cert);
  X509_STORE_free (CertStore);
  CMS_ContentInfo_free (Cms);

  if (Capture.Chain != NULL) {
    sk_X509_pop_free (Capture.Chain, X509_free);
  }

  if (!Wrapped) {
    OPENSSL_free (SignedData);
  }

  return Status;
}

/**
  Verifies the validity of a PKCS#7/CMS signed data structure.

  Pkcs7Verify() is retained for API compatibility. PKCS#7 SignedData is a
  strict subset of CMS (RFC 5652), so verification is delegated to
  CmsVerify(), which dispatches the signature algorithm through OpenSSL's
  crypto-agile CMS_verify path (RSA, ECDSA, Ed25519, ML-DSA, and future
  provider algorithms). Callers that also need the verified signer chain
  should call CmsVerify() directly.

  If P7Data, TrustedCert or InData is NULL, then return FALSE.
  If P7Length, CertLength or DataLength overflow, then return FALSE.

  Caution: This function may receive untrusted input.
  UEFI Authenticated Variable is external input, so this function will do basic
  check for data structure.

  @param[in]  P7Data       Pointer to the PKCS#7/CMS message to verify.
  @param[in]  P7Length     Length of the PKCS#7/CMS message in bytes.
  @param[in]  TrustedCert  Pointer to a trusted/root certificate encoded in DER, which
                           is used for certificate chain verification.
  @param[in]  CertLength   Length of the trusted certificate in bytes.
  @param[in]  InData       Pointer to the content to be verified.
  @param[in]  DataLength   Length of InData in bytes.

  @retval  TRUE  The specified PKCS#7/CMS signed data is valid.
  @retval  FALSE Invalid PKCS#7/CMS signed data.

**/
BOOLEAN
EFIAPI
Pkcs7Verify (
  IN  CONST UINT8  *P7Data,
  IN  UINTN        P7Length,
  IN  CONST UINT8  *TrustedCert,
  IN  UINTN        CertLength,
  IN  CONST UINT8  *InData,
  IN  UINTN        DataLength
  )
{
  return CmsVerify (P7Data, P7Length, TrustedCert, CertLength, InData, DataLength, NULL, NULL);
}
