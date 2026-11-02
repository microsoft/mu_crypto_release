/** @file
  Authenticode Portable Executable Signature Verification which does not provide
  real capabilities.

Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"

/**
  Verifies the validity of a PE/COFF Authenticode Signature as described in "Windows
  Authenticode Portable Executable Signature Format".

  Return FALSE to indicate this interface is not supported.

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

  @retval FALSE  This interface is not supported.

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
  ASSERT (FALSE);
  return FALSE;
}

/**
  Verifies a PE/COFF Authenticode Signature and optionally returns the
  verified signer chain.

  Return EFI_UNSUPPORTED to indicate this interface is not supported.

  @param[in]   AuthData       Authenticode signature.
  @param[in]   DataSize       Size of AuthData in bytes.
  @param[in]   TrustedCert    DER trust anchor.
  @param[in]   CertSize       Size of TrustedCert in bytes.
  @param[in]   ImageHash      Precomputed Authenticode image hash.
  @param[in]   HashSize       Size of ImageHash in bytes.
  @param[out]  CertChain      Optional EFI_CERT_STACK output.
  @param[out]  CertChainSize  Optional length of CertChain.

  @retval EFI_UNSUPPORTED  This interface is not supported.
**/
EFI_STATUS
EFIAPI
AuthenticodeVerifyEx (
  IN  CONST UINT8  *AuthData,
  IN  UINTN        DataSize,
  IN  CONST UINT8  *TrustedCert,
  IN  UINTN        CertSize,
  IN  CONST UINT8  *ImageHash,
  IN  UINTN        HashSize,
  OUT UINT8        **CertChain      OPTIONAL,
  OUT UINTN        *CertChainSize   OPTIONAL
  )
{
  ASSERT (FALSE);

  if (CertChain != NULL) {
    *CertChain = NULL;
  }

  if (CertChainSize != NULL) {
    *CertChainSize = 0;
  }

  return EFI_UNSUPPORTED;
}
