#ifndef CRYPT_PK_H_
#define CRYPT_PK_H_

#include <Uefi.h>
#include <CrtLibSupport.h>
#include "Shared/SharedCryptoProtocol.h"

// Internal functions

// TODO Where should these be defined? IndustryStandard.h?
#define SHA1_DIGEST_SIZE    20
#define SHA256_DIGEST_SIZE  32
#define SHA384_DIGEST_SIZE  48
#define SHA512_DIGEST_SIZE  64

/**
  Verifies the validity of a PKCS#7 signed data as described in "PKCS #7:
  Cryptographic Message Syntax Standard". The input signed data could be wrapped
  in a ContentInfo structure.

  If P7Data, TrustedCert or InData is NULL, then return FALSE.
  If P7Length, CertLength or DataLength overflow, then return FALSE.

  Caution: This function may receive untrusted input.
  UEFI Authenticated Variable is external input, so this function will do basic
  check for PKCS#7 data structure.

  @param[in]  P7Data       Pointer to the PKCS#7 message to verify.
  @param[in]  P7Length     Length of the PKCS#7 message in bytes.
  @param[in]  TrustedCert  Pointer to a trusted/root certificate encoded in DER, which
                           is used for certificate chain verification.
  @param[in]  CertLength   Length of the trusted certificate in bytes.
  @param[in]  InData       Pointer to the content to be verified.
  @param[in]  DataLength   Length of InData in bytes.

  @retval  TRUE  The specified PKCS#7 signed data is valid.
  @retval  FALSE Invalid PKCS#7 signed data.

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
  );

/**
    Installs PKCS#7 functions into the shared crypto protocol.

    @param[out]  Crypto  Pointer to the shared crypto protocol.

**/
VOID
EFIAPI
AuthenticodeInstallFunctions (
  OUT SHARED_CRYPTO_PROTOCOL  *Crypto
  );

/**
  Installs Diffie-Hellman functions into the shared crypto protocol.

  @param[out]  Crypto  Pointer to the shared crypto protocol.

**/
VOID
EFIAPI
DhInstallFunctions (
  OUT SHARED_CRYPTO_PROTOCOL  *Crypto
  );

/**
  Installs PKCS#5 PBKDF2 functions into the shared crypto protocol.

  @param[out]  Crypto  Pointer to the shared crypto protocol.

/**
  Installs PKCS1v2 (RSAES-OAEP) encryption/decryption functions into the shared crypto protocol.

  @param[out]  Crypto  Pointer to the shared crypto protocol.

**/
VOID
EFIAPI
Pkcs1v2InstallFunctions (
  OUT SHARED_CRYPTO_PROTOCOL  *Crypto
  );


/**
  Installs PKCS#5 PBKDF2 functions into the shared crypto protocol.

  @param[out]  Crypto  Pointer to the shared crypto protocol.

**/
VOID
EFIAPI
Pkcs5InstallFunctions (
  OUT SHARED_CRYPTO_PROTOCOL  *Crypto
  );

VOID
EFIAPI
PkInstallFunctions (
  OUT SHARED_CRYPTO_PROTOCOL  *Crypto
  );

#endif // CRYPT_PEM_H_
