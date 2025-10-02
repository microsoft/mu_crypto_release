#ifndef SHARED_OPENSSL_H_
#define SHARED_OPENSSL_H_

#include <Uefi.h>
#include "CrtLibSupport.h"
#include "Protocol/SharedCryptoProtocol.h"

/**
  Initializes the shared cryptography subsystem.

  This function initializes the cryptographic services based on the requested
  protocol configuration. It sets up the necessary OpenSSL components and
  prepares the shared cryptography environment for subsequent operations.

  @param[in] RequestedCrypto  Pointer to the shared crypto protocol interface
                              containing configuration and function pointers
                              to be initialized.

  @return None
**/
VOID
EFIAPI
CryptoInit (
  SHARED_CRYPTO_PROTOCOL  *RequestedCrypto
  );

/**
  Gets the OpenSSL version information.

  @return  Pointer to OpenSSL version string.
**/
CONST CHAR8 *
EFIAPI
GetOpenSslVersionText (
  VOID
  );

/**
  Gets the OpenSSL version number.

  @return  OpenSSL version number.
**/
UINTN
EFIAPI
GetOpenSslVersionNumber (
  VOID
  );
  
#endif // SHARED_OPENSSL_H_
