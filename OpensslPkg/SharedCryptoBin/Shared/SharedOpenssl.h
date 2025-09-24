#ifndef SHARED_OPENSSL_H_
#define SHARED_OPENSSL_H_

#include <Uefi.h>
#include "CrtLibSupport.h"
#include "Protocol/SharedCryptoProtocol.h"

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
