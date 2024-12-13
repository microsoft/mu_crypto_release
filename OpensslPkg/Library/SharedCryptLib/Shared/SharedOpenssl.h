#ifndef SHARED_OPENSSL_H_
#define SHARED_OPENSSL_H_

#include <Uefi.h>
#include "CrtLibSupport.h"
#include "SharedCryptoProtocol.h"

VOID
EFIAPI
CryptoInit (
  SHARED_CRYPTO_PROTOCOL  *RequestedCrypto
  );

#endif // SHARED_OPENSSL_H_
