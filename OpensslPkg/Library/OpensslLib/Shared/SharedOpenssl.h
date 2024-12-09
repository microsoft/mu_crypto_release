#ifndef SHARED_OPENSSL_H_
#define SHARED_OPENSSL_H_

#include <Uefi.h>
#include "Shared/SharedCryptoProtocol.h"


VOID
EFIAPI
CryptoInit (
  SHARED_CRYPTO_PROTOCOL  *Crypto
  );

#endif // SHARED_OPENSSL_H_
