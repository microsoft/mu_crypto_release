#ifndef CRYPT_BN_H_
#define CRYPT_BN_H_

#include <Uefi.h>
#include "SharedCryptoProtocol.h"

VOID
EFIAPI
BigNumInitFunctions (
  OUT SHARED_CRYPTO_PROTOCOL  *Crypto
  );

#endif // CRYPT_BN_H_
