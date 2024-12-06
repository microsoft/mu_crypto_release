#ifndef CRYPT_CIPHER_H_
#define CRYPT_CIPHER_H_

#include <Uefi.h>
#include "CrtLibSupport.h"
#include "SharedCryptoProtocol.h"

VOID
EFIAPI
AesInitFunctions (
  OUT SHARED_CRYPTO_PROTOCOL *Crypto
  );

VOID
EFIAPI
AeadAesGcmInitFunctions (
  OUT SHARED_CRYPTO_PROTOCOL *Crypto
  );

#endif // CRYPT_CIPHER_H_
