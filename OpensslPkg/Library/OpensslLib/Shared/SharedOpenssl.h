#ifndef SHARED_OPENSSL_H_
#define SHARED_OPENSSL_H_

#include <Uefi.h>
#include "BN/CryptBn.h"
#include "Cipher/CryptAeadAesGcm.h"
#include "Cipher/CryptAes.h"

typedef struct {
    BigNumFunctions BigNumFunctions;
    AeadAesGcmFunctions AeadAesGcmFunctions;
    AesFunctions AesFunctions;
} SHARED_CRYPTO_LIB;

VOID
EFIAPI
CryptoInit (
    SHARED_CRYPTO_LIB *Crypto
);

#endif // SHARED_OPENSSL_H_