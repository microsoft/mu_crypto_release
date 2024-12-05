#ifndef SHARED_OPENSSL_H_
#define SHARED_OPENSSL_H_

#include <Uefi.h>
#include "BN/CryptBn.h"
#include "Cipher/CryptAeadAesGcm.h"
#include "Cipher/CryptAes.h"
#include "Hash/CryptHash.h"


/**
  Structure that holds the function tables for various cryptographic operations.

  @param BigNumFunctionsTable    Function table for Big Number operations.
  @param AeadAesGcmFunctionsTable Function table for AEAD AES-GCM operations.
  @param AesFunctionsTable       Function table for AES operations.
  @param HashFunctionsTable      Function table for hash operations, including MD5, SHA-1, SHA-256, SHA-384, and SHA-512.
**/
typedef struct {
    BigNumFunctions BigNumFunctionsTable;
    AeadAesGcmFunctions AeadAesGcmFunctionsTable;
    AesFunctions AesFunctionsTable;
    HashFunctions HashFunctionsTable;
} SHARED_CRYPTO_LIB;

VOID
EFIAPI
CryptoInit (
    SHARED_CRYPTO_LIB *Crypto
);

#endif // SHARED_OPENSSL_H_