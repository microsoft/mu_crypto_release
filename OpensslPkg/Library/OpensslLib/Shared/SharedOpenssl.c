#include "SharedOpenssl.h"

#include <Uefi.h>

VOID
EFIAPI
CryptoInit (
    SHARED_CRYPTO_LIB *Crypto
) {
    BigNumInitFunctions(&Crypto->BigNumFunctions);
    AeadAesGcmInitFunctions(&Crypto->AeadAesGcmFunctions);
    AesInitFunctions(&Crypto->AesFunctions);
}