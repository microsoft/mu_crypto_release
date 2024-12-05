#include "SharedOpenssl.h"

#include <Uefi.h>

VOID
EFIAPI
CryptoInit (
    SHARED_CRYPTO_LIB *Crypto
) {
    BigNumInitFunctions(&Crypto->BigNumFunctionsTable);
    AeadAesGcmInitFunctions(&Crypto->AeadAesGcmFunctionsTable);
    AesInitFunctions(&Crypto->AesFunctionsTable);
    HashInitFunctions(&Crypto->HashFunctionsTable);
}