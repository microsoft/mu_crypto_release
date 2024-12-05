#include "SharedOpenssl.h"

#include <Uefi.h>

/**
 * Initializes the cryptographic library by setting up function tables for various cryptographic operations.
 *
 * @param[in] Crypto  Pointer to the SHARED_CRYPTO_LIB structure that will be initialized.
 *
 * This function initializes the following cryptographic function tables:
 * - BigNumFunctionsTable: Functions for big number operations.
 * - AeadAesGcmFunctionsTable: Functions for AEAD AES-GCM operations.
 * - AesFunctionsTable: Functions for AES operations.
 * - HashFunctionsTable: Functions for hash operations.
 * - HmacFunctionsTable: Functions for HMAC operations.
 */
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