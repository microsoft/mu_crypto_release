#include "SharedOpenssl.h"
#include "Hmac/CryptHmac.h"
#include "Hash/CryptHash.h"
#include "BN/CryptBn.h"
#include "Kdf/CryptHkdf.h"
#include "Cipher/CryptCipher.h"
#include "Pem/CryptPem.h"
#include <Uefi.h>

UINT64
EFIAPI
GetVersion (
  VOID
  )
{
  return SHARED_CRYPTO_VERSION;
}

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
  SHARED_CRYPTO_PROTOCOL  *Crypto
  )
{
  //
  // Set the Crypto Version
  //
  Crypto->GetVersion = GetVersion;
  //
  // Begin filling out the crypto protocol
  //
  HmacInitFunctions (Crypto);
  BigNumInitFunctions(Crypto);
  AeadAesGcmInitFunctions(Crypto);
  AesInitFunctions(Crypto);
  HashInitFunctions (Crypto);
  HkdfInstallFunctions(Crypto);
  PemInstallFunctions(Crypto);
}
