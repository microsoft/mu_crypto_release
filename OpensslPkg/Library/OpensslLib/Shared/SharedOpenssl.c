#include "SharedOpenssl.h"
#include "Hmac/CryptHmac.h"
#include "Hash/CryptHash.h"
#include "BN/CryptBn.h"
#include "Kdf/CryptHkdf.h"
#include "Cipher/CryptCipher.h"
#include "Pem/CryptPem.h"
#include "Pk/CryptPk.h"
#include <Uefi.h>

UINT64
EFIAPI
GetVersion (
  VOID
  )
{
  return PACK_VERSION (VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION);
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
  if (Crypto == NULL) {
    // TODO ASSERT
    return;
  }

  //
  // The Caller should provide a GetVersion function that returns the version that the caller is expecting.
  // and this function should use that to ensure that the crypto functionality is compatible with the caller.
  //
  UINT16  Major;
  UINT16  Minor;
  UINT16  Revision;

  UNPACK_VERSION (Crypto->GetVersion (), Major, Minor, Revision);

  //
  // If the Major version is different, then the caller is expecting a different version of the protocol.
  // If this does not match, then this request is not compatible with the provided crypto functions.
  //
  if (Major != VERSION_MAJOR) {
    // TODO ASSERT
    return;
  }

  //
  // If the Minor version is greater than the current version, then the caller is expecting a newer version of the protocol.
  // If this does not match, then this request is not compatible with the provided crypto functions.
  //
  if (Minor >= VERSION_MINOR) {
    // TODO ASSERT
    return;
  }

  //
  // Set the Crypto Version
  //
  Crypto->GetVersion = GetVersion;

  //
  // Begin filling out the crypto protocol
  //
  // TODO Ensure that we set only the function pointers requested by the caller
  //
  HmacInitFunctions (Crypto);
  BigNumInitFunctions (Crypto);
  AeadAesGcmInitFunctions (Crypto);
  AesInitFunctions (Crypto);
  HashInitFunctions (Crypto);
  HkdfInstallFunctions (Crypto);
  PemInstallFunctions (Crypto);
  PkInstallFunctions (Crypto);
}
