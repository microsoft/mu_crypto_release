#include "SharedOpenssl.h"
#include "SharedCryptoProtocol.h"
#include "SharedCryptDecl.h"
#include "CrtLibSupport.h"
#include <Uefi.h>

/**
  Retrieves the version of the shared crypto protocol.

  @return  The version of the shared crypto protocol.
**/
UINT64
EFIAPI
GetVersion (
  VOID
  )
{
  return PACK_VERSION (VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION);
}

/**
  Initializes the shared crypto protocol.

  @param[out]  Crypto  Pointer to the shared crypto protocol.
**/
VOID
EFIAPI
InitAvailableCrypto (
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

  //
  // Initialize HMAC-SHA256 function pointers
  //
  Crypto->HmacSha256New       = HmacSha256New;
  Crypto->HmacSha256Free      = HmacSha256Free;
  Crypto->HmacSha256SetKey    = HmacSha256SetKey;
  Crypto->HmacSha256Duplicate = HmacSha256Duplicate;
  Crypto->HmacSha256Update    = HmacSha256Update;
  Crypto->HmacSha256Final     = HmacSha256Final;
  Crypto->HmacSha256All       = HmacSha256All;

  //
  // Initialize HMAC-SHA384 function pointers
  //
  Crypto->HmacSha384New       = HmacSha384New;
  Crypto->HmacSha384Free      = HmacSha384Free;
  Crypto->HmacSha384SetKey    = HmacSha384SetKey;
  Crypto->HmacSha384Duplicate = HmacSha384Duplicate;
  Crypto->HmacSha384Update    = HmacSha384Update;
  Crypto->HmacSha384Final     = HmacSha384Final;
  Crypto->HmacSha384All       = HmacSha384All;

  //
  // Initialize the Big Num function pointers
  //
  Crypto->BigNumInit        = BigNumInit;
  Crypto->BigNumFromBin     = BigNumFromBin;
  Crypto->BigNumToBin       = BigNumToBin;
  Crypto->BigNumFree        = BigNumFree;
  Crypto->BigNumAdd         = BigNumAdd;
  Crypto->BigNumSub         = BigNumSub;
  Crypto->BigNumMod         = BigNumMod;
  Crypto->BigNumExpMod      = BigNumExpMod;
  Crypto->BigNumInverseMod  = BigNumInverseMod;
  Crypto->BigNumDiv         = BigNumDiv;
  Crypto->BigNumMulMod      = BigNumMulMod;
  Crypto->BigNumCmp         = BigNumCmp;
  Crypto->BigNumBits        = BigNumBits;
  Crypto->BigNumBytes       = BigNumBytes;
  Crypto->BigNumIsWord      = BigNumIsWord;
  Crypto->BigNumIsOdd       = BigNumIsOdd;
  Crypto->BigNumCopy        = BigNumCopy;
  Crypto->BigNumValueOne    = BigNumValueOne;
  Crypto->BigNumRShift      = BigNumRShift;
  Crypto->BigNumConstTime   = BigNumConstTime;
  Crypto->BigNumSqrMod      = BigNumSqrMod;
  Crypto->BigNumNewContext  = BigNumNewContext;
  Crypto->BigNumContextFree = BigNumContextFree;
  Crypto->BigNumSetUint     = BigNumSetUint;
  Crypto->BigNumAddMod      = BigNumAddMod;

  //
  // TODO
  //
  Crypto->AeadAesGcmEncrypt = AeadAesGcmEncrypt;
  Crypto->AeadAesGcmDecrypt = AeadAesGcmDecrypt;
  Crypto->AesGetContextSize = AesGetContextSize;
  Crypto->AesInit           = AesInit;
  Crypto->AesCbcEncrypt     = AesCbcEncrypt;
  Crypto->AesCbcDecrypt     = AesCbcDecrypt;

 #ifdef ENABLE_MD5_DEPRECATED_INTERFACES
  Crypto->Md5GetContextSize = MD5GetContextSize;
  Crypto->Md5Init           = MD5Init;
  Crypto->Md5Update         = MD5Update;
  Crypto->Md5Final          = MD5Final;
  Crypto->Md5Duplicate      = MD5Duplicate;
  Crypto->Md5HashAll        = MD5HashAll;
 #else
  Crypto->Md5HashAll        = NULL;
  Crypto->Md5GetContextSize = NULL;
  Crypto->Md5Init           = NULL;
  Crypto->Md5Update         = NULL;
  Crypto->Md5Final          = NULL;
  Crypto->Md5Duplicate      = NULL;
 #endif // ENABLE_MD5_DEPRECATED_INTERFACES

  Crypto->Sha1GetContextSize   = Sha1GetContextSize;
  Crypto->Sha1Init             = Sha1Init;
  Crypto->Sha1Update           = Sha1Update;
  Crypto->Sha1Final            = Sha1Final;
  Crypto->Sha1Duplicate        = Sha1Duplicate;
  Crypto->Sha1HashAll          = Sha1HashAll;
  Crypto->Sha256GetContextSize = Sha256GetContextSize;
  Crypto->Sha256Init           = Sha256Init;
  Crypto->Sha256Update         = Sha256Update;
  Crypto->Sha256Final          = Sha256Final;
  Crypto->Sha256Duplicate      = Sha256Duplicate;
  Crypto->Sha256HashAll        = Sha256HashAll;
  Crypto->Sha512GetContextSize = Sha512GetContextSize;
  Crypto->Sha512Init           = Sha512Init;
  Crypto->Sha512Update         = Sha512Update;
  Crypto->Sha512Final          = Sha512Final;
  Crypto->Sha512Duplicate      = Sha512Duplicate;
  Crypto->Sha512HashAll        = Sha512HashAll;
  Crypto->Sm3GetContextSize    = Sm3GetContextSize;
  Crypto->Sm3Init              = Sm3Init;
  Crypto->Sm3Update            = Sm3Update;
  Crypto->Sm3Final             = Sm3Final;
  Crypto->Sm3Duplicate         = Sm3Duplicate;
  Crypto->Sm3HashAll           = Sm3HashAll;

  //
  // TODO
  //
  Crypto->HkdfSha256Expand           = HkdfSha256Expand;
  Crypto->HkdfSha256Extract          = HkdfSha256Extract;
  Crypto->HkdfSha256ExtractAndExpand = HkdfSha256ExtractAndExpand;
  Crypto->HkdfSha384Expand           = HkdfSha384Expand;
  Crypto->HkdfSha384Extract          = HkdfSha384Extract;
  Crypto->HkdfSha384ExtractAndExpand = HkdfSha384ExtractAndExpand;

  //
  // TODO
  //
  Crypto->RsaGetPrivateKeyFromPem = RsaGetPrivateKeyFromPem;
  Crypto->EcGetPrivateKeyFromPem  = EcGetPrivateKeyFromPem;

  //
  // PK
  //
  Crypto->AuthenticodeVerify  = AuthenticodeVerify;
  Crypto->DhNew               = DhNew;
  Crypto->DhFree              = DhFree;
  Crypto->DhGenerateParameter = DhGenerateParameter;
  Crypto->DhSetParameter      = DhSetParameter;
  Crypto->DhGenerateKey       = DhGenerateKey;
  Crypto->DhComputeKey        = DhComputeKey;
  Crypto->Pkcs5HashPassword   = Pkcs5HashPassword;
  Crypto->Pkcs1v2Encrypt      = Pkcs1v2Encrypt;
  Crypto->Pkcs1v2Decrypt      = Pkcs1v2Decrypt;
  Crypto->RsaOaepEncrypt      = RsaOaepEncrypt;
  Crypto->RsaOaepDecrypt      = RsaOaepDecrypt;

  return;
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
    DEBUG ((DEBUG_ERROR, "CryptoInit: Crypto is NULL\n"));
    ASSERT (Crypto != NULL);
    return;
  }

  //
  // The Caller should provide a GetVersion function that returns the version that the caller is expecting.
  // and this function should use that to ensure that the crypto functionality is compatible with the caller.
  //
  UINT16  RequestedMajor;
  UINT16  RequestedMinor;
  UINT16  RequestedRevision;

  UNPACK_VERSION (Crypto->GetVersion (), RequestedMajor, RequestedMinor, RequestedRevision);

  //
  // If the Major version is different, then the caller is expecting a different version of the protocol.
  // If this does not match, then this request is not compatible with the provided crypto functions.
  //
  // If the Minor version is greater than the current version, then the caller is expecting a newer version of the protocol.
  // If this does not match, then this request is not compatible with the provided crypto functions.
  //
  // Revision is ignored for compatibility checks. Since the revision only refers to bug fixes and not API changes.
  //
  if ((RequestedMajor != VERSION_MAJOR) && (RequestedMinor > VERSION_MINOR)) {
    DEBUG ((DEBUG_ERROR, "Incompatible version requested: (%d.%d.%d) - Actual (%d.%d.%d)\n", RequestedMajor, RequestedMinor, RequestedRevision, VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION));
    ASSERT (RequestedMajor == VERSION_MAJOR && RequestedMinor <= VERSION_MINOR);
    return;
  }

  //
  // TODO Add logic to support backward compatibility with older versions of the protocol.
  // This may require archiving older versions of the protocol and providing the requested version.
  //

  //
  // Initialize the Crypto functions
  //
  InitAvailableCrypto (Crypto);

  return;
}
