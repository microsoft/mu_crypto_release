#ifndef _CRYPT_HASH_H_
#define _CRYPT_HASH_H_

#include <Uefi.h>
#include "CrtLibSupport.h"
#include "SharedCryptoProtocol.h"

/**
  Initializes the MD5 function pointers in the HashFunctions structure.

  @param[out]  HashFuncs  Pointer to the structure that will hold the MD5 function pointers.
**/
VOID
EFIAPI
InitMd5Support (
  OUT SHARED_CRYPTO_PROTOCOL *Crypto
  );

/**
  Initializes the SHA-1 function pointers in the HashFunctions structure.

  @param[out]  HashFuncs  Pointer to the structure that will hold the SHA-1 function pointers.
**/
VOID
InitSha1Support (
  OUT SHARED_CRYPTO_PROTOCOL *Crypto
  );

/**
  Initializes the SHA-256 function pointers in the HashFunctions structure.

  @param[out]  HashFuncs  Pointer to the structure that will hold the SHA-256 function pointers.
**/
VOID
InitSha256Support (
  OUT SHARED_CRYPTO_PROTOCOL *Crypto
  );

/**
  Initializes the SHA-512 function pointers in the HashFunctions structure.

  @param[out]  HashFuncs  Pointer to the structure that will hold the SHA-512 function pointers.
**/
VOID
InitSha512Support (
  OUT SHARED_CRYPTO_PROTOCOL *Crypto
  );

/**
  Initializes the SM3 function pointers in the HashFunctions structure.

  @param[out]  HashFuncs  Pointer to the structure that will hold the SM3 function pointers.
**/
VOID
InitSm3Support (
  OUT SHARED_CRYPTO_PROTOCOL *Crypto
  );

/**
  Initializes all supported hash function pointers in the HashFunctions structure.

  @param[out]  HashFuncs  Pointer to the structure that will hold the hash function pointers.
**/
VOID
EFIAPI
HashInitFunctions (
  OUT SHARED_CRYPTO_PROTOCOL *Crypto
  );

#endif // _CRYPT_HASH_H_
