#include "CryptHash.h"

/**
  Initializes the hash function pointers in the HashFunctions structure.

  @param[out]  Crypto  Pointer to the structure that will hold the hash function pointers.
**/
VOID
EFIAPI
HashInitFunctions (
  OUT SHARED_CRYPTO_PROTOCOL *Crypto
  )
{
  InitMd5Support (Crypto);
  InitSha1Support (Crypto);
  InitSha256Support (Crypto);
  InitSha512Support (Crypto);
  InitSm3Support (Crypto);
}
