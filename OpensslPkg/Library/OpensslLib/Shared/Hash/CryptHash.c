#include "CryptHash.h"

/**
  Initializes the hash function pointers in the HashFunctions structure.

  @param[out]  HashFuncs  Pointer to the structure that will hold the hash function pointers.
**/
VOID
EFIAPI
HashInitFunctions (
  HashFunctions  *HashFuncs
  )
{
  InitMd5Support (HashFuncs);
  InitSha1Support (HashFuncs);
  InitSha256Support (HashFuncs);
  InitSha512Support (HashFuncs);
  InitSm3Support (HashFuncs);
}
