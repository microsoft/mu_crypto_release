#ifndef __CRYPT_HMAC_H__
#define __CRYPT_HMAC_H__

#include <Uefi.h>
#include "SharedCryptoProtocol.h"

/**
  Initializes the HMAC function pointers in the HmacFunctions structure.

  @param[out]  Funcs  Pointer to the structure that will hold the HMAC function pointers.
**/
VOID
EFIAPI
HmacInitFunctions (
  SHARED_CRYPTO_PROTOCOL *Crypto
  );

#endif // __CRYPT_HMAC_H__