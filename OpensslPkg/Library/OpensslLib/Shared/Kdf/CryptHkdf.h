#ifndef CRYPT_HKDF_H__
#define CRYPT_HKDF_H__

#include <Uefi.h>
#include <CrtLibSupport.h>
#include "Shared/SharedCryptoProtocol.h"

VOID
EFIAPI
HkdfInstallFunctions (
  OUT SHARED_CRYPTO_PROTOCOL  *Crypto
  );

#endif //__CRYPT_HKDF_H__
