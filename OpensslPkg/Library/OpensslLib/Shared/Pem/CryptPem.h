#ifndef CRYPT_PEM_H_
#define CRYPT_PEM_H_

#include <Uefi.h>
#include <CrtLibSupport.h>
#include "Shared/SharedCryptoProtocol.h"

VOID
EFIAPI
PemInstallFunctions (
  OUT SHARED_CRYPTO_PROTOCOL  *Crypto
  );

#endif // CRYPT_PEM_H_
