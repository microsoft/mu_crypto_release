#include <Uefi.h>
#include "CryptPk.h"

VOID
EFIAPI
PkInstallFunctions (
  OUT SHARED_CRYPTO_PROTOCOL  *Crypto
  )
{
  AuthenticodeInstallFunctions (Crypto);
  DhInstallFunctions (Crypto);
  Pkcs5InstallFunctions(Crypto);
  Pkcs1v2InstallFunctions (Crypto);
}
