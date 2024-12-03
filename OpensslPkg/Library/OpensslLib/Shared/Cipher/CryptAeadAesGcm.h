#ifndef _CRYPT_AEAD_AES_GCM_H_
#define _CRYPT_AEAD_AES_GCM_H_

#include <Uefi.h>

/**
 * @typedef AeadAesGcmEncryptFunc
 * @brief Function pointer type for AEAD AES-GCM encryption.
 * @param Key The encryption key.
 * @param KeySize The size of the encryption key.
 * @param Iv The initialization vector.
 * @param IvSize The size of the initialization vector.
 * @param AData The additional authenticated data.
 * @param ADataSize The size of the additional authenticated data.
 * @param DataIn The input data to encrypt.
 * @param DataInSize The size of the input data.
 * @param DataOut The output buffer for the encrypted data.
 * @param DataOutSize The size of the output buffer.
 * @param TagOut The output buffer for the authentication tag.
 * @param TagSize The size of the authentication tag.
 * @return TRUE if the encryption was successful, FALSE otherwise.
 */
typedef BOOLEAN (*AeadAesGcmEncryptFunc)(
  IN   CONST UINT8  *Key,
  IN   UINTN        KeySize,
  IN   CONST UINT8  *Iv,
  IN   UINTN        IvSize,
  IN   CONST UINT8  *AData,
  IN   UINTN        ADataSize,
  IN   CONST UINT8  *DataIn,
  IN   UINTN        DataInSize,
  OUT  UINT8        *TagOut,
  IN   UINTN        TagSize,
  OUT  UINT8        *DataOut,
  OUT  UINTN        *DataOutSize
  );

/**
 * @typedef AeadAesGcmDecryptFunc
 * @brief Function pointer type for AEAD AES-GCM decryption.
 * @param Key The decryption key.
 * @param KeySize The size of the decryption key.
 * @param Iv The initialization vector.
 * @param IvSize The size of the initialization vector.
 * @param AData The additional authenticated data.
 * @param ADataSize The size of the additional authenticated data.
 * @param DataIn The input data to decrypt.
 * @param DataInSize The size of the input data.
 * @param DataOut The output buffer for the decrypted data.
 * @param DataOutSize The size of the output buffer.
 * @param Tag The authentication tag.
 * @param TagSize The size of the authentication tag.
 * @return TRUE if the decryption was successful, FALSE otherwise.
 */
typedef BOOLEAN (*AeadAesGcmDecryptFunc)(
  IN   CONST UINT8  *Key,
  IN   UINTN        KeySize,
  IN   CONST UINT8  *Iv,
  IN   UINTN        IvSize,
  IN   CONST UINT8  *AData,
  IN   UINTN        ADataSize,
  IN   CONST UINT8  *DataIn,
  IN   UINTN        DataInSize,
  IN   CONST UINT8  *Tag,
  IN   UINTN        TagSize,
  OUT  UINT8        *DataOut,
  OUT  UINTN        *DataOutSize
);

#define AEAD_AES_GCM_FUNCTIONS_SIGNATURE  SIGNATURE_32('A', 'A', 'G', 'F')
#define AEAD_AES_GCM_FUNCTIONS_VERSION    1

typedef struct {
  UINT32                   Signature; // Signature of the structure to verify this is the intended structure
  UINT32                   Version;   // Version of the structure to handle backward compatibility
  AeadAesGcmEncryptFunc    Encrypt;
  AeadAesGcmDecryptFunc    Decrypt;
} AeadAesGcmFunctions;

VOID
EFIAPI
AeadAesGcmInitFunctions (
  OUT AeadAesGcmFunctions  *Funcs
  );

#endif // _CRYPT_AEAD_AES_GCM_H_
