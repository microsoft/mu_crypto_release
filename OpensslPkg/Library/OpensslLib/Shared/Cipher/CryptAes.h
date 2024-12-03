#ifndef _CRYPT_AES_H_
#define _CRYPT_AES_H_

#include <Uefi.h>

/**
 * @typedef AesGetContextSizeFunc
 * @brief Function pointer type for retrieving the size of the AES context buffer.
 * @return The size, in bytes, of the context buffer required for AES operations.
 */
typedef UINTN (*AesGetContextSizeFunc)(
  VOID
  );

/**
 * @typedef AesInitFunc
 * @brief Function pointer type for initializing AES context.
 * @param[out] AesContext Pointer to AES context being initialized.
 * @param[in] Key Pointer to the user-supplied AES key.
 * @param[in] KeyLength Length of AES key in bits.
 * @return TRUE if AES context initialization succeeded, FALSE otherwise.
 */
typedef BOOLEAN (*AesInitFunc)(
  OUT VOID         *AesContext,
  IN CONST UINT8   *Key,
  IN UINTN         KeyLength
  );

/**
 * @typedef AesCbcEncryptFunc
 * @brief Function pointer type for performing AES encryption in CBC mode.
 * @param[in] AesContext Pointer to the AES context.
 * @param[in] Input Pointer to the buffer containing the data to be encrypted.
 * @param[in] InputSize Size of the Input buffer in bytes.
 * @param[in] Ivec Pointer to initialization vector.
 * @param[out] Output Pointer to a buffer that receives the AES encryption output.
 * @return TRUE if AES encryption succeeded, FALSE otherwise.
 */
typedef BOOLEAN (*AesCbcEncryptFunc)(
  IN VOID          *AesContext,
  IN CONST UINT8   *Input,
  IN UINTN         InputSize,
  IN CONST UINT8   *Ivec,
  OUT UINT8        *Output
  );

/**
 * @typedef AesCbcDecryptFunc
 * @brief Function pointer type for performing AES decryption in CBC mode.
 * @param[in] AesContext Pointer to the AES context.
 * @param[in] Input Pointer to the buffer containing the data to be decrypted.
 * @param[in] InputSize Size of the Input buffer in bytes.
 * @param[in] Ivec Pointer to initialization vector.
 * @param[out] Output Pointer to a buffer that receives the AES decryption output.
 * @return TRUE if AES decryption succeeded, FALSE otherwise.
 */
typedef BOOLEAN (*AesCbcDecryptFunc)(
  IN VOID          *AesContext,
  IN CONST UINT8   *Input,
  IN UINTN         InputSize,
  IN CONST UINT8   *Ivec,
  OUT UINT8        *Output
  );

#define AES_FUNCTIONS_SIGNATURE  SIGNATURE_32('A', 'E', 'S', 'F')
#define AES_FUNCTIONS_VERSION    1

typedef struct {
  UINT32                Signature; // Signature of the structure to verify this is the intended structure
  UINT32                Version;   // Version of the structure to handle backward compatibility
  AesGetContextSizeFunc GetContextSize;
  AesInitFunc           Init;
  AesCbcEncryptFunc     CbcEncrypt;
  AesCbcDecryptFunc     CbcDecrypt;
} AesFunctions;

VOID
EFIAPI
AesInitFunctions (
  OUT AesFunctions  *Funcs
  );

#endif // _CRYPT_AES_H_