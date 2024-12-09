#ifndef SHARED_CRYPTO_PROTOCOL_
#define SHARED_CRYPTO_PROTOCOL_

#include <Uefi.h>

/*
This file cannot depend on anything but UEFI primatives.

*/

#define VERSION_MAJOR     0ULL
#define VERSION_MINOR     0ULL
#define VERSION_REVISION  1ULL

//
// Pack the version number into a single UINT64
//
#define PACK_VERSION(Major, Minor, Revision) \
  (((UINT64)(Major) << 32) | ((UINT64)(Minor) << 16) | (UINT64)(Revision))

//
// Unpack the version number from a single UINT64
//
#define UNPACK_VERSION(Version, Major, Minor, Revision) \
  do { \
    Major = (UINT32)((Version) >> 32); \
    Minor = (UINT32)(((Version) >> 16) & 0xFFFF); \
    Revision = (UINT32)((Version) & 0xFFFF); \
  } while (0)

/**
    Retrieves the version of the shared crypto protocol.

    @return  The version of the shared crypto protocol.
**/
typedef UINT64 (*GetVersionFunc)(
  VOID
  );

// =====================================================================================
//    MAC (Message Authentication Code) Primitive
// =====================================================================================

/**
  Creates a new HMAC context.

  @return  Pointer to the new HMAC context.
**/
typedef VOID *(*HmacNewFunc)(
  VOID
  );

/**
  Frees an HMAC context.

  @param[in]  HmacCtx  Pointer to the HMAC context to be freed.
**/
typedef VOID (*HmacFreeFunc)(
  VOID  *HmacCtx
  );

/**
  Sets the key for an HMAC context.

  @param[in]  HmacContext  Pointer to the HMAC context.
  @param[in]  Key          Pointer to the key.
  @param[in]  KeySize      Size of the key in bytes.

  @retval TRUE   Key was set successfully.
  @retval FALSE  Failed to set the key.
**/
typedef BOOLEAN (*HmacSetKeyFunc)(
  VOID         *HmacContext,
  CONST UINT8  *Key,
  UINTN        KeySize
  );

/**
  Duplicates an HMAC context.

  @param[in]  HmacContext     Pointer to the source HMAC context.
  @param[out] NewHmacContext  Pointer to the new HMAC context.

  @retval TRUE   Context was duplicated successfully.
  @retval FALSE  Failed to duplicate the context.
**/
typedef BOOLEAN (*HmacDuplicateFunc)(
  CONST VOID  *HmacContext,
  VOID        *NewHmacContext
  );

/**
  Updates the HMAC with data.

  @param[in]  HmacContext  Pointer to the HMAC context.
  @param[in]  Data         Pointer to the data.
  @param[in]  DataSize     Size of the data in bytes.

  @retval TRUE   Data was updated successfully.
  @retval FALSE  Failed to update the data.
**/
typedef BOOLEAN (*HmacUpdateFunc)(
  VOID        *HmacContext,
  CONST VOID  *Data,
  UINTN       DataSize
  );

/**
  Finalizes the HMAC and produces the HMAC value.

  @param[in]  HmacContext  Pointer to the HMAC context.
  @param[out] HmacValue    Pointer to the buffer that receives the HMAC value.

  @retval TRUE   HMAC value was produced successfully.
  @retval FALSE  Failed to produce the HMAC value.
**/
typedef BOOLEAN (*HmacFinalFunc)(
  VOID   *HmacContext,
  UINT8  *HmacValue
  );

/**
  Performs the entire HMAC operation in one step.

  @param[in]  Data       Pointer to the data.
  @param[in]  DataSize   Size of the data in bytes.
  @param[in]  Key        Pointer to the key.
  @param[in]  KeySize    Size of the key in bytes.
  @param[out] HmacValue  Pointer to the buffer that receives the HMAC value.

  @retval TRUE   HMAC operation was performed successfully.
  @retval FALSE  Failed to perform the HMAC operation.
**/
typedef BOOLEAN (*HmacAllFunc)(
  CONST VOID   *Data,
  UINTN        DataSize,
  CONST UINT8  *Key,
  UINTN        KeySize,
  UINT8        *HmacValue
  );

// =====================================================================================
//    Hashing Primitives (TODO)
// =====================================================================================

/**
 * @typedef HashGetContextSizeFunc
 * @brief Function pointer type for retrieving the size of the Hash context buffer.
 * @return The size, in bytes, of the context buffer required for hash operations.
 */
typedef UINTN (*HashGetContextSizeFunc)(
  VOID
  );

/**
 * @typedef HashInitFunc
 * @brief Function pointer type for initializing Hash context.
 * @param[out] ContHashContextext Pointer to the Hash context being initialized.
 * @return TRUE if Hash context initialization succeeded, FALSE otherwise.
 */
typedef BOOLEAN (*HashInitFunc)(
  OUT VOID  *HashContext
  );

/**
 * @typedef HashUpdateFunc
 * @brief Function pointer type for updating Hash context with input data.
 * @param[in, out] HashContext Pointer to the Hash context.
 * @param[in] Data Pointer to the buffer containing the data to be hashed.
 * @param[in] DataSize Size of Data buffer in bytes.
 * @return TRUE if Hash data digest succeeded, FALSE otherwise.
 */
typedef BOOLEAN (*HashUpdateFunc)(
  IN OUT VOID    *HashContext,
  IN CONST VOID  *Data,
  IN UINTN       DataSize
  );

/**
 * @typedef HashFinalFunc
 * @brief Function pointer type for finalizing Hash context and retrieving the digest.
 * @param[out] HashDigest Pointer to a buffer that receives the Hash digest value.
 * @param[in, out] HashContext Pointer to the Hash context.
 * @return TRUE if Hash finalization succeeded, FALSE otherwise.
 */
typedef BOOLEAN (*HashFinalFunc)(
  OUT UINT8    *HashDigest,
  IN OUT VOID  *HashContext
  );

/**
 * @typedef HashHashAllFunc
 * @brief Function pointer type for performing Hash hash on a data buffer.
 * @param[in] Data Pointer to the buffer containing the data to be hashed.
 * @param[in] DataSize Size of Data buffer in bytes.
 * @param[out] HashDigest Pointer to a buffer that receives the Hash digest value.
 * @return TRUE if Hash hash succeeded, FALSE otherwise.
 */
typedef BOOLEAN (*HashHashAllFunc)(
  IN CONST VOID  *Data,
  IN UINTN       DataSize,
  OUT UINT8      *HashDigest
  );

/**
 * @typedef HashDuplicateFunc
 * @brief Function pointer type for duplicating an existing HASH context.
 * @param[in] HashContext Pointer to Hash context being copied.
 * @param[out] NewHashContext Pointer to new Hash context.
 * @return TRUE if Hash context copy succeeded, FALSE otherwise.
 */
typedef BOOLEAN (*HashDuplicateFunc)(
  IN CONST VOID  *HashContext,
  OUT VOID       *NewHashContext
  );

// =====================================================================================
//    Symmetric Cryptography Primitive
// =====================================================================================

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
  OUT VOID        *AesContext,
  IN CONST UINT8  *Key,
  IN UINTN        KeyLength
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
  IN VOID         *AesContext,
  IN CONST UINT8  *Input,
  IN UINTN        InputSize,
  IN CONST UINT8  *Ivec,
  OUT UINT8       *Output
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
  IN VOID         *AesContext,
  IN CONST UINT8  *Input,
  IN UINTN        InputSize,
  IN CONST UINT8  *Ivec,
  OUT UINT8       *Output
  );

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

// =====================================================================================
//  Big Number Primitives
// =====================================================================================

/**
 * @typedef BigNumInitFunc
 * @brief Function pointer type for initializing a big number.
 * @return A pointer to the initialized big number.
 */
typedef VOID *(*BigNumInitFunc)(
  VOID
  );

/**
 * @typedef BigNumFromBinFunc
 * @brief Function pointer type for creating a big number from a binary buffer.
 * @param Buf The binary buffer.
 * @param Len The length of the binary buffer.
 * @return A pointer to the created big number.
 */
typedef VOID *(*BigNumFromBinFunc)(
  IN CONST UINT8  *Buf,
  IN UINTN        Len
  );

/**
 * @typedef BigNumToBinFunc
 * @brief Function pointer type for converting a big number to a binary buffer.
 * @param Bn The big number to convert.
 * @param Buf The output binary buffer.
 * @return The length of the binary buffer.
 */
typedef INTN (*BigNumToBinFunc)(
  IN CONST VOID  *Bn,
  OUT UINT8      *Buf
  );

/**
 * @typedef BigNumFreeFunc
 * @brief Function pointer type for freeing a big number.
 * @param Bn The big number to free.
 * @param Clear Whether to clear the memory before freeing.
 */
typedef VOID (*BigNumFreeFunc)(
  IN VOID     *Bn,
  IN BOOLEAN  Clear
  );

/**
 * @typedef BigNumAddFunc
 * @brief Function pointer type for adding two big numbers.
 * @param BnA The first big number.
 * @param BnB The second big number.
 * @param BnRes The result of the addition.
 * @return TRUE if the addition was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumAddFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumSubFunc
 * @brief Function pointer type for subtracting one big number from another.
 * @param BnA The big number to subtract from.
 * @param BnB The big number to subtract.
 * @param BnRes The result of the subtraction.
 * @return TRUE if the subtraction was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumSubFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumModFunc
 * @brief Function pointer type for computing the modulus of two big numbers.
 * @param BnA The dividend big number.
 * @param BnB The divisor big number.
 * @param BnRes The result of the modulus operation.
 * @return TRUE if the modulus operation was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumModFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumExpModFunc
 * @brief Function pointer type for computing the modular exponentiation of a big number.
 * @param BnA The base big number.
 * @param BnP The exponent big number.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular exponentiation.
 * @return TRUE if the modular exponentiation was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumExpModFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnP,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumInverseModFunc
 * @brief Function pointer type for computing the modular inverse of a big number.
 * @param BnA The big number to invert.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular inverse.
 * @return TRUE if the modular inverse was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumInverseModFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumDivFunc
 * @brief Function pointer type for dividing one big number by another.
 * @param BnA The dividend big number.
 * @param BnB The divisor big number.
 * @param BnRes The result of the division.
 * @return TRUE if the division was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumDivFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumMulModFunc
 * @brief Function pointer type for computing the modular multiplication of two big numbers.
 * @param BnA The first big number.
 * @param BnB The second big number.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular multiplication.
 * @return TRUE if the modular multiplication was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumMulModFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumCmpFunc
 * @brief Function pointer type for comparing two big numbers.
 * @param BnA The first big number.
 * @param BnB The second big number.
 * @return A negative value if BnA < BnB, zero if BnA == BnB, and a positive value if BnA > BnB.
 */
typedef INTN (*BigNumCmpFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB
  );

/**
 * @typedef BigNumBitsFunc
 * @brief Function pointer type for getting the number of bits in a big number.
 * @param Bn The big number.
 * @return The number of bits in the big number.
 */
typedef UINTN (*BigNumBitsFunc)(
  IN CONST VOID  *Bn
  );

/**
 * @typedef BigNumBytesFunc
 * @brief Function pointer type for getting the number of bytes in a big number.
 * @param Bn The big number.
 * @return The number of bytes in the big number.
 */
typedef UINTN (*BigNumBytesFunc)(
  IN CONST VOID  *Bn
  );

/**
 * @typedef BigNumIsWordFunc
 * @brief Function pointer type for checking if a big number is equal to a specific word.
 * @param Bn The big number.
 * @param Num The word to compare against.
 * @return TRUE if the big number is equal to the word, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumIsWordFunc)(
  IN CONST VOID  *Bn,
  IN UINTN       Num
  );

/**
 * @typedef BigNumIsOddFunc
 * @brief Function pointer type for checking if a big number is odd.
 * @param Bn The big number.
 * @return TRUE if the big number is odd, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumIsOddFunc)(
  IN CONST VOID  *Bn
  );

/**
 * @typedef BigNumCopyFunc
 * @brief Function pointer type for copying one big number to another.
 * @param BnDst The destination big number.
 * @param BnSrc The source big number.
 * @return A pointer to the destination big number.
 */
typedef VOID *(*BigNumCopyFunc)(
  OUT VOID       *BnDst,
  IN CONST VOID  *BnSrc
  );

/**
 * @typedef BigNumValueOneFunc
 * @brief Function pointer type for getting a big number representing the value one.
 * @return A pointer to the big number representing the value one.
 */
typedef CONST VOID *(*BigNumValueOneFunc)(
  VOID
  );

/**
 * @typedef BigNumRShiftFunc
 * @brief Function pointer type for right-shifting a big number by a specified number of bits.
 * @param Bn The big number to shift.
 * @param N The number of bits to shift.
 * @param BnRes The result of the right shift.
 * @return TRUE if the right shift was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumRShiftFunc)(
  IN CONST VOID  *Bn,
  IN UINTN       N,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumConstTimeFunc
 * @brief Function pointer type for performing a constant-time operation on a big number.
 * @param Bn The big number.
 */
typedef VOID (*BigNumConstTimeFunc)(
  IN VOID  *Bn
  );

/**
 * @typedef BigNumSqrModFunc
 * @brief Function pointer type for computing the modular square of a big number.
 * @param BnA The big number to square.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular square.
 * @return TRUE if the modular square was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumSqrModFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes
  );

/**
 * @typedef BigNumNewContextFunc
 * @brief Function pointer type for creating a new big number context.
 * @return A pointer to the new big number context.
 */
typedef VOID *(*BigNumNewContextFunc)(
  VOID
  );

/**
 * @typedef BigNumContextFreeFunc
 * @brief Function pointer type for freeing a big number context.
 * @param BnCtx The big number context to free.
 */
typedef VOID (*BigNumContextFreeFunc)(
  IN VOID  *BnCtx
  );

/**
 * @typedef BigNumSetUintFunc
 * @brief Function pointer type for setting a big number to a specific unsigned integer value.
 * @param Bn The big number.
 * @param Val The unsigned integer value.
 * @return TRUE if the operation was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumSetUintFunc)(
  IN VOID   *Bn,
  IN UINTN  Val
  );

/**
 * @typedef BigNumAddModFunc
 * @brief Function pointer type for computing the modular addition of two big numbers.
 * @param BnA The first big number.
 * @param BnB The second big number.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular addition.
 * @return TRUE if the modular addition was successful, FALSE otherwise.
 */
typedef BOOLEAN (*BigNumAddModFunc)(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes
  );

// =====================================================================================
//    Key Derivation Function Primitive
// =====================================================================================

/**
  Derive key data using HMAC-SHA* based KDF.

  @param[in]   Key              Pointer to the user-supplied key.
  @param[in]   KeySize          Key size in bytes.
  @param[in]   Salt             Pointer to the salt(non-secret) value.
  @param[in]   SaltSize         Salt size in bytes.
  @param[in]   Info             Pointer to the application specific info.
  @param[in]   InfoSize         Info size in bytes.
  @param[out]  Out              Pointer to buffer to receive hkdf value.
  @param[in]   OutSize          Size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
typedef BOOLEAN (EFIAPI *HkdfExtractAndExpandFunc)(
  IN   CONST UINT8  *Key,
  IN   UINTN        KeySize,
  IN   CONST UINT8  *Salt,
  IN   UINTN        SaltSize,
  IN   CONST UINT8  *Info,
  IN   UINTN        InfoSize,
  OUT  UINT8        *Out,
  IN   UINTN        OutSize
  );

/**
  Derive HMAC-SHA*-based Extract key Derivation Function (HKDF).

  @param[in]   Key              Pointer to the user-supplied key.
  @param[in]   KeySize          key size in bytes.
  @param[in]   Salt             Pointer to the salt(non-secret) value.
  @param[in]   SaltSize         salt size in bytes.
  @param[out]  PrkOut           Pointer to buffer to receive hkdf value.
  @param[in]   PrkOutSize       size of hkdf bytes to generate.

  @retval true   Hkdf generated successfully.
  @retval false  Hkdf generation failed.
**/
typedef BOOLEAN (EFIAPI *HkdfExtractFunc)(
  IN CONST UINT8  *Key,
  IN UINTN        KeySize,
  IN CONST UINT8  *Salt,
  IN UINTN        SaltSize,
  OUT UINT8       *PrkOut,
  UINTN           PrkOutSize
  );

/**
  Derive HMAC-SHA*-based Expand Key Derivation Function (HKDF).

  @param[in]   Prk              Pointer to the user-supplied key.
  @param[in]   PrkSize          Key size in bytes.
  @param[in]   Info             Pointer to the application specific info.
  @param[in]   InfoSize         Info size in bytes.
  @param[out]  Out              Pointer to buffer to receive hkdf value.
  @param[in]   OutSize          Size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
typedef BOOLEAN (EFIAPI *HkdfExpandFunc)(
  IN   CONST UINT8  *Prk,
  IN   UINTN        PrkSize,
  IN   CONST UINT8  *Info,
  IN   UINTN        InfoSize,
  OUT  UINT8        *Out,
  IN   UINTN        OutSize
  );

// =====================================================================================

/**
  Retrieve the Private Key from the password-protected PEM key data.

  @param[in]  PemData      Pointer to the PEM-encoded key data to be retrieved.
  @param[in]  PemSize      Size of the PEM key data in bytes.
  @param[in]  Password     NULL-terminated passphrase used for encrypted PEM key data.
  @param[out] RsaContext   Pointer to new-generated RSA context which contains the retrieved private key component.
                           Use RsaFree() function to free the resource.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
typedef BOOLEAN (EFIAPI *RsaGetPrivateKeyFromPemFunc)(
  IN   CONST UINT8  *PemData,
  IN   UINTN        PemSize,
  IN   CONST CHAR8  *Password,
  OUT  VOID         **RsaContext
  );

/**
  Retrieve the Public Key from the PEM key data.

  @param[in]  PemData      Pointer to the PEM-encoded key data to be retrieved.
  @param[in]  PemSize      Size of the PEM key data in bytes.
  @param[out] RsaContext   Pointer to new-generated RSA context which contains the retrieved public key component.
                           Use RsaFree() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data.
**/
typedef BOOLEAN (EFIAPI *RsaGetPublicKeyFromPemFunc)(
  IN   CONST UINT8  *PemData,
  IN   UINTN        PemSize,
  OUT  VOID         **RsaContext
  );

/**
  Retrieve the Private Key from the password-protected PEM key data.

  @param[in]  PemData      Pointer to the PEM-encoded key data to be retrieved.
  @param[in]  PemSize      Size of the PEM key data in bytes.
  @param[in]  Password     NULL-terminated passphrase used for encrypted PEM key data.
  @param[out] EcContext    Pointer to new-generated EC context which contains the retrieved private key component.
                           Use EcFree() function to free the resource.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
typedef BOOLEAN (EFIAPI *EcGetPrivateKeyFromPemFunc)(
  IN   CONST UINT8  *PemData,
  IN   UINTN        PemSize,
  IN   CONST CHAR8  *Password,
  OUT  VOID         **EcContext
  );

/**
  Retrieve the Public Key from the PEM key data.

  @param[in]  PemData      Pointer to the PEM-encoded key data to be retrieved.
  @param[in]  PemSize      Size of the PEM key data in bytes.
  @param[out] EcContext    Pointer to new-generated EC context which contains the retrieved public key component.
                           Use EcFree() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data.
**/
typedef BOOLEAN (EFIAPI *EcGetPublicKeyFromPemFunc)(
  IN   CONST UINT8  *PemData,
  IN   UINTN        PemSize,
  OUT  VOID         **EcContext
  );

// ==================================== TODO

/**
  Verifies the validity of an Authenticode Signature.

  @param[in]  AuthData     Pointer to the Authenticode Signature retrieved from signed
                           PE/COFF image to be verified.
  @param[in]  DataSize     Size of the Authenticode Signature in bytes.
  @param[in]  TrustedCert  Pointer to a trusted/root certificate encoded in DER, which
                           is used for certificate chain verification.
  @param[in]  CertSize     Size of the trusted certificate in bytes.
  @param[in]  ImageHash    Pointer to the original image file hash value. The procedure
                           for calculating the image hash value is described in Authenticode
                           specification.
  @param[in]  HashSize     Size of Image hash value in bytes.

  @retval  TRUE   The specified Authenticode Signature is valid.
  @retval  FALSE  Invalid Authenticode Signature.
**/
typedef BOOLEAN (EFIAPI *AuthenticodeVerifyFunc)(
  IN  CONST UINT8  *AuthData,
  IN  UINTN        DataSize,
  IN  CONST UINT8  *TrustedCert,
  IN  UINTN        CertSize,
  IN  CONST UINT8  *ImageHash,
  IN  UINTN        HashSize
  );

// =============================================================================
//     PKCS functions
// =============================================================================

/**
  Derives a key from a password using a salt and iteration count, based on PKCS#5 v2.0
  password based encryption key derivation function PBKDF2, as specified in RFC 2898.
  If Password or Salt or OutKey is NULL, then return FALSE.
  If the hash algorithm could not be determined, then return FALSE.
  If this interface is not supported, then return FALSE.
  @param[in]  PasswordLength  Length of input password in bytes.
  @param[in]  Password        Pointer to the array for the password.
  @param[in]  SaltLength      Size of the Salt in bytes.
  @param[in]  Salt            Pointer to the Salt.
  @param[in]  IterationCount  Number of iterations to perform. Its value should be
                              greater than or equal to 1.
  @param[in]  DigestSize      Size of the message digest to be used (eg. SHA256_DIGEST_SIZE).
                              NOTE: DigestSize will be used to determine the hash algorithm.
                                    Only SHA1_DIGEST_SIZE or SHA256_DIGEST_SIZE is supported.
  @param[in]  KeyLength       Size of the derived key buffer in bytes.
  @param[out] OutKey          Pointer to the output derived key buffer.
  @retval  TRUE   A key was derived successfully.
  @retval  FALSE  One of the pointers was NULL or one of the sizes was too large.
  @retval  FALSE  The hash algorithm could not be determined from the digest size.
  @retval  FALSE  The key derivation operation failed.
  @retval  FALSE  This interface is not supported.
**/
typedef
BOOLEAN
(EFIAPI *Pkcs5HashPasswordFunc)(
  IN  UINTN        PasswordLength,
  IN  CONST CHAR8  *Password,
  IN  UINTN        SaltLength,
  IN  CONST UINT8  *Salt,
  IN  UINTN        IterationCount,
  IN  UINTN        DigestSize,
  IN  UINTN        KeyLength,
  OUT UINT8        *OutKey
  );

// =============================================================================
//     DH functions
// =============================================================================

/**
  Allocates and Initializes one Diffie-Hellman Context for subsequent use.
  @return  Pointer to the Diffie-Hellman Context that has been initialized.
           If the allocations fails, DhNew() returns NULL.
           If the interface is not supported, DhNew() returns NULL.
**/
typedef
VOID *
(EFIAPI *DhNewFunc)(
  VOID
  );

/**
  Release the specified DH context.
  If the interface is not supported, then ASSERT().
  @param[in]  DhContext  Pointer to the DH context to be released.
**/
typedef
VOID
(EFIAPI *DhFreeFunc)(
  IN  VOID  *DhContext
  );

/**
  Generates DH parameter.
  Given generator g, and length of prime number p in bits, this function generates p,
  and sets DH context according to value of g and p.
  Before this function can be invoked, pseudorandom number generator must be correctly
  initialized by RandomSeed().
  If DhContext is NULL, then return FALSE.
  If Prime is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.
  @param[in, out]  DhContext    Pointer to the DH context.
  @param[in]       Generator    Value of generator.
  @param[in]       PrimeLength  Length in bits of prime to be generated.
  @param[out]      Prime        Pointer to the buffer to receive the generated prime number.
  @retval TRUE   DH parameter generation succeeded.
  @retval FALSE  Value of Generator is not supported.
  @retval FALSE  PRNG fails to generate random prime number with PrimeLength.
  @retval FALSE  This interface is not supported.
**/
typedef
BOOLEAN
(EFIAPI *DhGenerateParameterFunc)(
  IN OUT  VOID   *DhContext,
  IN      UINTN  Generator,
  IN      UINTN  PrimeLength,
  OUT     UINT8  *Prime
  );

/**
  Sets generator and prime parameters for DH.
  Given generator g, and prime number p, this function and sets DH
  context accordingly.
  If DhContext is NULL, then return FALSE.
  If Prime is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.
  @param[in, out]  DhContext    Pointer to the DH context.
  @param[in]       Generator    Value of generator.
  @param[in]       PrimeLength  Length in bits of prime to be generated.
  @param[in]       Prime        Pointer to the prime number.
  @retval TRUE   DH parameter setting succeeded.
  @retval FALSE  Value of Generator is not supported.
  @retval FALSE  Value of Generator is not suitable for the Prime.
  @retval FALSE  Value of Prime is not a prime number.
  @retval FALSE  Value of Prime is not a safe prime number.
  @retval FALSE  This interface is not supported.
**/
typedef
BOOLEAN
(EFIAPI *DhSetParameterFunc)(
  IN OUT  VOID         *DhContext,
  IN      UINTN        Generator,
  IN      UINTN        PrimeLength,
  IN      CONST UINT8  *Prime
  );

/**
Generates DH public key.

This function generates random secret exponent, and computes the public key, which is
returned via parameter PublicKey and PublicKeySize. DH context is updated accordingly.
If the PublicKey buffer is too small to hold the public key, FALSE is returned and
PublicKeySize is set to the required buffer size to obtain the public key.

If DhContext is NULL, then return FALSE.
If PublicKeySize is NULL, then return FALSE.
If PublicKeySize is large enough but PublicKey is NULL, then return FALSE.
If this interface is not supported, then return FALSE.

@param[in, out]  DhContext      Pointer to the DH context.
@param[out]      PublicKey      Pointer to the buffer to receive generated public key.
@param[in, out]  PublicKeySize  On input, the size of PublicKey buffer in bytes.
                               On output, the size of data returned in PublicKey buffer in bytes.

@retval TRUE   DH public key generation succeeded.
@retval FALSE  DH public key generation failed.
@retval FALSE  PublicKeySize is not large enough.
@retval FALSE  This interface is not supported.

**/
typedef
BOOLEAN
(EFIAPI *DhGenerateKeyFunc)(
  IN OUT  VOID   *DhContext,
  OUT     UINT8  *PublicKey,
  IN OUT  UINTN  *PublicKeySize
  );

/**
  Computes exchanged common key.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  If DhContext is NULL, then return FALSE.
  If PeerPublicKey is NULL, then return FALSE.
  If KeySize is NULL, then return FALSE.
  If Key is NULL, then return FALSE.
  If KeySize is not large enough, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  DhContext          Pointer to the DH context.
  @param[in]       PeerPublicKey      Pointer to the peer's public key.
  @param[in]       PeerPublicKeySize  Size of peer's public key in bytes.
  @param[out]      Key                Pointer to the buffer to receive generated key.
  @param[in, out]  KeySize            On input, the size of Key buffer in bytes.
                                     On output, the size of data returned in Key buffer in bytes.

  @retval TRUE   DH exchanged key generation succeeded.
  @retval FALSE  DH exchanged key generation failed.
  @retval FALSE  KeySize is not large enough.
  @retval FALSE  This interface is not supported.

**/
typedef
BOOLEAN
(EFIAPI *DhComputeKeyFunc)(
  IN OUT  VOID         *DhContext,
  IN      CONST UINT8  *PeerPublicKey,
  IN      UINTN        PeerPublicKeySize,
  OUT     UINT8        *Key,
  IN OUT  UINTN        *KeySize
  );

/**
  Encrypts a blob using PKCS1v2 (RSAES-OAEP) schema. On success, will return the
  encrypted message in a newly allocated buffer.

  @param[in]  PublicKey           A pointer to the DER-encoded X509 certificate that
                                  will be used to encrypt the data.
  @param[in]  PublicKeySize       Size of the X509 cert buffer.
  @param[in]  InData              Data to be encrypted.
  @param[in]  InDataSize          Size of the data buffer.
  @param[in]  PrngSeed            [Optional] If provided, a pointer to a random seed buffer
                                  to be used when initializing the PRNG. NULL otherwise.
  @param[in]  PrngSeedSize        [Optional] If provided, size of the random seed buffer.
                                  0 otherwise.
  @param[out] EncryptedData       Pointer to an allocated buffer containing the encrypted
                                  message.
  @param[out] EncryptedDataSize   Size of the encrypted message buffer.

  @retval     TRUE                Encryption was successful.
  @retval     FALSE               Encryption failed.
**/
typedef BOOLEAN (EFIAPI *Pkcs1v2EncryptFunc)(
  IN   CONST UINT8  *PublicKey,
  IN   UINTN        PublicKeySize,
  IN   UINT8        *InData,
  IN   UINTN        InDataSize,
  IN   CONST UINT8  *PrngSeed   OPTIONAL,
  IN   UINTN        PrngSeedSize   OPTIONAL,
  OUT  UINT8        **EncryptedData,
  OUT  UINTN        *EncryptedDataSize
  );

/**
  Decrypts a blob using PKCS1v2 (RSAES-OAEP) schema. On success, will return the
  decrypted message in a newly allocated buffer.

  @param[in]  PrivateKey          A pointer to the DER-encoded private key.
  @param[in]  PrivateKeySize      Size of the private key buffer.
  @param[in]  EncryptedData       Data to be decrypted.
  @param[in]  EncryptedDataSize   Size of the encrypted buffer.
  @param[out] OutData             Pointer to an allocated buffer containing the encrypted
                                  message.
  @param[out] OutDataSize         Size of the encrypted message buffer.

  @retval     TRUE                Encryption was successful.
  @retval     FALSE               Encryption failed.
**/
typedef BOOLEAN (EFIAPI *Pkcs1v2DecryptFunc)(
  IN   CONST UINT8  *PrivateKey,
  IN   UINTN        PrivateKeySize,
  IN   UINT8        *EncryptedData,
  IN   UINTN        EncryptedDataSize,
  OUT  UINT8        **OutData,
  OUT  UINTN        *OutDataSize
  );

/**
  Encrypts a blob using PKCS1v2 (RSAES-OAEP) schema. On success, will return the
  encrypted message in a newly allocated buffer.

  @param[in]  RsaContext          A pointer to an RSA context created by RsaNew() and
                                  provisioned with a public key using RsaSetKey().
  @param[in]  InData              Data to be encrypted.
  @param[in]  InDataSize          Size of the data buffer.
  @param[in]  PrngSeed            [Optional] If provided, a pointer to a random seed buffer
                                  to be used when initializing the PRNG. NULL otherwise.
  @param[in]  PrngSeedSize        [Optional] If provided, size of the random seed buffer.
                                  0 otherwise.
  @param[in]  DigestLen           [Optional] If provided, size of the hash used:
                                  SHA1_DIGEST_SIZE
                                  SHA256_DIGEST_SIZE
                                  SHA384_DIGEST_SIZE
                                  SHA512_DIGEST_SIZE
                                  0 to use default (SHA1)
  @param[out] EncryptedData       Pointer to an allocated buffer containing the encrypted
                                  message.
  @param[out] EncryptedDataSize   Size of the encrypted message buffer.

  @retval     TRUE                Encryption was successful.
  @retval     FALSE               Encryption failed.
**/
typedef BOOLEAN (EFIAPI *RsaOaepEncryptFunc)(
  IN   VOID         *RsaContext,
  IN   UINT8        *InData,
  IN   UINTN        InDataSize,
  IN   CONST UINT8  *PrngSeed   OPTIONAL,
  IN   UINTN        PrngSeedSize   OPTIONAL,
  IN   UINT16       DigestLen OPTIONAL,
  OUT  UINT8        **EncryptedData,
  OUT  UINTN        *EncryptedDataSize
  );

/**
  Decrypts a blob using PKCS1v2 (RSAES-OAEP) schema. On success, will return the
  decrypted message in a newly allocated buffer.

  @param[in]  RsaContext          A pointer to an RSA context created by RsaNew() and
                                  provisioned with a private key using RsaSetKey().
  @param[in]  EncryptedData       Data to be decrypted.
  @param[in]  EncryptedDataSize   Size of the encrypted buffer.
  @param[in]  DigestLen           [Optional] If provided, size of the hash used:
                                  SHA1_DIGEST_SIZE
                                  SHA256_DIGEST_SIZE
                                  SHA384_DIGEST_SIZE
                                  SHA512_DIGEST_SIZE
                                  0 to use default (SHA1)
  @param[out] OutData             Pointer to an allocated buffer containing the encrypted
                                  message.
  @param[out] OutDataSize         Size of the encrypted message buffer.

  @retval     TRUE                Encryption was successful.
  @retval     FALSE               Encryption failed.
**/
typedef BOOLEAN (EFIAPI *RsaOaepDecryptFunc)(
  IN   VOID    *RsaContext,
  IN   UINT8   *EncryptedData,
  IN   UINTN   EncryptedDataSize,
  IN   UINT16  DigestLen OPTIONAL,
  OUT  UINT8   **OutData,
  OUT  UINTN   *OutDataSize
  );


typedef struct _SHARED_CRYPTO_PROTOCOL {
  // -------------------------------------------
  // Versioning [IMPORTANT]
  // Major - Breaking change to this structure
  // Minor - Functions added to the end of this structure
  // Revision - Some non breaking change
  //
  // The caller should fill in with a function that provides the version of the protocol they are expecting.
  // When initializing the protocol, the calle filling in the crypto functions will check the version
  // and attempt to provide the functions that match the version requested.
  //
  GetVersionFunc                 GetVersion;

  // Protocol Version 1 Functions [BEGIN] =================
  // --------------------------------------------
  // HMAC (Message Authentication Code) Primitive (14 Functions)
  // --------------------------------------------
  /// HMAC SHA-256 ------------------------------
  HmacNewFunc                    HmacSha256New;
  HmacFreeFunc                   HmacSha256Free;
  HmacSetKeyFunc                 HmacSha256SetKey;
  HmacDuplicateFunc              HmacSha256Duplicate;
  HmacUpdateFunc                 HmacSha256Update;
  HmacFinalFunc                  HmacSha256Final;
  HmacAllFunc                    HmacSha256All;
  /// HMAC SHA-384 ------------------------------
  HmacNewFunc                    HmacSha384New;
  HmacFreeFunc                   HmacSha384Free;
  HmacSetKeyFunc                 HmacSha384SetKey;
  HmacDuplicateFunc              HmacSha384Duplicate;
  HmacUpdateFunc                 HmacSha384Update;
  HmacFinalFunc                  HmacSha384Final;
  HmacAllFunc                    HmacSha384All;

  // --------------------------------------------
  //  One-Way Cryptographic Hash Primitives (30)
  // --------------------------------------------
  /// MD5 HASH ----------------------------------
  HashGetContextSizeFunc         Md5GetContextSize;
  HashInitFunc                   Md5Init;
  HashUpdateFunc                 Md5Update;
  HashFinalFunc                  Md5Final;
  HashHashAllFunc                Md5HashAll;
  HashDuplicateFunc              Md5Duplicate;
  /// SHA1 HASH ----------------------------------
  HashGetContextSizeFunc         Sha1GetContextSize;
  HashInitFunc                   Sha1Init;
  HashUpdateFunc                 Sha1Update;
  HashFinalFunc                  Sha1Final;
  HashHashAllFunc                Sha1HashAll;
  HashDuplicateFunc              Sha1Duplicate;
  /// SHA256  -------------------------------
  HashGetContextSizeFunc         Sha256GetContextSize;
  HashInitFunc                   Sha256Init;
  HashUpdateFunc                 Sha256Update;
  HashFinalFunc                  Sha256Final;
  HashHashAllFunc                Sha256HashAll;
  HashDuplicateFunc              Sha256Duplicate;
  /// SHA512 HASH -------------------------------
  HashGetContextSizeFunc         Sha512GetContextSize;
  HashInitFunc                   Sha512Init;
  HashUpdateFunc                 Sha512Update;
  HashFinalFunc                  Sha512Final;
  HashHashAllFunc                Sha512HashAll;
  HashDuplicateFunc              Sha512Duplicate;
  /// SM3 HASH ----------------------------------
  HashGetContextSizeFunc         Sm3GetContextSize;
  HashInitFunc                   Sm3Init;
  HashUpdateFunc                 Sm3Update;
  HashFinalFunc                  Sm3Final;
  HashHashAllFunc                Sm3HashAll;
  HashDuplicateFunc              Sm3Duplicate;

  // --------------------------------------------
  //  Symmetric Cryptography Primitive (6 Functions)
  // --------------------------------------------
  AesGetContextSizeFunc          AesGetContextSize;
  AesInitFunc                    AesInit;
  AesCbcEncryptFunc              AesCbcEncrypt;
  AesCbcDecryptFunc              AesCbcDecrypt;
  AeadAesGcmEncryptFunc          AeadAesGcmEncrypt;
  AeadAesGcmDecryptFunc          AeadAesGcmDecrypt;

  // --------------------------------------------
  //  Big Number Primitives (26 Functions)
  // --------------------------------------------
  BigNumInitFunc                 BigNumInit;
  BigNumFromBinFunc              BigNumFromBin;
  BigNumToBinFunc                BigNumToBin;
  BigNumFreeFunc                 BigNumFree;
  BigNumAddFunc                  BigNumAdd;
  BigNumSubFunc                  BigNumSub;
  BigNumModFunc                  BigNumMod;
  BigNumExpModFunc               BigNumExpMod;
  BigNumInverseModFunc           BigNumInverseMod;
  BigNumDivFunc                  BigNumDiv;
  BigNumMulModFunc               BigNumMulMod;
  BigNumCmpFunc                  BigNumCmp;
  BigNumBitsFunc                 BigNumBits;
  BigNumBytesFunc                BigNumBytes;
  BigNumIsWordFunc               BigNumIsWord;
  BigNumIsOddFunc                BigNumIsOdd;
  BigNumCopyFunc                 BigNumCopy;
  BigNumValueOneFunc             BigNumValueOne;
  BigNumRShiftFunc               BigNumRShift;
  BigNumConstTimeFunc            BigNumConstTime;
  BigNumSqrModFunc               BigNumSqrMod;
  BigNumNewContextFunc           BigNumNewContext;
  BigNumContextFreeFunc          BigNumContextFree;
  BigNumSetUintFunc              BigNumSetUint;
  BigNumAddModFunc               BigNumAddMod;

  // --------------------------------------------
  //  Key Derivation Function Primitive (6 Functions)
  // --------------------------------------------
  HkdfExtractAndExpandFunc       HkdfSha256ExtractAndExpand;
  HkdfExtractFunc                HkdfSha256Extract;
  HkdfExpandFunc                 HkdfSha256Expand;
  HkdfExtractAndExpandFunc       HkdfSha384ExtractAndExpand;
  HkdfExtractFunc                HkdfSha384Extract;
  HkdfExpandFunc                 HkdfSha384Expand;

  // ---------------------------------------------
  // PEM
  // ---------------------------------------------
  RsaGetPrivateKeyFromPemFunc    RsaGetPrivateKeyFromPem;
  // RsaGetPublicKeyFromPemFunc RsaGetPublicKeyFromPem; TODO Where
  EcGetPrivateKeyFromPemFunc     EcGetPrivateKeyFromPem;
  // EcGetPublicKeyFromPemFunc  EcGetPublicKeyFromPem;

  // ---------------------------------------------
  // PK
  // ---------------------------------------------
  /// Authenticode  ------------------------------
  AuthenticodeVerifyFunc         AuthenticodeVerify;
  /// PKCS1v2 ------------------------------------
  Pkcs1v2EncryptFunc             Pkcs1v2Encrypt;
  Pkcs1v2DecryptFunc             Pkcs1v2Decrypt;
  /// RSA OAEP -----------------------------------
  RsaOaepEncryptFunc             RsaOaepEncrypt;
  RsaOaepDecryptFunc             RsaOaepDecrypt;
  /// PKCS5 --------------------------------------
  Pkcs5HashPasswordFunc         Pkcs5HashPassword;
  /// PKCS7 --------------------------------------
  /// DH -----------------------------------------
  DhNewFunc                      DhNew;
  DhFreeFunc                     DhFree;
  DhGenerateParameterFunc        DhGenerateParameter;
  DhSetParameterFunc             DhSetParameter;
  DhGenerateKeyFunc              DhGenerateKey;
  DhComputeKeyFunc               DhComputeKey;

  // Protocol Version 1 Functions [END] ===================
} SHARED_CRYPTO_PROTOCOL;

#endif // SHARED_CRYPTO_PROTOCOL_
