#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include <Uefi.h>

#define VERSION_MAJOR     1ULL
#define VERSION_MINOR     0ULL
#define VERSION_REVISION  0ULL

#define CRYPTO_NID_NULL  0x0000

// Hash
#define CRYPTO_NID_SHA256  0x0001
#define CRYPTO_NID_SHA384  0x0002
#define CRYPTO_NID_SHA512  0x0003

// Key Exchange
#define CRYPTO_NID_SECP256R1  0x0204
#define CRYPTO_NID_SECP384R1  0x0205
#define CRYPTO_NID_SECP521R1  0x0206

///
/// MD5 digest size in bytes
///
#define MD5_DIGEST_SIZE  16

///
/// SHA-1 digest size in bytes.
///
#define SHA1_DIGEST_SIZE  20

///
/// SHA-256 digest size in bytes
///
#define SHA256_DIGEST_SIZE  32

///
/// SHA-384 digest size in bytes
///
#define SHA384_DIGEST_SIZE  48

///
/// SHA-512 digest size in bytes
///
#define SHA512_DIGEST_SIZE  64

///
/// SM3 digest size in bytes
///
#define SM3_256_DIGEST_SIZE  32

///
/// TDES block size in bytes
///
#define TDES_BLOCK_SIZE  8

///
/// AES block size in bytes
///
#define AES_BLOCK_SIZE  16

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


///
/// RSA Key Tags Definition used in RsaSetKey() function for key component identification.
///
typedef enum {
  RsaKeyN,      ///< RSA public Modulus (N)
  RsaKeyE,      ///< RSA Public exponent (e)
  RsaKeyD,      ///< RSA Private exponent (d)
  RsaKeyP,      ///< RSA secret prime factor of Modulus (p)
  RsaKeyQ,      ///< RSA secret prime factor of Modules (q)
  RsaKeyDp,     ///< p's CRT exponent (== d mod (p - 1))
  RsaKeyDq,     ///< q's CRT exponent (== d mod (q - 1))
  RsaKeyQInv    ///< The CRT coefficient (== 1/q mod p)
} RSA_KEY_TAG;


/**
    Retrieves the version of the shared crypto protocol.

    @return  The version of the shared crypto protocol.
**/
UINT64
EFIAPI
GetVersion(
  VOID);

/**
  Creates a new HMAC context.

  @return  Pointer to the new HMAC context.
**/
VOID *
EFIAPI
HmacSha256New(
  VOID);

/**
  Frees an HMAC context.

  @param[in]  HmacCtx  Pointer to the HMAC context to be freed.
**/
VOID
EFIAPI
HmacSha256Free(
  VOID  *HmacCtx);

/**
  Sets the key for an HMAC context.

  @param[in]  HmacContext  Pointer to the HMAC context.
  @param[in]  Key          Pointer to the key.
  @param[in]  KeySize      Size of the key in bytes.

  @retval TRUE   Key was set successfully.
  @retval FALSE  Failed to set the key.
**/
BOOLEAN
EFIAPI
HmacSha256SetKey(
  VOID         *HmacContext,
  CONST UINT8  *Key,
  UINTN        KeySize);

/**
  Duplicates an HMAC context.

  @param[in]  HmacContext     Pointer to the source HMAC context.
  @param[out] NewHmacContext  Pointer to the new HMAC context.

  @retval TRUE   Context was duplicated successfully.
  @retval FALSE  Failed to duplicate the context.
**/
BOOLEAN
EFIAPI
HmacSha256Duplicate(
  CONST VOID  *HmacContext,
  VOID        *NewHmacContext);

/**
  Updates the HMAC with data.

  @param[in]  HmacContext  Pointer to the HMAC context.
  @param[in]  Data         Pointer to the data.
  @param[in]  DataSize     Size of the data in bytes.

  @retval TRUE   Data was updated successfully.
  @retval FALSE  Failed to update the data.
**/
BOOLEAN
EFIAPI
HmacSha256Update(
  VOID        *HmacContext,
  CONST VOID  *Data,
  UINTN       DataSize);

/**
  Finalizes the HMAC and produces the HMAC value.

  @param[in]  HmacContext  Pointer to the HMAC context.
  @param[out] HmacValue    Pointer to the buffer that receives the HMAC value.

  @retval TRUE   HMAC value was produced successfully.
  @retval FALSE  Failed to produce the HMAC value.
**/
BOOLEAN
EFIAPI
HmacSha256Final(
  VOID   *HmacContext,
  UINT8  *HmacValue);

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
BOOLEAN
EFIAPI
HmacSha256All(
  CONST VOID   *Data,
  UINTN        DataSize,
  CONST UINT8  *Key,
  UINTN        KeySize,
  UINT8        *HmacValue);

/**
  Creates a new HMAC context.

  @return  Pointer to the new HMAC context.
**/
VOID *
EFIAPI
HmacSha384New(
  VOID);

/**
  Frees an HMAC context.

  @param[in]  HmacCtx  Pointer to the HMAC context to be freed.
**/
VOID
EFIAPI
HmacSha384Free(
  VOID  *HmacCtx);

/**
  Sets the key for an HMAC context.

  @param[in]  HmacContext  Pointer to the HMAC context.
  @param[in]  Key          Pointer to the key.
  @param[in]  KeySize      Size of the key in bytes.

  @retval TRUE   Key was set successfully.
  @retval FALSE  Failed to set the key.
**/
BOOLEAN
EFIAPI
HmacSha384SetKey(
  VOID         *HmacContext,
  CONST UINT8  *Key,
  UINTN        KeySize);

/**
  Duplicates an HMAC context.

  @param[in]  HmacContext     Pointer to the source HMAC context.
  @param[out] NewHmacContext  Pointer to the new HMAC context.

  @retval TRUE   Context was duplicated successfully.
  @retval FALSE  Failed to duplicate the context.
**/
BOOLEAN
EFIAPI
HmacSha384Duplicate(
  CONST VOID  *HmacContext,
  VOID        *NewHmacContext);

/**
  Updates the HMAC with data.

  @param[in]  HmacContext  Pointer to the HMAC context.
  @param[in]  Data         Pointer to the data.
  @param[in]  DataSize     Size of the data in bytes.

  @retval TRUE   Data was updated successfully.
  @retval FALSE  Failed to update the data.
**/
BOOLEAN
EFIAPI
HmacSha384Update(
  VOID        *HmacContext,
  CONST VOID  *Data,
  UINTN       DataSize);

/**
  Finalizes the HMAC and produces the HMAC value.

  @param[in]  HmacContext  Pointer to the HMAC context.
  @param[out] HmacValue    Pointer to the buffer that receives the HMAC value.

  @retval TRUE   HMAC value was produced successfully.
  @retval FALSE  Failed to produce the HMAC value.
**/
BOOLEAN
EFIAPI
HmacSha384Final(
  VOID   *HmacContext,
  UINT8  *HmacValue);

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
BOOLEAN
EFIAPI
HmacSha384All(
  CONST VOID   *Data,
  UINTN        DataSize,
  CONST UINT8  *Key,
  UINTN        KeySize,
  UINT8        *HmacValue);

/**
 * @typedef SHARED_HASH_GET_CONTEXT_SIZE
 * @brief Function pointer type for retrieving the size of the Hash context buffer.
 * @return The size, in bytes, of the context buffer required for hash operations.
 */
UINTN
EFIAPI
Md5GetContextSize(
  VOID);

/**
 * @typedef SHARED_HASH_INIT
 * @brief Function pointer type for initializing Hash context.
 * @param[out] ContHashContextext Pointer to the Hash context being initialized.
 * @return TRUE if Hash context initialization succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Md5Init(
  OUT VOID  *HashContext);

/**
 * @typedef SHARED_HASH_UPDATE
 * @brief Function pointer type for updating Hash context with input data.
 * @param[in, out] HashContext Pointer to the Hash context.
 * @param[in] Data Pointer to the buffer containing the data to be hashed.
 * @param[in] DataSize Size of Data buffer in bytes.
 * @return TRUE if Hash data digest succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Md5Update(
  IN OUT VOID    *HashContext,
  IN CONST VOID  *Data,
  IN UINTN       DataSize);

/**
 * @typedef SHARED_HASH_FINAL
 * @brief Function pointer type for finalizing Hash context and retrieving the digest.
 * @param[out] HashDigest Pointer to a buffer that receives the Hash digest value.
 * @param[in, out] HashContext Pointer to the Hash context.
 * @return TRUE if Hash finalization succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Md5Final(
  IN OUT  VOID   *HashContext,
  OUT     UINT8  *HashDigest);

/**
 * @typedef SHARED_HASH_ALL
 * @brief Function pointer type for performing Hash hash on a data buffer.
 * @param[in] Data Pointer to the buffer containing the data to be hashed.
 * @param[in] DataSize Size of Data buffer in bytes.
 * @param[out] HashDigest Pointer to a buffer that receives the Hash digest value.
 * @return TRUE if Hash hash succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Md5HashAll(
  IN CONST VOID  *Data,
  IN UINTN       DataSize,
  OUT UINT8      *HashDigest);

/**
 * @typedef SHARED_HASH_DUPLICATE
 * @brief Function pointer type for duplicating an existing HASH context.
 * @param[in] HashContext Pointer to Hash context being copied.
 * @param[out] NewHashContext Pointer to new Hash context.
 * @return TRUE if Hash context copy succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Md5Duplicate(
  IN CONST VOID  *HashContext,
  OUT VOID       *NewHashContext);

/**
 * @typedef SHARED_HASH_GET_CONTEXT_SIZE
 * @brief Function pointer type for retrieving the size of the Hash context buffer.
 * @return The size, in bytes, of the context buffer required for hash operations.
 */
UINTN
EFIAPI
Sha1GetContextSize(
  VOID);

/**
 * @typedef SHARED_HASH_INIT
 * @brief Function pointer type for initializing Hash context.
 * @param[out] ContHashContextext Pointer to the Hash context being initialized.
 * @return TRUE if Hash context initialization succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha1Init(
  OUT VOID  *HashContext);

/**
 * @typedef SHARED_HASH_UPDATE
 * @brief Function pointer type for updating Hash context with input data.
 * @param[in, out] HashContext Pointer to the Hash context.
 * @param[in] Data Pointer to the buffer containing the data to be hashed.
 * @param[in] DataSize Size of Data buffer in bytes.
 * @return TRUE if Hash data digest succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha1Update(
  IN OUT VOID    *HashContext,
  IN CONST VOID  *Data,
  IN UINTN       DataSize);

/**
 * @typedef SHARED_HASH_FINAL
 * @brief Function pointer type for finalizing Hash context and retrieving the digest.
 * @param[out] HashDigest Pointer to a buffer that receives the Hash digest value.
 * @param[in, out] HashContext Pointer to the Hash context.
 * @return TRUE if Hash finalization succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha1Final(
  IN OUT  VOID   *HashContext,
  OUT     UINT8  *HashDigest);

/**
 * @typedef SHARED_HASH_ALL
 * @brief Function pointer type for performing Hash hash on a data buffer.
 * @param[in] Data Pointer to the buffer containing the data to be hashed.
 * @param[in] DataSize Size of Data buffer in bytes.
 * @param[out] HashDigest Pointer to a buffer that receives the Hash digest value.
 * @return TRUE if Hash hash succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha1HashAll(
  IN CONST VOID  *Data,
  IN UINTN       DataSize,
  OUT UINT8      *HashDigest);

/**
 * @typedef SHARED_HASH_DUPLICATE
 * @brief Function pointer type for duplicating an existing HASH context.
 * @param[in] HashContext Pointer to Hash context being copied.
 * @param[out] NewHashContext Pointer to new Hash context.
 * @return TRUE if Hash context copy succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha1Duplicate(
  IN CONST VOID  *HashContext,
  OUT VOID       *NewHashContext);

/**
 * @typedef SHARED_HASH_GET_CONTEXT_SIZE
 * @brief Function pointer type for retrieving the size of the Hash context buffer.
 * @return The size, in bytes, of the context buffer required for hash operations.
 */
UINTN
EFIAPI
Sha256GetContextSize(
  VOID);

/**
 * @typedef SHARED_HASH_INIT
 * @brief Function pointer type for initializing Hash context.
 * @param[out] ContHashContextext Pointer to the Hash context being initialized.
 * @return TRUE if Hash context initialization succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha256Init(
  OUT VOID  *HashContext);

/**
 * @typedef SHARED_HASH_UPDATE
 * @brief Function pointer type for updating Hash context with input data.
 * @param[in, out] HashContext Pointer to the Hash context.
 * @param[in] Data Pointer to the buffer containing the data to be hashed.
 * @param[in] DataSize Size of Data buffer in bytes.
 * @return TRUE if Hash data digest succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha256Update(
  IN OUT VOID    *HashContext,
  IN CONST VOID  *Data,
  IN UINTN       DataSize);

/**
 * @typedef SHARED_HASH_FINAL
 * @brief Function pointer type for finalizing Hash context and retrieving the digest.
 * @param[out] HashDigest Pointer to a buffer that receives the Hash digest value.
 * @param[in, out] HashContext Pointer to the Hash context.
 * @return TRUE if Hash finalization succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha256Final(
  IN OUT  VOID   *HashContext,
  OUT     UINT8  *HashDigest);

/**
 * @typedef SHARED_HASH_ALL
 * @brief Function pointer type for performing Hash hash on a data buffer.
 * @param[in] Data Pointer to the buffer containing the data to be hashed.
 * @param[in] DataSize Size of Data buffer in bytes.
 * @param[out] HashDigest Pointer to a buffer that receives the Hash digest value.
 * @return TRUE if Hash hash succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha256HashAll(
  IN CONST VOID  *Data,
  IN UINTN       DataSize,
  OUT UINT8      *HashDigest);

/**
 * @typedef SHARED_HASH_DUPLICATE
 * @brief Function pointer type for duplicating an existing HASH context.
 * @param[in] HashContext Pointer to Hash context being copied.
 * @param[out] NewHashContext Pointer to new Hash context.
 * @return TRUE if Hash context copy succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha256Duplicate(
  IN CONST VOID  *HashContext,
  OUT VOID       *NewHashContext);

/**
 * @typedef SHARED_HASH_GET_CONTEXT_SIZE
 * @brief Function pointer type for retrieving the size of the Hash context buffer.
 * @return The size, in bytes, of the context buffer required for hash operations.
 */
UINTN
EFIAPI
Sha512GetContextSize(
  VOID);

/**
 * @typedef SHARED_HASH_INIT
 * @brief Function pointer type for initializing Hash context.
 * @param[out] ContHashContextext Pointer to the Hash context being initialized.
 * @return TRUE if Hash context initialization succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha512Init(
  OUT VOID  *HashContext);

/**
 * @typedef SHARED_HASH_UPDATE
 * @brief Function pointer type for updating Hash context with input data.
 * @param[in, out] HashContext Pointer to the Hash context.
 * @param[in] Data Pointer to the buffer containing the data to be hashed.
 * @param[in] DataSize Size of Data buffer in bytes.
 * @return TRUE if Hash data digest succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha512Update(
  IN OUT VOID    *HashContext,
  IN CONST VOID  *Data,
  IN UINTN       DataSize);

/**
 * @typedef SHARED_HASH_FINAL
 * @brief Function pointer type for finalizing Hash context and retrieving the digest.
 * @param[out] HashDigest Pointer to a buffer that receives the Hash digest value.
 * @param[in, out] HashContext Pointer to the Hash context.
 * @return TRUE if Hash finalization succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha512Final(
  IN OUT  VOID   *HashContext,
  OUT     UINT8  *HashDigest);

/**
 * @typedef SHARED_HASH_ALL
 * @brief Function pointer type for performing Hash hash on a data buffer.
 * @param[in] Data Pointer to the buffer containing the data to be hashed.
 * @param[in] DataSize Size of Data buffer in bytes.
 * @param[out] HashDigest Pointer to a buffer that receives the Hash digest value.
 * @return TRUE if Hash hash succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha512HashAll(
  IN CONST VOID  *Data,
  IN UINTN       DataSize,
  OUT UINT8      *HashDigest);

/**
 * @typedef SHARED_HASH_DUPLICATE
 * @brief Function pointer type for duplicating an existing HASH context.
 * @param[in] HashContext Pointer to Hash context being copied.
 * @param[out] NewHashContext Pointer to new Hash context.
 * @return TRUE if Hash context copy succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sha512Duplicate(
  IN CONST VOID  *HashContext,
  OUT VOID       *NewHashContext);

/**
 * @typedef SHARED_HASH_GET_CONTEXT_SIZE
 * @brief Function pointer type for retrieving the size of the Hash context buffer.
 * @return The size, in bytes, of the context buffer required for hash operations.
 */
UINTN
EFIAPI
Sm3GetContextSize(
  VOID);

/**
 * @typedef SHARED_HASH_INIT
 * @brief Function pointer type for initializing Hash context.
 * @param[out] ContHashContextext Pointer to the Hash context being initialized.
 * @return TRUE if Hash context initialization succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sm3Init(
  OUT VOID  *HashContext);

/**
 * @typedef SHARED_HASH_UPDATE
 * @brief Function pointer type for updating Hash context with input data.
 * @param[in, out] HashContext Pointer to the Hash context.
 * @param[in] Data Pointer to the buffer containing the data to be hashed.
 * @param[in] DataSize Size of Data buffer in bytes.
 * @return TRUE if Hash data digest succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sm3Update(
  IN OUT VOID    *HashContext,
  IN CONST VOID  *Data,
  IN UINTN       DataSize);

/**
 * @typedef SHARED_HASH_FINAL
 * @brief Function pointer type for finalizing Hash context and retrieving the digest.
 * @param[out] HashDigest Pointer to a buffer that receives the Hash digest value.
 * @param[in, out] HashContext Pointer to the Hash context.
 * @return TRUE if Hash finalization succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sm3Final(
  IN OUT  VOID   *HashContext,
  OUT     UINT8  *HashDigest);

/**
 * @typedef SHARED_HASH_ALL
 * @brief Function pointer type for performing Hash hash on a data buffer.
 * @param[in] Data Pointer to the buffer containing the data to be hashed.
 * @param[in] DataSize Size of Data buffer in bytes.
 * @param[out] HashDigest Pointer to a buffer that receives the Hash digest value.
 * @return TRUE if Hash hash succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sm3HashAll(
  IN CONST VOID  *Data,
  IN UINTN       DataSize,
  OUT UINT8      *HashDigest);

/**
 * @typedef SHARED_HASH_DUPLICATE
 * @brief Function pointer type for duplicating an existing HASH context.
 * @param[in] HashContext Pointer to Hash context being copied.
 * @param[out] NewHashContext Pointer to new Hash context.
 * @return TRUE if Hash context copy succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
Sm3Duplicate(
  IN CONST VOID  *HashContext,
  OUT VOID       *NewHashContext);

/**
 * @typedef SHARED_AES_GET_CONTEXT_SIZE
 * @brief Function pointer type for retrieving the size of the AES context buffer.
 * @return The size, in bytes, of the context buffer required for AES operations.
 */
UINTN
EFIAPI
AesGetContextSize(
  VOID);

/**
 * @typedef SHARED_AES_INIT
 * @brief Function pointer type for initializing AES context.
 * @param[out] AesContext Pointer to AES context being initialized.
 * @param[in] Key Pointer to the user-supplied AES key.
 * @param[in] KeyLength Length of AES key in bits.
 * @return TRUE if AES context initialization succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
AesInit(
  OUT VOID        *AesContext,
  IN CONST UINT8  *Key,
  IN UINTN        KeyLength);

/**
 * @typedef SHARED_AES_CBC_ENCRYPT
 * @brief Function pointer type for performing AES encryption in CBC mode.
 * @param[in] AesContext Pointer to the AES context.
 * @param[in] Input Pointer to the buffer containing the data to be encrypted.
 * @param[in] InputSize Size of the Input buffer in bytes.
 * @param[in] Ivec Pointer to initialization vector.
 * @param[out] Output Pointer to a buffer that receives the AES encryption output.
 * @return TRUE if AES encryption succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
AesCbcEncrypt(
  IN VOID         *AesContext,
  IN CONST UINT8  *Input,
  IN UINTN        InputSize,
  IN CONST UINT8  *Ivec,
  OUT UINT8       *Output);

/**
 * @typedef SHARED_AES_CBC_DECRYPT
 * @brief Function pointer type for performing AES decryption in CBC mode.
 * @param[in] AesContext Pointer to the AES context.
 * @param[in] Input Pointer to the buffer containing the data to be decrypted.
 * @param[in] InputSize Size of the Input buffer in bytes.
 * @param[in] Ivec Pointer to initialization vector.
 * @param[out] Output Pointer to a buffer that receives the AES decryption output.
 * @return TRUE if AES decryption succeeded, FALSE otherwise.
 */
BOOLEAN
EFIAPI
AesCbcDecrypt(
  IN VOID         *AesContext,
  IN CONST UINT8  *Input,
  IN UINTN        InputSize,
  IN CONST UINT8  *Ivec,
  OUT UINT8       *Output);

/**
 * @typedef SHARED_AEAD_AES_GCM_ENCRYPT
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
BOOLEAN
EFIAPI
AeadAesGcmEncrypt(
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
  OUT  UINTN        *DataOutSize);

/**
 * @typedef SHARED_AEAD_AES_GCM_DECRYPT
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
BOOLEAN
EFIAPI
AeadAesGcmDecrypt(
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
  OUT  UINTN        *DataOutSize);

/**
 * @typedef BIG_NUM_INIT
 * @brief Function pointer type for initializing a big number.
 * @return A pointer to the initialized big number.
 */
VOID *
EFIAPI
BigNumInit(
  VOID);

/**
 * @typedef SHARED_BIG_NUM_FROM_BIN
 * @brief Function pointer type for creating a big number from a binary buffer.
 * @param Buf The binary buffer.
 * @param Len The length of the binary buffer.
 * @return A pointer to the created big number.
 */
VOID *
EFIAPI
BigNumFromBin(
  IN CONST UINT8  *Buf,
  IN UINTN        Len);

/**
 * @typedef SHARED_BIG_NUM_TO_BIN
 * @brief Function pointer type for converting a big number to a binary buffer.
 * @param Bn The big number to convert.
 * @param Buf The output binary buffer.
 * @return The length of the binary buffer.
 */
INTN
EFIAPI
BigNumToBin(
  IN CONST VOID  *Bn,
  OUT UINT8      *Buf);

/**
 * @typedef SHARED_BIG_NUM_FREE
 * @brief Function pointer type for freeing a big number.
 * @param Bn The big number to free.
 * @param Clear Whether to clear the memory before freeing.
 */
VOID
EFIAPI
BigNumFree(
  IN VOID     *Bn,
  IN BOOLEAN  Clear);

/**
 * @typedef SHARED_BIG_NUM_ADD
 * @brief Function pointer type for adding two big numbers.
 * @param BnA The first big number.
 * @param BnB The second big number.
 * @param BnRes The result of the addition.
 * @return TRUE if the addition was successful, FALSE otherwise.
 */
BOOLEAN
EFIAPI
BigNumAdd(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  OUT VOID       *BnRes);

/**
 * @typedef SHARED_BIG_NUM_SUB
 * @brief Function pointer type for subtracting one big number from another.
 * @param BnA The big number to subtract from.
 * @param BnB The big number to subtract.
 * @param BnRes The result of the subtraction.
 * @return TRUE if the subtraction was successful, FALSE otherwise.
 */
BOOLEAN
EFIAPI
BigNumSub(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  OUT VOID       *BnRes);

/**
 * @typedef SHARED_BIG_NUM_MOD
 * @brief Function pointer type for computing the modulus of two big numbers.
 * @param BnA The dividend big number.
 * @param BnB The divisor big number.
 * @param BnRes The result of the modulus operation.
 * @return TRUE if the modulus operation was successful, FALSE otherwise.
 */
BOOLEAN
EFIAPI
BigNumMod(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  OUT VOID       *BnRes);

/**
 * @typedef SHARED_BIG_NUM_EXP_MOD
 * @brief Function pointer type for computing the modular exponentiation of a big number.
 * @param BnA The base big number.
 * @param BnP The exponent big number.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular exponentiation.
 * @return TRUE if the modular exponentiation was successful, FALSE otherwise.
 */
BOOLEAN
EFIAPI
BigNumExpMod(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnP,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes);

/**
 * @typedef SHARED_BIG_NUM_INVERSE_MOD
 * @brief Function pointer type for computing the modular inverse of a big number.
 * @param BnA The big number to invert.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular inverse.
 * @return TRUE if the modular inverse was successful, FALSE otherwise.
 */
BOOLEAN
EFIAPI
BigNumInverseMod(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes);

/**
 * @typedef SHARED_BIG_NUM_DIV
 * @brief Function pointer type for dividing one big number by another.
 * @param BnA The dividend big number.
 * @param BnB The divisor big number.
 * @param BnRes The result of the division.
 * @return TRUE if the division was successful, FALSE otherwise.
 */
BOOLEAN
EFIAPI
BigNumDiv(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  OUT VOID       *BnRes);

/**
 * @typedef SHARED_BIG_NUM_MUL_MOD
 * @brief Function pointer type for computing the modular multiplication of two big numbers.
 * @param BnA The first big number.
 * @param BnB The second big number.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular multiplication.
 * @return TRUE if the modular multiplication was successful, FALSE otherwise.
 */
BOOLEAN
EFIAPI
BigNumMulMod(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes);

/**
 * @typedef SHARED_BIG_NUM_CMP
 * @brief Function pointer type for comparing two big numbers.
 * @param BnA The first big number.
 * @param BnB The second big number.
 * @return A negative value if BnA < BnB, zero if BnA == BnB, and a positive value if BnA > BnB.
 */
INTN
EFIAPI
BigNumCmp(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB);

/**
 * @typedef SHARED_BIG_NUM_BITS
 * @brief Function pointer type for getting the number of bits in a big number.
 * @param Bn The big number.
 * @return The number of bits in the big number.
 */
UINTN
EFIAPI
BigNumBits(
  IN CONST VOID  *Bn);

/**
 * @typedef SHARED_BIG_NUM_BYTES
 * @brief Function pointer type for getting the number of bytes in a big number.
 * @param Bn The big number.
 * @return The number of bytes in the big number.
 */
UINTN
EFIAPI
BigNumBytes(
  IN CONST VOID  *Bn);

/**
 * @typedef SHARED_BIG_NUM_IS_WORD
 * @brief Function pointer type for checking if a big number is equal to a specific word.
 * @param Bn The big number.
 * @param Num The word to compare against.
 * @return TRUE if the big number is equal to the word, FALSE otherwise.
 */
BOOLEAN
EFIAPI
BigNumIsWord(
  IN CONST VOID  *Bn,
  IN UINTN       Num);

/**
 * @typedef SHARED_BIG_NUM_IS_ODD
 * @brief Function pointer type for checking if a big number is odd.
 * @param Bn The big number.
 * @return TRUE if the big number is odd, FALSE otherwise.
 */
BOOLEAN
EFIAPI
BigNumIsOdd(
  IN CONST VOID  *Bn);

/**
 * @typedef SHARED_BIG_NUM_COPY
 * @brief Function pointer type for copying one big number to another.
 * @param BnDst The destination big number.
 * @param BnSrc The source big number.
 * @return A pointer to the destination big number.
 */
VOID *
EFIAPI
BigNumCopy(
  OUT VOID       *BnDst,
  IN CONST VOID  *BnSrc);

/**
 * @typedef SHARED_BIG_NUM_VALUE_ONE
 * @brief Function pointer type for getting a big number representing the value one.
 * @return A pointer to the big number representing the value one.
 */
CONST VOID *
EFIAPI
BigNumValueOne(
  VOID);

/**
 * @typedef SHARED_BIG_NUM_R_SHIFT
 * @brief Function pointer type for right-shifting a big number by a specified number of bits.
 * @param Bn The big number to shift.
 * @param N The number of bits to shift.
 * @param BnRes The result of the right shift.
 * @return TRUE if the right shift was successful, FALSE otherwise.
 */
BOOLEAN
EFIAPI
BigNumRShift(
  IN CONST VOID  *Bn,
  IN UINTN       N,
  OUT VOID       *BnRes);

/**
 * @typedef SHARED_BIG_NUM_CONST_TIME
 * @brief Function pointer type for performing a constant-time operation on a big number.
 * @param Bn The big number.
 */
VOID
EFIAPI
BigNumConstTime(
  IN VOID  *Bn);

/**
 * @typedef SHARED_BIG_NUM_SQR_MOD
 * @brief Function pointer type for computing the modular square of a big number.
 * @param BnA The big number to square.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular square.
 * @return TRUE if the modular square was successful, FALSE otherwise.
 */
BOOLEAN
EFIAPI
BigNumSqrMod(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes);

/**
 * @typedef SHARED_BIG_NUM_NEW_CONTEXT
 * @brief Function pointer type for creating a new big number context.
 * @return A pointer to the new big number context.
 */
VOID *
EFIAPI
BigNumNewContext(
  VOID);

/**
 * @typedef SHARED_BIG_NUM_CONTEXT_FREE
 * @brief Function pointer type for freeing a big number context.
 * @param BnCtx The big number context to free.
 */
VOID
EFIAPI
BigNumContextFree(
  IN VOID  *BnCtx);

/**
 * @typedef SHARED_BIG_NUM_SET_UINT
 * @brief Function pointer type for setting a big number to a specific unsigned integer value.
 * @param Bn The big number.
 * @param Val The unsigned integer value.
 * @return TRUE if the operation was successful, FALSE otherwise.
 */
BOOLEAN
EFIAPI
BigNumSetUint(
  IN VOID   *Bn,
  IN UINTN  Val);

/**
 * @typedef SHARED_BIG_NUM_ADD_MOD
 * @brief Function pointer type for computing the modular addition of two big numbers.
 * @param BnA The first big number.
 * @param BnB The second big number.
 * @param BnM The modulus big number.
 * @param BnRes The result of the modular addition.
 * @return TRUE if the modular addition was successful, FALSE otherwise.
 */
BOOLEAN
EFIAPI
BigNumAddMod(
  IN CONST VOID  *BnA,
  IN CONST VOID  *BnB,
  IN CONST VOID  *BnM,
  OUT VOID       *BnRes);

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
BOOLEAN
EFIAPI
HkdfSha256ExtractAndExpand(
  IN   CONST UINT8  *Key,
  IN   UINTN        KeySize,
  IN   CONST UINT8  *Salt,
  IN   UINTN        SaltSize,
  IN   CONST UINT8  *Info,
  IN   UINTN        InfoSize,
  OUT  UINT8        *Out,
  IN   UINTN        OutSize);

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
BOOLEAN
EFIAPI
HkdfSha256Extract(
  IN CONST UINT8  *Key,
  IN UINTN        KeySize,
  IN CONST UINT8  *Salt,
  IN UINTN        SaltSize,
  OUT UINT8       *PrkOut,
  UINTN           PrkOutSize);

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
BOOLEAN
EFIAPI
HkdfSha256Expand(
  IN   CONST UINT8  *Prk,
  IN   UINTN        PrkSize,
  IN   CONST UINT8  *Info,
  IN   UINTN        InfoSize,
  OUT  UINT8        *Out,
  IN   UINTN        OutSize);

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
BOOLEAN
EFIAPI
HkdfSha384ExtractAndExpand(
  IN   CONST UINT8  *Key,
  IN   UINTN        KeySize,
  IN   CONST UINT8  *Salt,
  IN   UINTN        SaltSize,
  IN   CONST UINT8  *Info,
  IN   UINTN        InfoSize,
  OUT  UINT8        *Out,
  IN   UINTN        OutSize);

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
BOOLEAN
EFIAPI
HkdfSha384Extract(
  IN CONST UINT8  *Key,
  IN UINTN        KeySize,
  IN CONST UINT8  *Salt,
  IN UINTN        SaltSize,
  OUT UINT8       *PrkOut,
  UINTN           PrkOutSize);

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
BOOLEAN
EFIAPI
HkdfSha384Expand(
  IN   CONST UINT8  *Prk,
  IN   UINTN        PrkSize,
  IN   CONST UINT8  *Info,
  IN   UINTN        InfoSize,
  OUT  UINT8        *Out,
  IN   UINTN        OutSize);

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
BOOLEAN
EFIAPI
RsaGetPrivateKeyFromPem(
  IN   CONST UINT8  *PemData,
  IN   UINTN        PemSize,
  IN   CONST CHAR8  *Password,
  OUT  VOID         **RsaContext);

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
BOOLEAN
EFIAPI
EcGetPrivateKeyFromPem(
  IN   CONST UINT8  *PemData,
  IN   UINTN        PemSize,
  IN   CONST CHAR8  *Password,
  OUT  VOID         **EcContext);

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
BOOLEAN
EFIAPI
AuthenticodeVerify(
  IN  CONST UINT8  *AuthData,
  IN  UINTN        DataSize,
  IN  CONST UINT8  *TrustedCert,
  IN  UINTN        CertSize,
  IN  CONST UINT8  *ImageHash,
  IN  UINTN        HashSize);

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
BOOLEAN
EFIAPI
Pkcs1v2Encrypt(
  IN   CONST UINT8  *PublicKey,
  IN   UINTN        PublicKeySize,
  IN   UINT8        *InData,
  IN   UINTN        InDataSize,
  IN   CONST UINT8  *PrngSeed   OPTIONAL,
  IN   UINTN        PrngSeedSize   OPTIONAL,
  OUT  UINT8        **EncryptedData,
  OUT  UINTN        *EncryptedDataSize);

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
BOOLEAN
EFIAPI
Pkcs1v2Decrypt(
  IN   CONST UINT8  *PrivateKey,
  IN   UINTN        PrivateKeySize,
  IN   UINT8        *EncryptedData,
  IN   UINTN        EncryptedDataSize,
  OUT  UINT8        **OutData,
  OUT  UINTN        *OutDataSize);

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
BOOLEAN
EFIAPI
RsaOaepEncrypt(
  IN   VOID         *RsaContext,
  IN   UINT8        *InData,
  IN   UINTN        InDataSize,
  IN   CONST UINT8  *PrngSeed   OPTIONAL,
  IN   UINTN        PrngSeedSize   OPTIONAL,
  IN   UINT16       DigestLen OPTIONAL,
  OUT  UINT8        **EncryptedData,
  OUT  UINTN        *EncryptedDataSize);

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
BOOLEAN
EFIAPI
RsaOaepDecrypt(
  IN   VOID    *RsaContext,
  IN   UINT8   *EncryptedData,
  IN   UINTN   EncryptedDataSize,
  IN   UINT16  DigestLen OPTIONAL,
  OUT  UINT8   **OutData,
  OUT  UINTN   *OutDataSize);

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
BOOLEAN
EFIAPI
Pkcs5HashPassword(
  IN  UINTN        PasswordLength,
  IN  CONST CHAR8  *Password,
  IN  UINTN        SaltLength,
  IN  CONST UINT8  *Salt,
  IN  UINTN        IterationCount,
  IN  UINTN        DigestSize,
  IN  UINTN        KeyLength,
  OUT UINT8        *OutKey);

/**
  Get the signer's certificates from PKCS#7 signed data as described in "PKCS #7:
  Cryptographic Message Syntax Standard". The input signed data could be wrapped
  in a ContentInfo structure.
  If P7Data, CertStack, StackLength, TrustedCert or CertLength is NULL, then
  return FALSE. If P7Length overflow, then return FALSE.
  If this interface is not supported, then return FALSE.
  @param[in]  P7Data       Pointer to the PKCS#7 message to verify.
  @param[in]  P7Length     Length of the PKCS#7 message in bytes.
  @param[out] CertStack    Pointer to Signer's certificates retrieved from P7Data.
                           It's caller's responsibility to free the buffer with
                           Pkcs7FreeSigners().
                           This data structure is EFI_CERT_STACK type.
  @param[out] StackLength  Length of signer's certificates in bytes.
  @param[out] TrustedCert  Pointer to a trusted certificate from Signer's certificates.
                           It's caller's responsibility to free the buffer with
                           Pkcs7FreeSigners().
  @param[out] CertLength   Length of the trusted certificate in bytes.
  @retval  TRUE            The operation is finished successfully.
  @retval  FALSE           Error occurs during the operation.
  @retval  FALSE           This interface is not supported.
**/
BOOLEAN
EFIAPI
Pkcs7GetSigners(
  IN  CONST UINT8  *P7Data,
  IN  UINTN        P7Length,
  OUT UINT8        **CertStack,
  OUT UINTN        *StackLength,
  OUT UINT8        **TrustedCert,
  OUT UINTN        *CertLength);

/**
Wrap function to use free() to free allocated memory for certificates.
If this interface is not supported, then ASSERT().
@param[in]  Certs        Pointer to the certificates to be freed.
**/
VOID
EFIAPI
Pkcs7FreeSigners(
  IN  UINT8  *Certs);

/**
  Retrieves all embedded certificates from PKCS#7 signed data as described in "PKCS #7:
  Cryptographic Message Syntax Standard", and outputs two certificate lists chained and
  unchained to the signer's certificates.
  The input signed data could be wrapped in a ContentInfo structure.
  @param[in]  P7Data            Pointer to the PKCS#7 message.
  @param[in]  P7Length          Length of the PKCS#7 message in bytes.
  @param[out] SignerChainCerts  Pointer to the certificates list chained to signer's
                                certificate. It's caller's responsibility to free the buffer
                                with Pkcs7FreeSigners().
                                This data structure is EFI_CERT_STACK type.
  @param[out] ChainLength       Length of the chained certificates list buffer in bytes.
  @param[out] UnchainCerts      Pointer to the unchained certificates lists. It's caller's
                                responsibility to free the buffer with Pkcs7FreeSigners().
                                This data structure is EFI_CERT_STACK type.
  @param[out] UnchainLength     Length of the unchained certificates list buffer in bytes.
  @retval  TRUE         The operation is finished successfully.
  @retval  FALSE        Error occurs during the operation.
**/
BOOLEAN
EFIAPI
Pkcs7GetCertificatesList(
  IN  CONST UINT8  *P7Data,
  IN  UINTN        P7Length,
  OUT UINT8        **SignerChainCerts,
  OUT UINTN        *ChainLength,
  OUT UINT8        **UnchainCerts,
  OUT UINTN        *UnchainLength);

/**
  Creates a PKCS#7 signedData as described in "PKCS #7: Cryptographic Message
  Syntax Standard, version 1.5". This interface is only intended to be used for
  application to perform PKCS#7 functionality validation.
  If this interface is not supported, then return FALSE.
  @param[in]  PrivateKey       Pointer to the PEM-formatted private key data for
                               data signing.
  @param[in]  PrivateKeySize   Size of the PEM private key data in bytes.
  @param[in]  KeyPassword      NULL-terminated passphrase used for encrypted PEM
                               key data.
  @param[in]  InData           Pointer to the content to be signed.
  @param[in]  InDataSize       Size of InData in bytes.
  @param[in]  SignCert         Pointer to signer's DER-encoded certificate to sign with.
  @param[in]  SignCertSize     Size of signer's DER-encoded certificate to sign with.  // MU_CHANGE [TCBZ3925] - Pkcs7Sign is broken
  @param[in]  OtherCerts       Pointer to an optional additional set of certificates to
                               include in the PKCS#7 signedData (e.g. any intermediate
                               CAs in the chain).
  @param[out] SignedData       Pointer to output PKCS#7 signedData. It's caller's
                               responsibility to free the buffer with FreePool().
  @param[out] SignedDataSize   Size of SignedData in bytes.
  @retval     TRUE             PKCS#7 data signing succeeded.
  @retval     FALSE            PKCS#7 data signing failed.
  @retval     FALSE            This interface is not supported.
**/
BOOLEAN
EFIAPI
Pkcs7Sign(
  IN   CONST UINT8  *PrivateKey,
  IN   UINTN        PrivateKeySize,
  IN   CONST UINT8  *KeyPassword,
  IN   UINT8        *InData,
  IN   UINTN        InDataSize,
  IN   CONST UINT8  *SignCert,
  IN   UINTN        SignCertSize,
  IN   UINT8        *OtherCerts      OPTIONAL,
  OUT  UINT8        **SignedData,
  OUT  UINTN        *SignedDataSize);

/**
  Verifies the validity of a PKCS#7 signed data as described in "PKCS #7:
  Cryptographic Message Syntax Standard". The input signed data could be wrapped
  in a ContentInfo structure.

  If P7Data, TrustedCert or InData is NULL, then return FALSE.
  If P7Length, CertLength or DataLength overflow, then return FALSE.

  Caution: This function may receive untrusted input.
  UEFI Authenticated Variable is external input, so this function will do basic
  check for PKCS#7 data structure.

  @param[in]  P7Data       Pointer to the PKCS#7 message to verify.
  @param[in]  P7Length     Length of the PKCS#7 message in bytes.
  @param[in]  TrustedCert  Pointer to a trusted/root certificate encoded in DER, which
                           is used for certificate chain verification.
  @param[in]  CertLength   Length of the trusted certificate in bytes.
  @param[in]  InData       Pointer to the content to be verified.
  @param[in]  DataLength   Length of InData in bytes.

  @retval  TRUE  The specified PKCS#7 signed data is valid.
  @retval  FALSE Invalid PKCS#7 signed data.

**/
BOOLEAN
EFIAPI
Pkcs7Verify(
  IN  CONST UINT8  *P7Data,
  IN  UINTN        P7Length,
  IN  CONST UINT8  *TrustedCert,
  IN  UINTN        CertLength,
  IN  CONST UINT8  *InData,
  IN  UINTN        DataLength);

/**
  This function receives a PKCS7 formatted signature, and then verifies that
  the specified Enhanced or Extended Key Usages (EKU's) are present in the end-entity
  leaf signing certificate.
  Note that this function does not validate the certificate chain.
  Applications for custom EKU's are quite flexible. For example, a policy EKU
  may be present in an Issuing Certificate Authority (CA), and any sub-ordinate
  certificate issued might also contain this EKU, thus constraining the
  sub-ordinate certificate.  Other applications might allow a certificate
  embedded in a device to specify that other Object Identifiers (OIDs) are
  present which contains binary data specifying custom capabilities that
  the device is able to do.
  @param[in]  Pkcs7Signature       The PKCS#7 signed information content block. An array
                                   containing the content block with both the signature,
                                   the signer's certificate, and any necessary intermediate
                                   certificates.
  @param[in]  Pkcs7SignatureSize   Number of bytes in Pkcs7Signature.
  @param[in]  RequiredEKUs         Array of null-terminated strings listing OIDs of
                                   required EKUs that must be present in the signature.
  @param[in]  RequiredEKUsSize     Number of elements in the RequiredEKUs string array.
  @param[in]  RequireAllPresent    If this is TRUE, then all of the specified EKU's
                                   must be present in the leaf signer.  If it is
                                   FALSE, then we will succeed if we find any
                                   of the specified EKU's.
  @retval EFI_SUCCESS              The required EKUs were found in the signature.
  @retval EFI_INVALID_PARAMETER    A parameter was invalid.
  @retval EFI_NOT_FOUND            One or more EKU's were not found in the signature.
**/
RETURN_STATUS
EFIAPI
VerifyEKUsInPkcs7Signature(
  IN  CONST UINT8   *Pkcs7Signature,
  IN  CONST UINT32  SignatureSize,
  IN  CONST CHAR8   *RequiredEKUs[],
  IN  CONST UINT32  RequiredEKUsSize,
  IN  BOOLEAN       RequireAllPresent);

/**
  Extracts the attached content from a PKCS#7 signed data if existed. The input signed
  data could be wrapped in a ContentInfo structure.
  If P7Data, Content, or ContentSize is NULL, then return FALSE. If P7Length overflow,
  then return FALSE. If the P7Data is not correctly formatted, then return FALSE.
  Caution: This function may receive untrusted input. So this function will do
           basic check for PKCS#7 data structure.
  @param[in]   P7Data       Pointer to the PKCS#7 signed data to process.
  @param[in]   P7Length     Length of the PKCS#7 signed data in bytes.
  @param[out]  Content      Pointer to the extracted content from the PKCS#7 signedData.
                            It's caller's responsibility to free the buffer with FreePool().
  @param[out]  ContentSize  The size of the extracted content in bytes.
  @retval     TRUE          The P7Data was correctly formatted for processing.
  @retval     FALSE         The P7Data was not correctly formatted for processing.
**/
BOOLEAN
EFIAPI
Pkcs7GetAttachedContent(
  IN  CONST UINT8  *P7Data,
  IN  UINTN        P7Length,
  OUT VOID         **Content,
  OUT UINTN        *ContentSize);

/**
  Allocates and Initializes one Diffie-Hellman Context for subsequent use.
  @return  Pointer to the Diffie-Hellman Context that has been initialized.
           If the allocations fails, DhNew() returns NULL.
           If the interface is not supported, DhNew() returns NULL.
**/
VOID *
EFIAPI
DhNew(
  VOID);

/**
  Release the specified DH context.
  If the interface is not supported, then ASSERT().
  @param[in]  DhContext  Pointer to the DH context to be released.
**/
VOID
EFIAPI
DhFree(
  IN  VOID  *DhContext);

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
BOOLEAN
EFIAPI
DhGenerateParameter(
  IN OUT  VOID   *DhContext,
  IN      UINTN  Generator,
  IN      UINTN  PrimeLength,
  OUT     UINT8  *Prime);

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
BOOLEAN
EFIAPI
DhSetParameter(
  IN OUT  VOID         *DhContext,
  IN      UINTN        Generator,
  IN      UINTN        PrimeLength,
  IN      CONST UINT8  *Prime);

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
BOOLEAN
EFIAPI
DhGenerateKey(
  IN OUT  VOID   *DhContext,
  OUT     UINT8  *PublicKey,
  IN OUT  UINTN  *PublicKeySize);

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
BOOLEAN
EFIAPI
DhComputeKey(
  IN OUT  VOID         *DhContext,
  IN      CONST UINT8  *PeerPublicKey,
  IN      UINTN        PeerPublicKeySize,
  OUT     UINT8        *Key,
  IN OUT  UINTN        *KeySize);

#endif