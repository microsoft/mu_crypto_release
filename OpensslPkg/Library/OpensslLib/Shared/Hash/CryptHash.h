#ifndef _CRYPT_HASH_H_
#define _CRYPT_HASH_H_

#include <Uefi.h>
#include "CrtLibSupport.h"

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

/**
  Structure that defines the function pointers for a specific hash algorithm.

  @param Signature       Signature of the structure to verify this is the intended structure.
  @param GetContextSize  Function pointer to retrieve the size of the context buffer required for hash operations.
  @param Init            Function pointer to initialize the hash context.
  @param Update          Function pointer to update the hash context with input data.
  @param Final           Function pointer to finalize the hash context and retrieve the digest.
  @param Duplicate       Function pointer to duplicate an existing hash context.
  @param HashAll         Function pointer to perform hash on a data buffer.
**/
typedef struct {
  UINT64                    Signature;
  HashGetContextSizeFunc    GetContextSize;
  HashInitFunc              Init;
  HashUpdateFunc            Update;
  HashFinalFunc             Final;
  HashDuplicateFunc         Duplicate;
  HashHashAllFunc           HashAll;
} HashFunctionApi;

/**
  Structure that holds the function pointers for all supported hash algorithms.

  @param MD5    Function pointers for MD5 hash algorithm.
  @param SHA1   Function pointers for SHA-1 hash algorithm.
  @param SHA256 Function pointers for SHA-256 hash algorithm.
  @param SHA384 Function pointers for SHA-384 hash algorithm.
  @param SHA512 Function pointers for SHA-512 hash algorithm.
**/
typedef struct {
  HashFunctionApi    MD5;
  HashFunctionApi    SHA1;
  HashFunctionApi    SHA256;
  HashFunctionApi    SHA384;
  HashFunctionApi    SHA512;
  HashFunctionApi    SM3;
} HashFunctions;

/**
  Initializes the MD5 function pointers in the HashFunctions structure.

  @param[out]  HashFuncs  Pointer to the structure that will hold the MD5 function pointers.
**/
VOID
EFIAPI
InitMd5Support (
  HashFunctions  *HashFuncs
  );

/**
  Initializes the SHA-1 function pointers in the HashFunctions structure.

  @param[out]  HashFuncs  Pointer to the structure that will hold the SHA-1 function pointers.
**/
VOID
InitSha1Support (
  HashFunctions  *HashFuncs
  );

/**
  Initializes the SHA-256 function pointers in the HashFunctions structure.

  @param[out]  HashFuncs  Pointer to the structure that will hold the SHA-256 function pointers.
**/
VOID
InitSha256Support (
  HashFunctions  *HashFuncs
  );

/**
  Initializes the SHA-512 function pointers in the HashFunctions structure.

  @param[out]  HashFuncs  Pointer to the structure that will hold the SHA-512 function pointers.
**/
VOID
InitSha512Support (
  HashFunctions  *HashFuncs
  );

/**
  Initializes the SM3 function pointers in the HashFunctions structure.

  @param[out]  HashFuncs  Pointer to the structure that will hold the SM3 function pointers.
**/
VOID
InitSm3Support (
  HashFunctions  *HashFuncs
  );

/**
  Initializes all supported hash function pointers in the HashFunctions structure.

  @param[out]  HashFuncs  Pointer to the structure that will hold the hash function pointers.
**/
VOID
EFIAPI
HashInitFunctions (
  HashFunctions  *HashFuncs
  );

#endif // _CRYPT_HASH_H_
