#ifndef __CRYPT_HMAC_H__
#define __CRYPT_HMAC_H__

#include <Uefi.h>

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

/**
  Structure that holds function pointers for HMAC operations for a specific hash algorithm.
**/
typedef struct _HmacFunctionsApi {
  UINT32               Signature;    ///< Signature of the HMAC function API.
  HmacNewFunc          New;          ///< Function to create a new HMAC context.
  HmacFreeFunc         Free;         ///< Function to free an HMAC context.
  HmacSetKeyFunc       SetKey;       ///< Function to set the key for an HMAC context.
  HmacDuplicateFunc    Duplicate;    ///< Function to duplicate an HMAC context.
  HmacUpdateFunc       Update;       ///< Function to update the HMAC with data.
  HmacFinalFunc        Final;        ///< Function to finalize the HMAC and produce the HMAC value.
  HmacAllFunc          All;          ///< Function to perform the entire HMAC operation in one step.
} HmacFunctionsApi;

/**
  Structure that holds HmacFunctionsApi structures for different hash algorithms.
**/
typedef struct _HmacFunctions {
  HmacFunctionsApi    SHA256;    ///< HMAC function pointers for SHA-256.
  HmacFunctionsApi    SHA384;    ///< HMAC function pointers for SHA-384.
} HmacFunctions;

/**
  Initializes the HMAC function pointers in the HmacFunctions structure.

  @param[out]  Funcs  Pointer to the structure that will hold the HMAC function pointers.
**/
VOID
EFIAPI
HmacInitFunctions (
  HmacFunctions  *Funcs
  );

#endif // __CRYPT_HMAC_H__