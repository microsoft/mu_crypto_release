/** @file
  Mbed TLS hash adapters for the EDK II Crypto PPI.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "MbedTlsHash.h"

#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

STATIC
BOOLEAN
HashParametersValid (
  IN CONST VOID  *Data,
  IN UINTN       DataSize,
  IN CONST VOID  *HashValue
  )
{
  return (BOOLEAN)((HashValue != NULL) && ((Data != NULL) || (DataSize == 0)));
}

UINTN
EFIAPI
MbedTlsSha1GetContextSize (
  VOID
  )
{
  return sizeof (mbedtls_sha1_context);
}

BOOLEAN
EFIAPI
MbedTlsSha1Init (
  OUT VOID  *Context
  )
{
  if (Context == NULL) {
    return FALSE;
  }

  mbedtls_sha1_init (Context);
  if (mbedtls_sha1_starts (Context) != 0) {
    mbedtls_sha1_free (Context);
    return FALSE;
  }

  return TRUE;
}

BOOLEAN
EFIAPI
MbedTlsSha1Duplicate (
  IN CONST VOID  *Context,
  OUT VOID       *NewContext
  )
{
  if ((Context == NULL) || (NewContext == NULL)) {
    return FALSE;
  }

  mbedtls_sha1_clone (NewContext, Context);
  return TRUE;
}

BOOLEAN
EFIAPI
MbedTlsSha1Update (
  IN OUT VOID    *Context,
  IN CONST VOID  *Data,
  IN UINTN       DataSize
  )
{
  if ((Context == NULL) || ((Data == NULL) && (DataSize != 0))) {
    return FALSE;
  }

  return (BOOLEAN)(mbedtls_sha1_update (Context, Data, DataSize) == 0);
}

BOOLEAN
EFIAPI
MbedTlsSha1Final (
  IN OUT VOID  *Context,
  OUT UINT8    *HashValue
  )
{
  INT32  Result;

  if ((Context == NULL) || (HashValue == NULL)) {
    return FALSE;
  }

  Result = mbedtls_sha1_finish (Context, HashValue);
  mbedtls_sha1_free (Context);
  return (BOOLEAN)(Result == 0);
}

BOOLEAN
EFIAPI
MbedTlsSha1HashAll (
  IN CONST VOID  *Data,
  IN UINTN       DataSize,
  OUT UINT8      *HashValue
  )
{
  if (!HashParametersValid (Data, DataSize, HashValue)) {
    return FALSE;
  }

  return (BOOLEAN)(mbedtls_sha1 (Data, DataSize, HashValue) == 0);
}

UINTN
EFIAPI
MbedTlsSha256GetContextSize (
  VOID
  )
{
  return sizeof (mbedtls_sha256_context);
}

BOOLEAN
EFIAPI
MbedTlsSha256Init (
  OUT VOID  *Context
  )
{
  if (Context == NULL) {
    return FALSE;
  }

  mbedtls_sha256_init (Context);
  if (mbedtls_sha256_starts (Context, FALSE) != 0) {
    mbedtls_sha256_free (Context);
    return FALSE;
  }

  return TRUE;
}

BOOLEAN
EFIAPI
MbedTlsSha256Duplicate (
  IN CONST VOID  *Context,
  OUT VOID       *NewContext
  )
{
  if ((Context == NULL) || (NewContext == NULL)) {
    return FALSE;
  }

  mbedtls_sha256_clone (NewContext, Context);
  return TRUE;
}

BOOLEAN
EFIAPI
MbedTlsSha256Update (
  IN OUT VOID    *Context,
  IN CONST VOID  *Data,
  IN UINTN       DataSize
  )
{
  if ((Context == NULL) || ((Data == NULL) && (DataSize != 0))) {
    return FALSE;
  }

  return (BOOLEAN)(mbedtls_sha256_update (Context, Data, DataSize) == 0);
}

BOOLEAN
EFIAPI
MbedTlsSha256Final (
  IN OUT VOID  *Context,
  OUT UINT8    *HashValue
  )
{
  INT32  Result;

  if ((Context == NULL) || (HashValue == NULL)) {
    return FALSE;
  }

  Result = mbedtls_sha256_finish (Context, HashValue);
  mbedtls_sha256_free (Context);
  return (BOOLEAN)(Result == 0);
}

BOOLEAN
EFIAPI
MbedTlsSha256HashAll (
  IN CONST VOID  *Data,
  IN UINTN       DataSize,
  OUT UINT8      *HashValue
  )
{
  if (!HashParametersValid (Data, DataSize, HashValue)) {
    return FALSE;
  }

  return (BOOLEAN)(mbedtls_sha256 (Data, DataSize, HashValue, FALSE) == 0);
}

STATIC
BOOLEAN
MbedTlsSha512InitInternal (
  OUT VOID    *Context,
  IN BOOLEAN  IsSha384
  )
{
  if (Context == NULL) {
    return FALSE;
  }

  mbedtls_sha512_init (Context);
  if (mbedtls_sha512_starts (Context, IsSha384) != 0) {
    mbedtls_sha512_free (Context);
    return FALSE;
  }

  return TRUE;
}

STATIC
BOOLEAN
MbedTlsSha512DuplicateInternal (
  IN CONST VOID  *Context,
  OUT VOID       *NewContext
  )
{
  if ((Context == NULL) || (NewContext == NULL)) {
    return FALSE;
  }

  mbedtls_sha512_clone (NewContext, Context);
  return TRUE;
}

STATIC
BOOLEAN
MbedTlsSha512UpdateInternal (
  IN OUT VOID    *Context,
  IN CONST VOID  *Data,
  IN UINTN       DataSize
  )
{
  if ((Context == NULL) || ((Data == NULL) && (DataSize != 0))) {
    return FALSE;
  }

  return (BOOLEAN)(mbedtls_sha512_update (Context, Data, DataSize) == 0);
}

STATIC
BOOLEAN
MbedTlsSha512FinalInternal (
  IN OUT VOID  *Context,
  OUT UINT8    *HashValue
  )
{
  INT32  Result;

  if ((Context == NULL) || (HashValue == NULL)) {
    return FALSE;
  }

  Result = mbedtls_sha512_finish (Context, HashValue);
  mbedtls_sha512_free (Context);
  return (BOOLEAN)(Result == 0);
}

STATIC
BOOLEAN
MbedTlsSha512HashAllInternal (
  IN CONST VOID  *Data,
  IN UINTN       DataSize,
  OUT UINT8      *HashValue,
  IN BOOLEAN     IsSha384
  )
{
  if (!HashParametersValid (Data, DataSize, HashValue)) {
    return FALSE;
  }

  return (BOOLEAN)(mbedtls_sha512 (Data, DataSize, HashValue, IsSha384) == 0);
}

UINTN
EFIAPI
MbedTlsSha384GetContextSize (
  VOID
  )
{
  return sizeof (mbedtls_sha512_context);
}

BOOLEAN
EFIAPI
MbedTlsSha384Init (
  OUT VOID  *Context
  )
{
  return MbedTlsSha512InitInternal (Context, TRUE);
}

BOOLEAN
EFIAPI
MbedTlsSha384Duplicate (
  IN CONST VOID  *Context,
  OUT VOID       *NewContext
  )
{
  return MbedTlsSha512DuplicateInternal (Context, NewContext);
}

BOOLEAN
EFIAPI
MbedTlsSha384Update (
  IN OUT VOID    *Context,
  IN CONST VOID  *Data,
  IN UINTN       DataSize
  )
{
  return MbedTlsSha512UpdateInternal (Context, Data, DataSize);
}

BOOLEAN
EFIAPI
MbedTlsSha384Final (
  IN OUT VOID  *Context,
  OUT UINT8    *HashValue
  )
{
  return MbedTlsSha512FinalInternal (Context, HashValue);
}

BOOLEAN
EFIAPI
MbedTlsSha384HashAll (
  IN CONST VOID  *Data,
  IN UINTN       DataSize,
  OUT UINT8      *HashValue
  )
{
  return MbedTlsSha512HashAllInternal (Data, DataSize, HashValue, TRUE);
}

UINTN
EFIAPI
MbedTlsSha512GetContextSize (
  VOID
  )
{
  return sizeof (mbedtls_sha512_context);
}

BOOLEAN
EFIAPI
MbedTlsSha512Init (
  OUT VOID  *Context
  )
{
  return MbedTlsSha512InitInternal (Context, FALSE);
}

BOOLEAN
EFIAPI
MbedTlsSha512Duplicate (
  IN CONST VOID  *Context,
  OUT VOID       *NewContext
  )
{
  return MbedTlsSha512DuplicateInternal (Context, NewContext);
}

BOOLEAN
EFIAPI
MbedTlsSha512Update (
  IN OUT VOID    *Context,
  IN CONST VOID  *Data,
  IN UINTN       DataSize
  )
{
  return MbedTlsSha512UpdateInternal (Context, Data, DataSize);
}

BOOLEAN
EFIAPI
MbedTlsSha512Final (
  IN OUT VOID  *Context,
  OUT UINT8    *HashValue
  )
{
  return MbedTlsSha512FinalInternal (Context, HashValue);
}

BOOLEAN
EFIAPI
MbedTlsSha512HashAll (
  IN CONST VOID  *Data,
  IN UINTN       DataSize,
  OUT UINT8      *HashValue
  )
{
  return MbedTlsSha512HashAllInternal (Data, DataSize, HashValue, FALSE);
}

VOID
mbedtls_platform_zeroize (
  VOID    *buf,
  size_t  len
  )
{
  ZeroMem (buf, len);
}
