/** @file
  Report available Authenticode image-hash digest algorithms.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include "CryptOpCapability.h"

typedef
UINTN
(EFIAPI *AUTH_HASH_GET_CONTEXT_SIZE)(
  VOID
  );

typedef
BOOLEAN
(EFIAPI *AUTH_HASH_INIT)(
  OUT VOID  *HashContext
  );

typedef struct {
  CONST CHAR8                   *DottedOid;
  AUTH_HASH_GET_CONTEXT_SIZE    GetContextSize;
  AUTH_HASH_INIT                Init;
} AUTH_HASH_INFO;

STATIC CONST AUTH_HASH_INFO  mAuthHashInfo[] = {
  { "1.3.14.3.2.26",          Sha1GetContextSize,   Sha1Init   },
  { "2.16.840.1.101.3.4.2.1", Sha256GetContextSize, Sha256Init },
  { "2.16.840.1.101.3.4.2.2", Sha384GetContextSize, Sha384Init },
  { "2.16.840.1.101.3.4.2.3", Sha512GetContextSize, Sha512Init },
};

EFI_STATUS
EFIAPI
AuthenticodeHashOpCapability (
  OUT BASE_CRYPT_OP_CAPABILITY  **Capabilities,
  OUT UINTN                     *CapabilityCount
  )
{
  UINTN        Index;
  UINTN        ContextSize;
  VOID         *Context;
  BOOLEAN      Available;
  CONST CHAR8  *AlgorithmOids[ARRAY_SIZE (mAuthHashInfo)];
  UINTN        AlgorithmCount;

  if (Capabilities != NULL) {
    *Capabilities = NULL;
  }

  if (CapabilityCount != NULL) {
    *CapabilityCount = 0;
  }

  if ((Capabilities == NULL) || (CapabilityCount == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  AlgorithmCount = 0;
  for (Index = 0; Index < ARRAY_SIZE (mAuthHashInfo); Index++) {
    ContextSize = mAuthHashInfo[Index].GetContextSize ();
    if (ContextSize == 0) {
      continue;
    }

    Context = AllocatePool (ContextSize);
    if (Context == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    Available = mAuthHashInfo[Index].Init (Context);
    FreePool (Context);
    if (Available) {
      AlgorithmOids[AlgorithmCount++] = mAuthHashInfo[Index].DottedOid;
    }
  }

  return CryptOpCreateCapabilities (
           AlgorithmOids,
           AlgorithmCount,
           Capabilities,
           CapabilityCount
           );
}
