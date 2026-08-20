/** @file
  Null implementation of HashAllByGuid() for library instances that do
  not include the generic buffer-hashing helper (Hash/CryptHashAll.c).

Copyright (C) Microsoft Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"

/**
  Compute the digest of a buffer using the algorithm selected by
  HashType.

  Return EFI_UNSUPPORTED to indicate this interface is not supported.

  @param[in]   HashType    Hash-algorithm GUID identifying the digest
                           algorithm to use.
  @param[in]   Buffer      Pointer to the data to be hashed.
  @param[in]   BufferSize  Size of Buffer in bytes.
  @param[out]  Digest      Caller-provided digest buffer.
  @param[out]  DigestSize  On success, receives the digest length in
                           bytes.

  @retval EFI_UNSUPPORTED  This interface is not supported.

**/
EFI_STATUS
EFIAPI
HashAllByGuid (
  IN  CONST EFI_GUID  *HashType,
  IN  CONST VOID      *Buffer,
  IN  UINTN           BufferSize,
  OUT UINT8           *Digest,
  OUT UINTN           *DigestSize
  )
{
  ASSERT (FALSE);
  return EFI_UNSUPPORTED;
}
