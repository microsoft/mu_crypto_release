/** @file
  GetAuthenticodeHash() Null implementation.

  Returns EFI_UNSUPPORTED to indicate this interface is not provided by
  the current library instance (e.g., PEI / Runtime / SEC / SMM phases
  that do not include the Pk/CryptAuthenticodeHash.c implementation).

Copyright (C) Microsoft Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"

/**
  Compute the PE/COFF Authenticode-style image hash of a loaded image.

  Return EFI_UNSUPPORTED to indicate this interface is not supported.

  @param[in]   FileBuffer  Pointer to the in-memory PE/COFF image.
  @param[in]   FileSize    Size of FileBuffer in bytes.
  @param[in]   HashType    Signature-type GUID identifying the hash
                           algorithm to use.
  @param[out]  Digest      Caller-provided buffer that receives the
                           computed digest.
  @param[out]  DigestSize  On success, receives the digest length in
                           bytes.

  @retval EFI_UNSUPPORTED  This interface is not supported.

**/
EFI_STATUS
EFIAPI
GetAuthenticodeHash (
  IN  VOID            *FileBuffer,
  IN  UINTN           FileSize,
  IN  CONST EFI_GUID  *HashType,
  OUT UINT8           *Digest,
  OUT UINTN           *DigestSize
  )
{
  ASSERT (FALSE);
  return EFI_UNSUPPORTED;
}
