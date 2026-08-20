/** @file
  Generic buffer hashing keyed by a hash-algorithm GUID.

  Implements HashAllByGuid(), a provider-independent one-shot digest
  helper. The caller selects the digest algorithm with a generic
  hash-algorithm GUID (as defined in Protocol/Hash.h) and the raw buffer
  is hashed with the matching BaseCryptLib primitive. This keeps callers
  decoupled from any particular signature-list encoding and from the
  underlying crypto provider (OpenSSL / Mbed TLS).

Copyright (C) Microsoft Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"

#include <Protocol/Hash.h>

//
// One-shot hash primitive signature shared by every BaseCryptLib digest
// (Sha1HashAll, Sha256HashAll, Md5HashAll, ...).
//
typedef
BOOLEAN
(EFIAPI *HASH_ALL_FUNC)(
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  );

typedef struct {
  CONST EFI_GUID    *HashGuid;
  UINTN             DigestSize;
  HASH_ALL_FUNC     HashAll;
} HASH_ALL_INFO;

//
// Supported hash algorithms, keyed by their generic Protocol/Hash.h GUID.
// MD5 and SHA-1 are deprecated interfaces that are only declared by
// BaseCryptLib.h when the corresponding build switch is set, so their
// entries are compiled in under the same guards.
//
STATIC CONST HASH_ALL_INFO  mHashAllInfo[] = {
 #ifdef ENABLE_MD5_DEPRECATED_INTERFACES
  { &gEfiHashAlgorithmMD5Guid,    MD5_DIGEST_SIZE,    Md5HashAll    },
 #endif
 #ifndef DISABLE_SHA1_DEPRECATED_INTERFACES
  { &gEfiHashAlgorithmSha1Guid,   SHA1_DIGEST_SIZE,   Sha1HashAll   },
 #endif
  { &gEfiHashAlgorithmSha256Guid, SHA256_DIGEST_SIZE, Sha256HashAll },
  { &gEfiHashAlgorithmSha384Guid, SHA384_DIGEST_SIZE, Sha384HashAll },
  { &gEfiHashAlgorithmSha512Guid, SHA512_DIGEST_SIZE, Sha512HashAll },
};

#define HASH_ALL_INFO_COUNT  (ARRAY_SIZE (mHashAllInfo))

/**
  Compute the digest of a buffer using the algorithm selected by
  HashType.

  The caller selects the digest algorithm with a generic hash-algorithm
  GUID (as defined in Protocol/Hash.h, e.g. gEfiHashAlgorithmSha256Guid).
  The entire buffer is hashed in a single operation and the digest is
  written to Digest, which must be large enough to hold the largest
  supported digest (at least SHA512_DIGEST_SIZE bytes).

  @param[in]   HashType    Hash-algorithm GUID identifying the digest
                           algorithm to use.
  @param[in]   Buffer      Pointer to the data to be hashed.
  @param[in]   BufferSize  Size of Buffer in bytes.
  @param[out]  Digest      Caller-provided buffer that receives the
                           computed digest. Must be at least
                           SHA512_DIGEST_SIZE bytes.
  @param[out]  DigestSize  On success, receives the digest length in
                           bytes.

  @retval EFI_SUCCESS            Digest was computed successfully.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL.
  @retval EFI_UNSUPPORTED        HashType is not a recognized hash
                                 algorithm.
  @retval EFI_DEVICE_ERROR       The hash primitive failed.
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
  UINTN  Index;

  if ((HashType == NULL) || (Buffer == NULL) ||
      (Digest == NULL) || (DigestSize == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  for (Index = 0; Index < HASH_ALL_INFO_COUNT; Index++) {
    if (CompareGuid (HashType, mHashAllInfo[Index].HashGuid)) {
      if (!mHashAllInfo[Index].HashAll (Buffer, BufferSize, Digest)) {
        return EFI_DEVICE_ERROR;
      }

      *DigestSize = mHashAllInfo[Index].DigestSize;
      return EFI_SUCCESS;
    }
  }

  return EFI_UNSUPPORTED;
}
