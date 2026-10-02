/** @file
  Cryptographic Library Information Implementation.

  This module provides version information for the underlying OpenSSL library.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <Library/BaseLib.h>
#include <Guid/CryptoOpId.h>
#include "InternalCryptLib.h"

/**
  Gets the cryptographic provider version information.

  This function returns the version string of the cryptographic provider.
  For this OpenSSL implementation, it returns the OpenSSL version string.

  @param[out]     Buffer       Pointer to the buffer to receive the version string.
                               If NULL, the required buffer size is returned in BufferSize.
  @param[in,out]  BufferSize   On input, the size of the buffer in bytes.
                               On output, the size of the data copied to the buffer (including null terminator).
                               If Buffer is NULL, returns the required buffer size.

  @retval  EFI_SUCCESS            The version string was successfully copied to the buffer or
                                  the BufferSize was updated when a NULL buffer was provided.
  @retval  EFI_BUFFER_TOO_SMALL   The buffer is too small. BufferSize contains the required size.
  @retval  EFI_INVALID_PARAMETER  BufferSize is NULL.
**/
EFI_STATUS
EFIAPI
GetCryptoProviderVersionString (
  OUT    CHAR8  *Buffer,
  IN OUT UINTN  *BufferSize
  )
{
  CONST CHAR8  *VersionText;
  UINTN        RequiredSize;

  if (BufferSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  VersionText  = OPENSSL_VERSION_TEXT;
  RequiredSize = AsciiStrSize (VersionText);

  if (Buffer == NULL) {
    *BufferSize = RequiredSize;
    return EFI_SUCCESS;
  }

  if (*BufferSize < RequiredSize) {
    *BufferSize = RequiredSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  AsciiStrCpyS (Buffer, *BufferSize, VersionText);
  *BufferSize = RequiredSize;

  return EFI_SUCCESS;
}

#include "CryptOpCapability.h"

//
// ECIT (EFI Crypto Indicator Table) capability reporting -- public dispatcher.
// =========================================================================
//
// GetCryptoOpCapability(OpIdGuid, Buffer, BufferSize) is the single public
// entry point exported by BaseCryptLib for the ECIT mechanism. Callers pass
// a GUID identifying the crypto operation they care about (e.g. PKCS#7
// verify) and receive an unordered set of algorithm OIDs the linked
// crypto provider can accept for that operation.
//
// Architecture
// ------------
// This dispatcher is intentionally minimal: a static GUID -> handler
// table (mCryptoOpDispatch) and a linear search. Per-op handlers live
// next to the verify pipeline they describe (e.g.
// Pk/CryptPkcs7OpCapability.c next to Pk/CryptPkcs7VerifyCommon.c) so
// that adding or modifying an op never reaches across module boundaries.
//
// Each handler answers "what algorithms can my pipeline accept on the
// linked binary right now?" by querying the OpenSSL provider directly --
// never from a static OID list.
//
// Adding a new op
// ---------------
//   1. Add the GUID to MU_BASECORE/CryptoPkg/Include/Library/BaseCryptLib.h.
//   2. Define the handler in Pk/Crypt<Op>OpCapability.c with prototype
//      EFI_STATUS EFIAPI <Op>OpCapability (CHAR8 *, UINTN *).
//   3. Declare the prototype in CryptOpCapability.h.
//   4. Append one row to mCryptoOpDispatch[] below.
//   5. Wire the new .c into BaseCryptLib.inf and UnitTestHostBaseCryptLib.inf.
//
// Payload format
// --------------
// The handler-produced payload is a CSV-encoded, NUL-terminated ASCII
// string of dotted-decimal OIDs, unordered set semantics (callers must
// not infer preference from position). Empty payload is a single NUL
// byte.
//

//
// GUID storage for gCryptoOpPkcs7VerifyGuid and
// gCryptoOpAuthenticodeVerifyGuid is provided by AutoGen for every
// module that lists those GUIDs in its INF [Guids] block. They are
// declared in <Guid/CryptoOpId.h> and registered in CryptoPkg.dec.
//

/**
  Per-op handler signature. Same shape as the public
  GetCryptoOpCapability minus the OpIdGuid parameter (dispatch already
  matched it).

  @param[out]     Buffer      NULL probes required size, else receives payload.
  @param[in,out]  BufferSize  In: capacity. Out: bytes written or required.

  @retval EFI_SUCCESS           Sizing probe / fetch succeeded.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small; *BufferSize set to required.
**/
typedef
EFI_STATUS
(EFIAPI *CRYPTO_OP_HANDLER)(
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  );

/**
  Single row of the GUID -> handler dispatch table.

  Kept separate from the typedef so the table itself stays grep-friendly
  and easy to extend.
**/
typedef struct {
  CONST EFI_GUID       *OpId;
  CRYPTO_OP_HANDLER    Handler;
} CRYPTO_OP_DISPATCH;

/**
  GUID -> handler dispatch table. One row per supported op. Order is
  irrelevant; lookup is a linear scan and the table is expected to stay
  small (<10 entries).
**/
STATIC CONST CRYPTO_OP_DISPATCH  mCryptoOpDispatch[] = {
  { &gCryptoOpPkcs7VerifyGuid,        Pkcs7VerifyOpCapability        },
  { &gCryptoOpAuthenticodeVerifyGuid, AuthenticodeVerifyOpCapability },
};

/**
  Return the capability descriptor for a given crypto operation.

  The descriptor is operation-specific. For verify ops it is a CSV-encoded,
  NUL-terminated ASCII string of algorithm OIDs in dotted-decimal form
  (e.g. "1.2.840.113549.1.1.11,1.2.840.10045.4.3.2"). The OIDs are an
  UNORDERED SET: callers must not infer preference from position.

  Standard sizing pattern:
    1. Call with Buffer == NULL to learn the required size in *BufferSize.
    2. Allocate a buffer of that size.
    3. Call again with Buffer != NULL to fetch the payload.

  Implementation: linear scan of mCryptoOpDispatch[] for a matching
  GUID; on hit, delegate to the per-op handler.

  @param[in]      OpIdGuid    GUID identifying the crypto operation.
                              See <Library/BaseCryptLib.h> for known
                              op-ID GUID externs (e.g.
                              gCryptoOpPkcs7VerifyGuid).
  @param[out]     Buffer      NULL to probe required size, else receives
                              the payload.
  @param[in,out]  BufferSize  In: size of Buffer in bytes. Out: bytes
                              written, or bytes required (always includes
                              the trailing NUL).

  @retval EFI_SUCCESS           Buffer populated, or size returned when
                                Buffer == NULL.
  @retval EFI_BUFFER_TOO_SMALL  Buffer non-NULL and capacity insufficient;
                                *BufferSize is set to the required size.
  @retval EFI_NOT_FOUND         OpIdGuid is not registered in this binary.
  @retval EFI_INVALID_PARAMETER OpIdGuid or BufferSize is NULL.
**/
EFI_STATUS
EFIAPI
GetCryptoOpCapability (
  IN     CONST EFI_GUID  *OpIdGuid,
  OUT    VOID            *Buffer       OPTIONAL,
  IN OUT UINTN           *BufferSize
  )
{
  UINTN  Index;

  if ((OpIdGuid == NULL) || (BufferSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  for (Index = 0; Index < ARRAY_SIZE (mCryptoOpDispatch); Index++) {
    if (CompareGuid (OpIdGuid, mCryptoOpDispatch[Index].OpId)) {
      return mCryptoOpDispatch[Index].Handler ((CHAR8 *)Buffer, BufferSize);
    }
  }

  return EFI_NOT_FOUND;
}
