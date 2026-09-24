/** @file
  ECIT capability reporting for Authenticode verification.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include "CryptOpCapability.h"

#include <openssl/objects.h>

STATIC
BOOLEAN
EFIAPI
AuthenticodeAccept (
  IN INT32  SigNid,
  IN VOID   *Ctx
  )
{
  INT32  DigestNid;
  INT32  PkNid;

  DigestNid = NID_undef;
  PkNid     = NID_undef;
  if (OBJ_find_sigid_algs (SigNid, &DigestNid, &PkNid) != 1) {
    return FALSE;
  }

  return (BOOLEAN)((DigestNid == NID_undef) ||
                   (DigestNid == NID_sha1) ||
                   (DigestNid == NID_sha256) ||
                   (DigestNid == NID_sha384) ||
                   (DigestNid == NID_sha512));
}

EFI_STATUS
EFIAPI
AuthenticodeVerifyOpCapability (
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  )
{
  return CryptOpEmitProviderSignatureOids (AuthenticodeAccept, NULL, Buffer, BufferSize);
}
