/** @file
  ECIT capability reporting -- PKCS#7 verify op handler.

  Reports the algorithm OIDs the BaseCryptLib PKCS#7 verify pipeline
  (CryptPkcs7VerifyCommon.c -> CMS_verify) will accept. The pipeline
  hands signatures straight to the linked OpenSSL provider, so the
  predicate is "anything OpenSSL recognises as a signature algorithm" --
  no additional filtering. The common engine in
  Pk/CryptOpCapabilityCommon.c does the heavy lifting; this file
  contributes only the policy.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include "CryptOpCapability.h"

/**
  PKCS#7 verify accept predicate. Accepts every signature NID the
  provider can form: the verify pipeline does not impose extra
  digest/key constraints.

  @param[in]  SigNid  Candidate signature NID (unused).
  @param[in]  Ctx     Unused.

  @retval TRUE   Always.
**/
STATIC
BOOLEAN
EFIAPI
Pkcs7Accept (
  IN INT32  SigNid,
  IN VOID   *Ctx
  )
{
  return TRUE;
}

EFI_STATUS
EFIAPI
Pkcs7VerifyOpCapability (
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  )
{
  return CryptOpEmitProviderSignatureOids (Pkcs7Accept, NULL, Buffer, BufferSize);
}
