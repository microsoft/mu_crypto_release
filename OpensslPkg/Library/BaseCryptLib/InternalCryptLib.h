/** @file
  Internal include file for BaseCryptLib.

Copyright (c) 2010 - 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __INTERNAL_CRYPT_LIB_H__
#define __INTERNAL_CRYPT_LIB_H__

#undef _WIN32
#undef _WIN64

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseCryptLib.h>

#include "CrtLibSupport.h"

// MU_CHANGE [BEGIN]
// TODO: remove in near future to stop using deprecated OpenSSL APIs
// #define OPENSSL_NO_DEPRECATED  0
// MU_CHANGE [END]
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OBJ_get0_data(o)  ((o)->data)
#define OBJ_length(o)     ((o)->length)
#endif

/**
  Check input P7Data is a wrapped ContentInfo structure or not. If not construct
  a new structure to wrap P7Data.

  Caution: This function may receive untrusted input.
  UEFI Authenticated Variable is external input, so this function will do basic
  check for PKCS#7 data structure.

  @param[in]  P7Data       Pointer to the PKCS#7 message to verify.
  @param[in]  P7Length     Length of the PKCS#7 message in bytes.
  @param[out] WrapFlag     If TRUE P7Data is a ContentInfo structure, otherwise
                           return FALSE.
  @param[out] WrapData     If return status of this function is TRUE:
                           1) when WrapFlag is TRUE, pointer to P7Data.
                           2) when WrapFlag is FALSE, pointer to a new ContentInfo
                           structure. It's caller's responsibility to free this
                           buffer.
  @param[out] WrapDataSize Length of ContentInfo structure in bytes.

  @retval     TRUE         The operation is finished successfully.
  @retval     FALSE        The operation is failed due to lack of resources.

**/
BOOLEAN
WrapPkcs7Data (
  IN  CONST UINT8  *P7Data,
  IN  UINTN        P7Length,
  OUT BOOLEAN      *WrapFlag,
  OUT UINT8        **WrapData,
  OUT UINTN        *WrapDataSize
  );

/**
  Same as Pkcs7Verify(), but on success also returns the signer's verified
  certificate chain in EFI_CERT_STACK form (signer..anchor). Internal to
  the OpenSSL BaseCryptLib instance; used by AuthenticodeVerifyEx().

  @param[in]   P7Data          PKCS#7 message to verify.
  @param[in]   P7Length        Length of P7Data.
  @param[in]   TrustedCert     DER trust anchor.
  @param[in]   CertLength      Length of TrustedCert.
  @param[in]   InData          Content to verify.
  @param[in]   DataLength      Length of InData.
  @param[out]  SignerChain     Optional EFI_CERT_STACK output; caller frees.
  @param[out]  SignerChainSize Optional length of SignerChain.

  @retval TRUE   Valid PKCS#7 signed data.
  @retval FALSE  Invalid PKCS#7 signed data.
**/
BOOLEAN
EFIAPI
Pkcs7VerifyEx (
  IN  CONST UINT8  *P7Data,
  IN  UINTN        P7Length,
  IN  CONST UINT8  *TrustedCert,
  IN  UINTN        CertLength,
  IN  CONST UINT8  *InData,
  IN  UINTN        DataLength,
  OUT UINT8        **SignerChain      OPTIONAL,
  OUT UINTN        *SignerChainSize   OPTIONAL
  );

#endif
