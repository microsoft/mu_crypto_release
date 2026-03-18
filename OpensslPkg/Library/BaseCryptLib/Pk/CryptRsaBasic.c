/** @file
  RSA Asymmetric Cipher Wrapper Implementation over OpenSSL.

  This file implements following APIs which provide basic capabilities for RSA:
  1) RsaNew
  2) RsaFree
  3) RsaSetKey
  4) RsaPkcs1Verify

  Uses OpenSSL 3.x EVP_PKEY provider-based APIs instead of deprecated RSA APIs.

Copyright (c) 2009 - 2020, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include "CryptRsaPkeyCtx.h"

/**
  Invalidate (free) the cached EVP_PKEY in the RSA context.

  @param[in,out]  RsaPkeyCtx  Pointer to RSA_PKEY_CTX whose cache to invalidate.

**/
VOID
RsaInvalidatePkey (
  IN OUT  RSA_PKEY_CTX  *RsaPkeyCtx
  )
{
  if (RsaPkeyCtx->Pkey != NULL) {
    EVP_PKEY_free (RsaPkeyCtx->Pkey);
    RsaPkeyCtx->Pkey = NULL;
  }
}

/**
  Build (or return cached) EVP_PKEY from the stored BIGNUM components.

  @param[in,out]  RsaPkeyCtx  Pointer to RSA_PKEY_CTX holding key components.

  @return  Pointer to EVP_PKEY on success, or NULL on failure.

**/
EVP_PKEY *
RsaBuildEvpPkey (
  IN OUT  RSA_PKEY_CTX  *RsaPkeyCtx
  )
{
  OSSL_PARAM_BLD  *ParamBld;
  OSSL_PARAM      *Params;
  EVP_PKEY_CTX    *PkeyCtx;
  EVP_PKEY        *Pkey;
  INT32           Selection;

  if (RsaPkeyCtx->Pkey != NULL) {
    return RsaPkeyCtx->Pkey;
  }

  //
  // N and E are the minimum required components.
  //
  if ((RsaPkeyCtx->N == NULL) || (RsaPkeyCtx->E == NULL)) {
    return NULL;
  }

  ParamBld = NULL;
  Params   = NULL;
  PkeyCtx  = NULL;
  Pkey     = NULL;

  ParamBld = OSSL_PARAM_BLD_new ();
  if (ParamBld == NULL) {
    return NULL;
  }

  if (OSSL_PARAM_BLD_push_BN (ParamBld, OSSL_PKEY_PARAM_RSA_N, RsaPkeyCtx->N) != 1) {
    goto _Exit;
  }

  if (OSSL_PARAM_BLD_push_BN (ParamBld, OSSL_PKEY_PARAM_RSA_E, RsaPkeyCtx->E) != 1) {
    goto _Exit;
  }

  if (RsaPkeyCtx->D != NULL) {
    Selection = EVP_PKEY_KEYPAIR;

    if (OSSL_PARAM_BLD_push_BN (ParamBld, OSSL_PKEY_PARAM_RSA_D, RsaPkeyCtx->D) != 1) {
      goto _Exit;
    }

    if (RsaPkeyCtx->P != NULL) {
      if (OSSL_PARAM_BLD_push_BN (ParamBld, OSSL_PKEY_PARAM_RSA_FACTOR1, RsaPkeyCtx->P) != 1) {
        goto _Exit;
      }
    }

    if (RsaPkeyCtx->Q != NULL) {
      if (OSSL_PARAM_BLD_push_BN (ParamBld, OSSL_PKEY_PARAM_RSA_FACTOR2, RsaPkeyCtx->Q) != 1) {
        goto _Exit;
      }
    }

    if (RsaPkeyCtx->Dp != NULL) {
      if (OSSL_PARAM_BLD_push_BN (ParamBld, OSSL_PKEY_PARAM_RSA_EXPONENT1, RsaPkeyCtx->Dp) != 1) {
        goto _Exit;
      }
    }

    if (RsaPkeyCtx->Dq != NULL) {
      if (OSSL_PARAM_BLD_push_BN (ParamBld, OSSL_PKEY_PARAM_RSA_EXPONENT2, RsaPkeyCtx->Dq) != 1) {
        goto _Exit;
      }
    }

    if (RsaPkeyCtx->QInv != NULL) {
      if (OSSL_PARAM_BLD_push_BN (ParamBld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, RsaPkeyCtx->QInv) != 1) {
        goto _Exit;
      }
    }
  } else {
    Selection = EVP_PKEY_PUBLIC_KEY;
  }

  Params = OSSL_PARAM_BLD_to_param (ParamBld);
  if (Params == NULL) {
    goto _Exit;
  }

  PkeyCtx = EVP_PKEY_CTX_new_from_name (NULL, "RSA", NULL);
  if (PkeyCtx == NULL) {
    goto _Exit;
  }

  if (EVP_PKEY_fromdata_init (PkeyCtx) != 1) {
    goto _Exit;
  }

  if (EVP_PKEY_fromdata (PkeyCtx, &Pkey, Selection, Params) != 1) {
    Pkey = NULL;
    goto _Exit;
  }

  //
  // Cache the built EVP_PKEY.
  //
  RsaPkeyCtx->Pkey = Pkey;

_Exit:
  if (PkeyCtx != NULL) {
    EVP_PKEY_CTX_free (PkeyCtx);
  }

  if (Params != NULL) {
    OSSL_PARAM_free (Params);
  }

  if (ParamBld != NULL) {
    OSSL_PARAM_BLD_free (ParamBld);
  }

  return RsaPkeyCtx->Pkey;
}

/**
  Extract all RSA BIGNUM key components from an EVP_PKEY into RSA_PKEY_CTX.

  @param[in,out]  RsaPkeyCtx  Pointer to RSA_PKEY_CTX to populate.
  @param[in]      Pkey        EVP_PKEY from which to extract components.

  @retval  TRUE   Components extracted successfully.
  @retval  FALSE  Extraction failed.

**/
BOOLEAN
RsaExtractBigNums (
  IN OUT  RSA_PKEY_CTX  *RsaPkeyCtx,
  IN      EVP_PKEY      *Pkey
  )
{
  //
  // Free any existing BIGNUMs.
  //
  BN_free (RsaPkeyCtx->N);
  BN_free (RsaPkeyCtx->E);
  BN_clear_free (RsaPkeyCtx->D);
  BN_clear_free (RsaPkeyCtx->P);
  BN_clear_free (RsaPkeyCtx->Q);
  BN_clear_free (RsaPkeyCtx->Dp);
  BN_clear_free (RsaPkeyCtx->Dq);
  BN_clear_free (RsaPkeyCtx->QInv);

  RsaPkeyCtx->N    = NULL;
  RsaPkeyCtx->E    = NULL;
  RsaPkeyCtx->D    = NULL;
  RsaPkeyCtx->P    = NULL;
  RsaPkeyCtx->Q    = NULL;
  RsaPkeyCtx->Dp   = NULL;
  RsaPkeyCtx->Dq   = NULL;
  RsaPkeyCtx->QInv = NULL;

  //
  // Extract public components (required).
  //
  if (EVP_PKEY_get_bn_param (Pkey, OSSL_PKEY_PARAM_RSA_N, &RsaPkeyCtx->N) != 1) {
    return FALSE;
  }

  if (EVP_PKEY_get_bn_param (Pkey, OSSL_PKEY_PARAM_RSA_E, &RsaPkeyCtx->E) != 1) {
    return FALSE;
  }

  //
  // Extract private components (optional -- may not be present for public keys).
  //
  EVP_PKEY_get_bn_param (Pkey, OSSL_PKEY_PARAM_RSA_D, &RsaPkeyCtx->D);
  EVP_PKEY_get_bn_param (Pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &RsaPkeyCtx->P);
  EVP_PKEY_get_bn_param (Pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &RsaPkeyCtx->Q);
  EVP_PKEY_get_bn_param (Pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &RsaPkeyCtx->Dp);
  EVP_PKEY_get_bn_param (Pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &RsaPkeyCtx->Dq);
  EVP_PKEY_get_bn_param (Pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &RsaPkeyCtx->QInv);

  return TRUE;
}

/**
  Retrieve a pointer to EVP message digest object.

  @param[in]  HashSize  Size of the message digest in bytes.

  @return  Pointer to EVP_MD, or NULL if unsupported size.

**/
STATIC
CONST
EVP_MD *
GetEvpMdFromHashSize (
  IN  UINTN  HashSize
  )
{
  switch (HashSize) {
    case MD5_DIGEST_SIZE:
      return EVP_md5 ();
    case SHA1_DIGEST_SIZE:
      return EVP_sha1 ();
    case SHA256_DIGEST_SIZE:
      return EVP_sha256 ();
    case SHA384_DIGEST_SIZE:
      return EVP_sha384 ();
    case SHA512_DIGEST_SIZE:
      return EVP_sha512 ();
    default:
      return NULL;
  }
}

/**
  Allocates and initializes one RSA context for subsequent use.

  @return  Pointer to the RSA context that has been initialized.
           If the allocations fails, RsaNew() returns NULL.

**/
VOID *
EFIAPI
RsaNew (
  VOID
  )
{
  //
  // Allocate and zero-initialize an RSA_PKEY_CTX structure.
  //
  return (VOID *)AllocateZeroPool (sizeof (RSA_PKEY_CTX));
}

/**
  Release the specified RSA context.

  @param[in]  RsaContext  Pointer to the RSA context to be released.

**/
VOID
EFIAPI
RsaFree (
  IN  VOID  *RsaContext
  )
{
  RSA_PKEY_CTX  *RsaPkeyCtx;

  if (RsaContext == NULL) {
    return;
  }

  RsaPkeyCtx = (RSA_PKEY_CTX *)RsaContext;

  //
  // Free cached EVP_PKEY.
  //
  if (RsaPkeyCtx->Pkey != NULL) {
    EVP_PKEY_free (RsaPkeyCtx->Pkey);
  }

  //
  // Free public components.
  //
  BN_free (RsaPkeyCtx->N);
  BN_free (RsaPkeyCtx->E);

  //
  // Securely free private components.
  //
  BN_clear_free (RsaPkeyCtx->D);
  BN_clear_free (RsaPkeyCtx->P);
  BN_clear_free (RsaPkeyCtx->Q);
  BN_clear_free (RsaPkeyCtx->Dp);
  BN_clear_free (RsaPkeyCtx->Dq);
  BN_clear_free (RsaPkeyCtx->QInv);

  FreePool (RsaPkeyCtx);
}

/**
  Sets the tag-designated key component into the established RSA context.

  This function sets the tag-designated RSA key component into the established
  RSA context from the user-specified non-negative integer (octet string format
  represented in RSA PKCS#1).
  If BigNumber is NULL, then the specified key component in RSA context is cleared.

  If RsaContext is NULL, then return FALSE.

  @param[in, out]  RsaContext  Pointer to RSA context being set.
  @param[in]       KeyTag      Tag of RSA key component being set.
  @param[in]       BigNumber   Pointer to octet integer buffer.
                               If NULL, then the specified key component in RSA
                               context is cleared.
  @param[in]       BnSize      Size of big number buffer in bytes.
                               If BigNumber is NULL, then it is ignored.

  @retval  TRUE   RSA key component was set successfully.
  @retval  FALSE  Invalid RSA key component tag.

**/
BOOLEAN
EFIAPI
RsaSetKey (
  IN OUT  VOID         *RsaContext,
  IN      RSA_KEY_TAG  KeyTag,
  IN      CONST UINT8  *BigNumber,
  IN      UINTN        BnSize
  )
{
  RSA_PKEY_CTX  *RsaPkeyCtx;
  BIGNUM        **BnTarget;

  //
  // Check input parameters.
  //
  if ((RsaContext == NULL) || (BnSize > INT_MAX)) {
    return FALSE;
  }

  RsaPkeyCtx = (RSA_PKEY_CTX *)RsaContext;

  //
  // Invalidate cached EVP_PKEY since a key component is changing.
  //
  RsaInvalidatePkey (RsaPkeyCtx);

  //
  // Select the target BIGNUM pointer based on key tag.
  //
  switch (KeyTag) {
    case RsaKeyN:
      BnTarget = &RsaPkeyCtx->N;
      break;
    case RsaKeyE:
      BnTarget = &RsaPkeyCtx->E;
      break;
    case RsaKeyD:
      BnTarget = &RsaPkeyCtx->D;
      break;
    case RsaKeyP:
      BnTarget = &RsaPkeyCtx->P;
      break;
    case RsaKeyQ:
      BnTarget = &RsaPkeyCtx->Q;
      break;
    case RsaKeyDp:
      BnTarget = &RsaPkeyCtx->Dp;
      break;
    case RsaKeyDq:
      BnTarget = &RsaPkeyCtx->Dq;
      break;
    case RsaKeyQInv:
      BnTarget = &RsaPkeyCtx->QInv;
      break;
    default:
      return FALSE;
  }

  //
  // If BigNumber is NULL, clear the component.
  //
  if (BigNumber == NULL) {
    if (*BnTarget != NULL) {
      if ((KeyTag == RsaKeyN) || (KeyTag == RsaKeyE)) {
        BN_free (*BnTarget);
      } else {
        BN_clear_free (*BnTarget);
      }

      *BnTarget = NULL;
    }

    return TRUE;
  }

  //
  // Convert octet string to BIGNUM.
  //
  *BnTarget = BN_bin2bn (BigNumber, (UINT32)BnSize, *BnTarget);
  if (*BnTarget == NULL) {
    return FALSE;
  }

  return TRUE;
}

/**
  Verifies the RSA-SSA signature with EMSA-PKCS1-v1_5 encoding scheme defined in
  RSA PKCS#1.

  If RsaContext is NULL, then return FALSE.
  If MessageHash is NULL, then return FALSE.
  If Signature is NULL, then return FALSE.
  If HashSize is not equal to the size of MD5, SHA-1, SHA-256, SHA-384 or SHA-512 digest, then return FALSE.

  @param[in]  RsaContext   Pointer to RSA context for signature verification.
  @param[in]  MessageHash  Pointer to octet message hash to be checked.
  @param[in]  HashSize     Size of the message hash in bytes.
  @param[in]  Signature    Pointer to RSA PKCS1-v1_5 signature to be verified.
  @param[in]  SigSize      Size of signature in bytes.

  @retval  TRUE   Valid signature encoded in PKCS1-v1_5.
  @retval  FALSE  Invalid signature or invalid RSA context.

**/
BOOLEAN
EFIAPI
RsaPkcs1Verify (
  IN  VOID         *RsaContext,
  IN  CONST UINT8  *MessageHash,
  IN  UINTN        HashSize,
  IN  CONST UINT8  *Signature,
  IN  UINTN        SigSize
  )
{
  RSA_PKEY_CTX    *RsaPkeyCtx;
  EVP_PKEY        *Pkey;
  EVP_PKEY_CTX    *PkeyCtx;
  CONST EVP_MD    *Md;
  BOOLEAN         Result;

  //
  // Check input parameters.
  //
  if ((RsaContext == NULL) || (MessageHash == NULL) || (Signature == NULL)) {
    return FALSE;
  }

  if ((SigSize > INT_MAX) || (SigSize == 0)) {
    return FALSE;
  }

  //
  // Determine the message digest algorithm according to digest size.
  //
  Md = GetEvpMdFromHashSize (HashSize);
  if (Md == NULL) {
    return FALSE;
  }

  RsaPkeyCtx = (RSA_PKEY_CTX *)RsaContext;
  Result      = FALSE;
  PkeyCtx     = NULL;

  //
  // Build EVP_PKEY from stored key components.
  //
  Pkey = RsaBuildEvpPkey (RsaPkeyCtx);
  if (Pkey == NULL) {
    return FALSE;
  }

  PkeyCtx = EVP_PKEY_CTX_new_from_pkey (NULL, Pkey, NULL);
  if (PkeyCtx == NULL) {
    goto _Exit;
  }

  if (EVP_PKEY_verify_init (PkeyCtx) != 1) {
    goto _Exit;
  }

  if (EVP_PKEY_CTX_set_rsa_padding (PkeyCtx, RSA_PKCS1_PADDING) <= 0) {
    goto _Exit;
  }

  if (EVP_PKEY_CTX_set_signature_md (PkeyCtx, Md) <= 0) {
    goto _Exit;
  }

  if (EVP_PKEY_verify (PkeyCtx, Signature, SigSize, MessageHash, HashSize) == 1) {
    Result = TRUE;
  }

_Exit:
  if (PkeyCtx != NULL) {
    EVP_PKEY_CTX_free (PkeyCtx);
  }

  return Result;
}
