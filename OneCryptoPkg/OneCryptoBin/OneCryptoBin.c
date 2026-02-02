/** @file
  This file implements the OneCryptoBin protocol initialization and constructor logic.
  It sets up the ONE_CRYPTO_PROTOCOL structure with function pointers for cryptographic operations,
  and provides entry points for MM driver integration and DXE driver integration (AARCH64).

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/OneCryptoCrtLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/TlsLib.h>
#include <Protocol/OneCrypto.h>
#include "OneCryptoBin.h"

#if defined (_MSC_EXTENSIONS)
  #define COMMON_EXPORT_API  __declspec(dllexport)
#elif defined(__GNUC__)
  // noipa = no interprocedural analysis (GCC 8+), prevents LTO from inlining/merging
  #define COMMON_EXPORT_API  __attribute__((used, visibility("default"), externally_visible, noinline, noipa))
#elif defined(__clang__)
  #define COMMON_EXPORT_API  __attribute__((used, visibility("default"), noinline, optnone))
#else
  #define COMMON_EXPORT_API
#endif

ONE_CRYPTO_CONSTRUCTOR_PROTOCOL  *mProtocolInstance = NULL;

/**
  Initialize crypto functionality.

  This function populates the crypto protocol structure with function pointers
  from BaseCryptLib implementations.

  @param[in] CryptoProtocol  Pointer to crypto protocol structure to initialize.
**/
VOID
EFIAPI
CryptoInit (
  IN ONE_CRYPTO_PROTOCOL *CryptoProtocol
  )
{

  if (CryptoProtocol == NULL) {
    return;
  }

  //
  // Set the Crypto Version
  //
  CryptoProtocol->Major    = ONE_CRYPTO_VERSION_MAJOR;
  CryptoProtocol->Minor    = ONE_CRYPTO_VERSION_MINOR;

  //
  // Begin filling out the crypto protocol
  //

  //
  // Initialize HMAC-SHA256 function pointers
  //
  CryptoProtocol->HmacSha256New       = HmacSha256New;
  CryptoProtocol->HmacSha256Free      = HmacSha256Free;
  CryptoProtocol->HmacSha256SetKey    = HmacSha256SetKey;
  CryptoProtocol->HmacSha256Duplicate = HmacSha256Duplicate;
  CryptoProtocol->HmacSha256Update    = HmacSha256Update;
  CryptoProtocol->HmacSha256Final     = HmacSha256Final;
  CryptoProtocol->HmacSha256All       = HmacSha256All;

  //
  // Initialize HMAC-SHA384 function pointers
  //
  CryptoProtocol->HmacSha384New       = HmacSha384New;
  CryptoProtocol->HmacSha384Free      = HmacSha384Free;
  CryptoProtocol->HmacSha384SetKey    = HmacSha384SetKey;
  CryptoProtocol->HmacSha384Duplicate = HmacSha384Duplicate;
  CryptoProtocol->HmacSha384Update    = HmacSha384Update;
  CryptoProtocol->HmacSha384Final     = HmacSha384Final;
  CryptoProtocol->HmacSha384All       = HmacSha384All;

  //
  // Initialize the Big Num function pointers
  //
  CryptoProtocol->BigNumInit        = BigNumInit;
  CryptoProtocol->BigNumFromBin     = BigNumFromBin;
  CryptoProtocol->BigNumToBin       = BigNumToBin;
  CryptoProtocol->BigNumFree        = BigNumFree;
  CryptoProtocol->BigNumAdd         = BigNumAdd;
  CryptoProtocol->BigNumSub         = BigNumSub;
  CryptoProtocol->BigNumMod         = BigNumMod;
  CryptoProtocol->BigNumExpMod      = BigNumExpMod;
  CryptoProtocol->BigNumInverseMod  = BigNumInverseMod;
  CryptoProtocol->BigNumDiv         = BigNumDiv;
  CryptoProtocol->BigNumMulMod      = BigNumMulMod;
  CryptoProtocol->BigNumCmp         = BigNumCmp;
  CryptoProtocol->BigNumBits        = BigNumBits;
  CryptoProtocol->BigNumBytes       = BigNumBytes;
  CryptoProtocol->BigNumIsWord      = BigNumIsWord;
  CryptoProtocol->BigNumIsOdd       = BigNumIsOdd;
  CryptoProtocol->BigNumCopy        = BigNumCopy;
  CryptoProtocol->BigNumValueOne    = BigNumValueOne;
  CryptoProtocol->BigNumRShift      = BigNumRShift;
  CryptoProtocol->BigNumConstTime   = BigNumConstTime;
  CryptoProtocol->BigNumSqrMod      = BigNumSqrMod;
  CryptoProtocol->BigNumNewContext  = BigNumNewContext;
  CryptoProtocol->BigNumContextFree = BigNumContextFree;
  CryptoProtocol->BigNumSetUint     = BigNumSetUint;
  CryptoProtocol->BigNumAddMod      = BigNumAddMod;

  //
  // AES functions
  //
  CryptoProtocol->AeadAesGcmEncrypt = AeadAesGcmEncrypt;
  CryptoProtocol->AeadAesGcmDecrypt = AeadAesGcmDecrypt;
  CryptoProtocol->AesGetContextSize = AesGetContextSize;
  CryptoProtocol->AesInit           = AesInit;
  CryptoProtocol->AesCbcEncrypt     = AesCbcEncrypt;
  CryptoProtocol->AesCbcDecrypt     = AesCbcDecrypt;

  CryptoProtocol->Md5GetContextSize = Md5GetContextSize;
  CryptoProtocol->Md5Init           = Md5Init;
  CryptoProtocol->Md5Update         = Md5Update;
  CryptoProtocol->Md5Final          = Md5Final;
  CryptoProtocol->Md5Duplicate      = Md5Duplicate;
  CryptoProtocol->Md5HashAll        = Md5HashAll;

  CryptoProtocol->Sha1GetContextSize = Sha1GetContextSize;
  CryptoProtocol->Sha1Init           = Sha1Init;
  CryptoProtocol->Sha1Update         = Sha1Update;
  CryptoProtocol->Sha1Final          = Sha1Final;
  CryptoProtocol->Sha1Duplicate      = Sha1Duplicate;
  CryptoProtocol->Sha1HashAll        = Sha1HashAll;

  CryptoProtocol->Sha256GetContextSize = Sha256GetContextSize;
  CryptoProtocol->Sha256Init           = Sha256Init;
  CryptoProtocol->Sha256Update         = Sha256Update;
  CryptoProtocol->Sha256Final          = Sha256Final;
  CryptoProtocol->Sha256Duplicate      = Sha256Duplicate;
  CryptoProtocol->Sha256HashAll        = Sha256HashAll;

  CryptoProtocol->Sha384GetContextSize = Sha384GetContextSize;
  CryptoProtocol->Sha384Init           = Sha384Init;
  CryptoProtocol->Sha384Update         = Sha384Update;
  CryptoProtocol->Sha384Final          = Sha384Final;
  CryptoProtocol->Sha384Duplicate      = Sha384Duplicate;
  CryptoProtocol->Sha384HashAll        = Sha384HashAll;

  CryptoProtocol->Sha512GetContextSize = Sha512GetContextSize;
  CryptoProtocol->Sha512Init           = Sha512Init;
  CryptoProtocol->Sha512Update         = Sha512Update;
  CryptoProtocol->Sha512Final          = Sha512Final;
  CryptoProtocol->Sha512Duplicate      = Sha512Duplicate;
  CryptoProtocol->Sha512HashAll        = Sha512HashAll;

  //
  // SM3 Hash functions
  //
  CryptoProtocol->Sm3GetContextSize = Sm3GetContextSize;
  CryptoProtocol->Sm3Init           = Sm3Init;
  CryptoProtocol->Sm3Update         = Sm3Update;
  CryptoProtocol->Sm3Final          = Sm3Final;
  CryptoProtocol->Sm3Duplicate      = Sm3Duplicate;
  CryptoProtocol->Sm3HashAll        = Sm3HashAll;

  // ========================================================================================================
  // Key Derivation Functions
  // ========================================================================================================
  CryptoProtocol->HkdfSha256Expand           = HkdfSha256Expand;
  CryptoProtocol->HkdfSha256Extract          = HkdfSha256Extract;
  CryptoProtocol->HkdfSha256ExtractAndExpand = HkdfSha256ExtractAndExpand;
  CryptoProtocol->HkdfSha384Expand           = HkdfSha384Expand;
  CryptoProtocol->HkdfSha384Extract          = HkdfSha384Extract;
  CryptoProtocol->HkdfSha384ExtractAndExpand = HkdfSha384ExtractAndExpand;

  // ========================================================================================================
  // Public Key Cryptography
  // ========================================================================================================
  CryptoProtocol->AuthenticodeVerify         = AuthenticodeVerify;
  CryptoProtocol->DhNew                      = DhNew;
  CryptoProtocol->DhFree                     = DhFree;
  CryptoProtocol->DhGenerateParameter        = DhGenerateParameter;
  CryptoProtocol->DhSetParameter             = DhSetParameter;
  CryptoProtocol->DhGenerateKey              = DhGenerateKey;
  CryptoProtocol->DhComputeKey               = DhComputeKey;
  CryptoProtocol->Pkcs5HashPassword          = Pkcs5HashPassword;
  CryptoProtocol->Pkcs1v2Encrypt             = Pkcs1v2Encrypt;
  CryptoProtocol->Pkcs1v2Decrypt             = Pkcs1v2Decrypt;
  CryptoProtocol->RsaOaepEncrypt             = RsaOaepEncrypt;
  CryptoProtocol->RsaOaepDecrypt             = RsaOaepDecrypt;
  CryptoProtocol->Pkcs7GetSigners            = Pkcs7GetSigners;
  CryptoProtocol->Pkcs7FreeSigners           = Pkcs7FreeSigners;
  CryptoProtocol->Pkcs7GetCertificatesList   = Pkcs7GetCertificatesList;
  CryptoProtocol->Pkcs7Verify                = Pkcs7Verify;
  CryptoProtocol->Pkcs7Sign                  = Pkcs7Sign;
  CryptoProtocol->Pkcs7Encrypt               = Pkcs7Encrypt;
  CryptoProtocol->VerifyEKUsInPkcs7Signature = VerifyEKUsInPkcs7Signature;
  CryptoProtocol->Pkcs7GetAttachedContent    = Pkcs7GetAttachedContent;

  // ========================================================================================================
  // Basic Elliptic Curve Primitives
  // ========================================================================================================
  CryptoProtocol->EcGroupInit                     = EcGroupInit;
  CryptoProtocol->EcGroupGetCurve                 = EcGroupGetCurve;
  CryptoProtocol->EcGroupGetOrder                 = EcGroupGetOrder;
  CryptoProtocol->EcGroupFree                     = EcGroupFree;
  CryptoProtocol->EcPointInit                     = EcPointInit;
  CryptoProtocol->EcPointDeInit                   = EcPointDeInit;
  CryptoProtocol->EcPointGetAffineCoordinates     = EcPointGetAffineCoordinates;
  CryptoProtocol->EcPointSetAffineCoordinates     = EcPointSetAffineCoordinates;
  CryptoProtocol->EcPointAdd                      = EcPointAdd;
  CryptoProtocol->EcPointMul                      = EcPointMul;
  CryptoProtocol->EcPointInvert                   = EcPointInvert;
  CryptoProtocol->EcPointIsOnCurve                = EcPointIsOnCurve;
  CryptoProtocol->EcPointIsAtInfinity             = EcPointIsAtInfinity;
  CryptoProtocol->EcPointEqual                    = EcPointEqual;
  CryptoProtocol->EcPointSetCompressedCoordinates = EcPointSetCompressedCoordinates;

  // ========================================================================================================
  // Elliptic Curve Diffie Hellman Primitives
  // ========================================================================================================

  CryptoProtocol->EcNewByNid             = EcNewByNid;
  CryptoProtocol->EcFree                 = EcFree;
  CryptoProtocol->EcGenerateKey          = EcGenerateKey;
  CryptoProtocol->EcGetPubKey            = EcGetPubKey;
  CryptoProtocol->EcDhComputeKey         = EcDhComputeKey;
  CryptoProtocol->EcGetPrivateKeyFromPem = EcGetPrivateKeyFromPem;
  CryptoProtocol->EcGetPublicKeyFromX509 = EcGetPublicKeyFromX509;
  CryptoProtocol->EcDsaSign              = EcDsaSign;
  CryptoProtocol->EcDsaVerify            = EcDsaVerify;

  // ========================================================================================================
  // RSA Primitives
  // ========================================================================================================
  CryptoProtocol->RsaNew                  = RsaNew;
  CryptoProtocol->RsaFree                 = RsaFree;
  CryptoProtocol->RsaSetKey               = RsaSetKey;
  CryptoProtocol->RsaGetKey               = RsaGetKey;
  CryptoProtocol->RsaGenerateKey          = RsaGenerateKey;
  CryptoProtocol->RsaCheckKey             = RsaCheckKey;
  CryptoProtocol->RsaPkcs1Sign            = RsaPkcs1Sign;
  CryptoProtocol->RsaPkcs1Verify          = RsaPkcs1Verify;
  CryptoProtocol->RsaPssSign              = RsaPssSign;
  CryptoProtocol->RsaPssVerify            = RsaPssVerify;
  CryptoProtocol->RsaGetPrivateKeyFromPem = RsaGetPrivateKeyFromPem;
  CryptoProtocol->RsaGetPublicKeyFromX509 = RsaGetPublicKeyFromX509;

  // ========================================================================================================
  // X509 Certificate Primitives
  // ========================================================================================================
  CryptoProtocol->X509GetSubjectName              = X509GetSubjectName;
  CryptoProtocol->X509GetCommonName               = X509GetCommonName;
  CryptoProtocol->X509GetOrganizationName         = X509GetOrganizationName;
  CryptoProtocol->X509VerifyCert                  = X509VerifyCert;
  CryptoProtocol->X509ConstructCertificate        = X509ConstructCertificate;
  CryptoProtocol->X509ConstructCertificateStackV  = X509ConstructCertificateStackV;
  CryptoProtocol->X509ConstructCertificateStack   = X509ConstructCertificateStack;
  CryptoProtocol->X509Free                        = X509Free;
  CryptoProtocol->X509StackFree                   = X509StackFree;
  CryptoProtocol->X509GetTBSCert                  = X509GetTBSCert;
  CryptoProtocol->X509GetVersion                  = X509GetVersion;
  CryptoProtocol->X509GetSerialNumber             = X509GetSerialNumber;
  CryptoProtocol->X509GetIssuerName               = X509GetIssuerName;
  CryptoProtocol->X509GetSignatureAlgorithm       = X509GetSignatureAlgorithm;
  CryptoProtocol->X509GetExtensionData            = X509GetExtensionData;
  CryptoProtocol->X509GetValidity                 = X509GetValidity;
  CryptoProtocol->X509FormatDateTime              = X509FormatDateTime;
  CryptoProtocol->X509GetKeyUsage                 = X509GetKeyUsage;
  CryptoProtocol->X509GetExtendedKeyUsage         = X509GetExtendedKeyUsage;
  CryptoProtocol->X509VerifyCertChain             = X509VerifyCertChain;
  CryptoProtocol->X509GetCertFromCertChain        = X509GetCertFromCertChain;
  CryptoProtocol->X509GetExtendedBasicConstraints = X509GetExtendedBasicConstraints;
  CryptoProtocol->X509CompareDateTime             = X509CompareDateTime;
  CryptoProtocol->Asn1GetTag                      = Asn1GetTag;

  // ========================================================================================================
  // Random Number Generation
  // ========================================================================================================
  CryptoProtocol->RandomSeed  = RandomSeed;
  CryptoProtocol->RandomBytes = RandomBytes;

  // ========================================================================================================
  // TLS Primitives
  // ========================================================================================================
  CryptoProtocol->TlsInitialize              = TlsInitialize;
  CryptoProtocol->TlsCtxFree                 = TlsCtxFree;
  CryptoProtocol->TlsCtxNew                  = TlsCtxNew;
  CryptoProtocol->TlsFree                    = TlsFree;
  CryptoProtocol->TlsNew                     = TlsNew;
  CryptoProtocol->TlsInHandshake             = TlsInHandshake;
  CryptoProtocol->TlsDoHandshake             = TlsDoHandshake;
  CryptoProtocol->TlsHandleAlert             = TlsHandleAlert;
  CryptoProtocol->TlsCloseNotify             = TlsCloseNotify;
  CryptoProtocol->TlsCtrlTrafficOut          = TlsCtrlTrafficOut;
  CryptoProtocol->TlsCtrlTrafficIn           = TlsCtrlTrafficIn;
  CryptoProtocol->TlsRead                    = TlsRead;
  CryptoProtocol->TlsWrite                   = TlsWrite;
  CryptoProtocol->TlsShutdown                = TlsShutdown;
  CryptoProtocol->TlsSetVersion              = TlsSetVersion;
  CryptoProtocol->TlsSetConnectionEnd        = TlsSetConnectionEnd;
  CryptoProtocol->TlsSetCipherList           = TlsSetCipherList;
  CryptoProtocol->TlsSetCompressionMethod    = TlsSetCompressionMethod;
  CryptoProtocol->TlsSetVerify               = TlsSetVerify;
  CryptoProtocol->TlsSetVerifyHost           = TlsSetVerifyHost;
  CryptoProtocol->TlsSetSessionId            = TlsSetSessionId;
  CryptoProtocol->TlsSetCaCertificate        = TlsSetCaCertificate;
  CryptoProtocol->TlsSetHostPublicCert       = TlsSetHostPublicCert;
  CryptoProtocol->TlsSetHostPrivateKeyEx     = TlsSetHostPrivateKeyEx;
  CryptoProtocol->TlsSetHostPrivateKey       = TlsSetHostPrivateKey;
  CryptoProtocol->TlsSetCertRevocationList   = TlsSetCertRevocationList;
  CryptoProtocol->TlsSetSignatureAlgoList    = TlsSetSignatureAlgoList;
  CryptoProtocol->TlsSetEcCurve              = TlsSetEcCurve;
  CryptoProtocol->TlsGetVersion              = TlsGetVersion;
  CryptoProtocol->TlsGetConnectionEnd        = TlsGetConnectionEnd;
  CryptoProtocol->TlsGetCurrentCipher        = TlsGetCurrentCipher;
  CryptoProtocol->TlsGetCurrentCompressionId = TlsGetCurrentCompressionId;
  CryptoProtocol->TlsGetVerify               = TlsGetVerify;
  CryptoProtocol->TlsGetSessionId            = TlsGetSessionId;
  CryptoProtocol->TlsGetClientRandom         = TlsGetClientRandom;
  CryptoProtocol->TlsGetServerRandom         = TlsGetServerRandom;
  CryptoProtocol->TlsGetKeyMaterial          = TlsGetKeyMaterial;
  CryptoProtocol->TlsGetCaCertificate        = TlsGetCaCertificate;
  CryptoProtocol->TlsGetHostPublicCert       = TlsGetHostPublicCert;
  CryptoProtocol->TlsGetHostPrivateKey       = TlsGetHostPrivateKey;
  CryptoProtocol->TlsGetCertRevocationList   = TlsGetCertRevocationList;
  CryptoProtocol->TlsGetExportKey            = TlsGetExportKey;

  // ========================================================================================================
  // Timestamp Primitives
  // ========================================================================================================

  CryptoProtocol->ImageTimestampVerify = ImageTimestampVerify;

  // ========================================================================================================
  // Info
  // ========================================================================================================

  CryptoProtocol->GetCryptoProviderVersionString   = GetCryptoProviderVersionString;
}


/**
  OneCrypto Entry Point (No Setup)

  This entry point assumes that library constructors have already been called
  by the build system. This is the case for S*mm (StandaloneMm/SupvMm) binaries
  where the standard UEFI loader will properly initialize all library constructors
  before calling the entry point.

  This function is used by MmEntry (the S*mm entry point) where the build system
  has already set up the OpenSSL library through its constructor mechanism.

  @param[in]  Depends     Pointer to dependencies structure containing function
                          pointers required by the CRT library.
  @param[out] Crypto      Pointer to receive the initialized ONE_CRYPTO_PROTOCOL.
                          If NULL, this is a size query.
  @param[out] CryptoSize  Pointer to receive the size of ONE_CRYPTO_PROTOCOL.

  @retval EFI_SUCCESS             Protocol initialized successfully.
  @retval EFI_BUFFER_TOO_SMALL    Crypto is NULL (size query).
  @retval EFI_INVALID_PARAMETER   *Crypto is NULL when Crypto is not NULL.
  @retval other                   Error from BaseCryptCrtSetup.
**/
EFI_STATUS
EFIAPI
NoSetupCryptoEntry (
  IN ONE_CRYPTO_DEPENDENCIES  *Depends,
  OUT VOID                    **Crypto,
  OUT UINT32                  *CryptoSize
  )
{
  EFI_STATUS  Status;

  //
  // Always return the size
  //
  if (CryptoSize != NULL) {
    *CryptoSize = sizeof(ONE_CRYPTO_PROTOCOL);
  }

  //
  // If Crypto is NULL, this is a size query
  //
  if (Crypto == NULL) {
    return EFI_BUFFER_TOO_SMALL;
  }

  //
  // Initialize the CRT library with the dependencies
  //
  Status = OneCryptoCrtSetup (Depends);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Verify the caller provided a valid buffer
  //
  if (*Crypto == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Zero the buffer
  //
  SetMem(*Crypto, sizeof(ONE_CRYPTO_PROTOCOL), 0);

  //
  // Initialize the Crypto Protocol
  //
  CryptoInit (*Crypto);

  return EFI_SUCCESS;
}

/**
  OneCrypto Entry Point (With Setup)

  This entry point manually calls library constructors before initializing the
  crypto protocol. This is necessary for DXE binaries loaded by OneCrypto loaders,
  which load the binary outside the standard UEFI calling convention.

  When OneCrypto loads DXE binaries, the build system's normal library constructor
  mechanism does not run. Therefore, this entry point explicitly calls BaseCryptInit()
  to initialize the OpenSSL library before delegating to NoSetupCryptoEntry.

  Architecture Overview:
  ----------------------
  OneCrypto requires two entry points because of how binaries are loaded:

  1. CryptoEntry (this function):
     - Used when loaded by OneCrypto DXE loaders
     - Loaders call CryptoEntry directly via function pointer
     - Must manually call BaseCryptInit() to initialize OpenSSL
     - Then delegates to NoSetupCryptoEntry for protocol initialization

  2. NoSetupCryptoEntry:
     - Used by MmEntry for S*mm binaries
     - Build system calls library constructors automatically
     - BaseCryptInit() already called by constructor
     - Only needs to initialize the protocol

  @param[in]  Depends     Pointer to dependencies structure containing function
                          pointers required by the CRT library.
  @param[out] Crypto      Pointer to receive the initialized ONE_CRYPTO_PROTOCOL.
                          If NULL, this is a size query.
  @param[out] CryptoSize  Pointer to receive the size of ONE_CRYPTO_PROTOCOL.

  @retval EFI_SUCCESS             Protocol initialized successfully.
  @retval EFI_BUFFER_TOO_SMALL    Crypto is NULL (size query).
  @retval EFI_INVALID_PARAMETER   *Crypto is NULL when Crypto is not NULL.
  @retval other                   Error from BaseCryptInit
**/
COMMON_EXPORT_API
EFI_STATUS
EFIAPI
CryptoEntry (
  IN ONE_CRYPTO_DEPENDENCIES  *Depends,
  OUT VOID                    **Crypto,
  OUT UINT32                  *CryptoSize
  )
{
  EFI_STATUS  Status;

  //
  // Perform crypto setup
  //
  Status = BaseCryptInit ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Delegate to the main CryptoEntry function
  //
  return NoSetupCryptoEntry (Depends, Crypto, CryptoSize);
}
