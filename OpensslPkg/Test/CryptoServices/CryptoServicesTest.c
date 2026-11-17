/** @file
  Protocol 1.1 provider service regression tests.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/BaseCryptLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UnitTestLib.h>
#include <Protocol/Hash.h>
#include <Guid/ImageAuthentication.h>

#ifndef SERVICE_NULL
  #include "CmsTestData.h"
  #include "../X509PublicKeySupported/TestData.h"
  #ifndef SERVICE_MBEDTLS
    #include <openssl/opensslconf.h>
  #endif
#endif

VOID
EFIAPI
ProcessLibraryConstructorList (
  VOID
  );

#ifdef SERVICE_NULL
STATIC
UNIT_TEST_STATUS
EFIAPI
TestNullServices (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT8     Data[SHA512_DIGEST_SIZE] = { 0 };
  UINT8     *Chain;
  UINTN     Size;
  EFI_GUID  Guid = { 0 };

  Chain = Data;
  Size  = sizeof (Data);
  UT_ASSERT_STATUS_EQUAL (
    GetTrustAnchorX509FromAuthData (NULL, Data, SHA256_DIGEST_SIZE, Data, sizeof (Data), &Chain, &Size),
    EFI_UNSUPPORTED
    );
  UT_ASSERT_TRUE (Chain == NULL);
  UT_ASSERT_EQUAL (Size, 0);
  FreeTrustAnchorX509Cache (NULL);
  UT_ASSERT_STATUS_EQUAL (GetAuthenticodeHashAlgorithm (Data, sizeof (Data), &Guid), EFI_UNSUPPORTED);
  UT_ASSERT_STATUS_EQUAL (HashAllByGuid (&Guid, Data, sizeof (Data), Data, &Size), EFI_UNSUPPORTED);
  Chain = Data;
  Size  = sizeof (Data);
  UT_ASSERT_FALSE (CmsVerify (Data, sizeof (Data), Data, sizeof (Data), Data, sizeof (Data), &Chain, &Size));
  UT_ASSERT_TRUE (Chain == NULL);
  UT_ASSERT_EQUAL (Size, 0);
  UT_ASSERT_EQUAL (CmsGetSignerInfoNum (Data, sizeof (Data)), 0);
  UT_ASSERT_FALSE (X509IsPublicKeySupported (Data, sizeof (Data)));
  Chain = Data;
  Size  = sizeof (Data);
  UT_ASSERT_STATUS_EQUAL (
    AuthenticodeVerifyEx (Data, sizeof (Data), Data, sizeof (Data), Data, sizeof (Data), &Chain, &Size),
    EFI_UNSUPPORTED
    );
  UT_ASSERT_TRUE (Chain == NULL);
  UT_ASSERT_EQUAL (Size, 0);
  return UNIT_TEST_PASSED;
}

#else
STATIC
UNIT_TEST_STATUS
EFIAPI
TestHashServices (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  STATIC CONST UINT8  Sha256Abc[] = {
    0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
    0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
    0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
    0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
  };
  UINT8               AuthData[] = {
    0x30, 0x59, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
    0xA0, 0x4C, 0x30, 0x4A, 0x02, 0x01, 0x01, 0x31, 0x00, 0x30, 0x43, 0x06, 0x0A,
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04,
    0xA0, 0x35, 0x30, 0x33, 0x30, 0x00, 0x30, 0x2F, 0x30, 0x0B, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,   0,  0, 0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,   0,  0, 0
  };
  EFI_GUID            HashGuid;
  UINT8               Digest[SHA512_DIGEST_SIZE];
  UINTN               DigestSize;
  UINTN               Index;

  UT_ASSERT_STATUS_EQUAL (GetAuthenticodeHashAlgorithm (AuthData, sizeof (AuthData), &HashGuid), EFI_SUCCESS);
  UT_ASSERT_TRUE (CompareGuid (&HashGuid, &gEfiHashAlgorithmSha256Guid));
  UT_ASSERT_FALSE (CompareGuid (&HashGuid, &gEfiCertSha256Guid));
  UT_ASSERT_STATUS_EQUAL (HashAllByGuid (&HashGuid, "abc", 3, Digest, &DigestSize), EFI_SUCCESS);
  UT_ASSERT_EQUAL (DigestSize, sizeof (Sha256Abc));
  UT_ASSERT_MEM_EQUAL (Digest, Sha256Abc, DigestSize);
  UT_ASSERT_STATUS_EQUAL (HashAllByGuid (&gEfiCertSha256Guid, "abc", 3, Digest, &DigestSize), EFI_UNSUPPORTED);
  UT_ASSERT_STATUS_EQUAL (HashAllByGuid (NULL, "abc", 3, Digest, &DigestSize), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (HashAllByGuid (&HashGuid, NULL, 3, Digest, &DigestSize), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (HashAllByGuid (&HashGuid, "abc", 3, NULL, &DigestSize), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (HashAllByGuid (&HashGuid, "abc", 3, Digest, NULL), EFI_INVALID_PARAMETER);
  for (Index = 0; Index < sizeof (AuthData); Index++) {
    UT_ASSERT_STATUS_EQUAL (GetAuthenticodeHashAlgorithm (AuthData, Index, &HashGuid), EFI_INVALID_PARAMETER);
  }

  AuthData[56] = 0x7F;
  UT_ASSERT_STATUS_EQUAL (GetAuthenticodeHashAlgorithm (AuthData, sizeof (AuthData), &HashGuid), EFI_UNSUPPORTED);
  AuthData[1] = 0x80;
  UT_ASSERT_STATUS_EQUAL (GetAuthenticodeHashAlgorithm (AuthData, sizeof (AuthData), &HashGuid), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (GetAuthenticodeHashAlgorithm (AuthData, MAX_UINTN, &HashGuid), EFI_INVALID_PARAMETER);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestTrustAnchor (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT8  Hash[SHA256_DIGEST_SIZE];
  UINT8  *Tbs;
  UINTN  TbsSize;
  VOID   *Cache;
  UINT8  *Anchor;
  UINTN  AnchorSize;
  UINTN  Index;

  UT_ASSERT_TRUE (X509GetTBSCert (mCmsCert, sizeof (mCmsCert), &Tbs, &TbsSize));
  UT_ASSERT_TRUE (Sha256HashAll (Tbs, TbsSize, Hash));
  Cache = NULL;
  for (Index = 0; Index < 2; Index++) {
    UT_ASSERT_STATUS_EQUAL (
      GetTrustAnchorX509FromAuthData (&Cache, Hash, sizeof (Hash), mCmsData, sizeof (mCmsData), &Anchor, &AnchorSize),
      EFI_SUCCESS
      );
    UT_ASSERT_EQUAL (AnchorSize, sizeof (mCmsCert));
    UT_ASSERT_MEM_EQUAL (Anchor, mCmsCert, AnchorSize);
    UT_ASSERT_TRUE (Anchor != mCmsCert);
    FreePool (Anchor);
  }

  Hash[0]   ^= 1;
  Anchor     = mCmsCert;
  AnchorSize = sizeof (mCmsCert);
  UT_ASSERT_STATUS_EQUAL (
    GetTrustAnchorX509FromAuthData (&Cache, Hash, sizeof (Hash), mCmsData, sizeof (mCmsData), &Anchor, &AnchorSize),
    EFI_NOT_FOUND
    );
  UT_ASSERT_TRUE (Anchor == NULL);
  UT_ASSERT_EQUAL (AnchorSize, 0);
  FreeTrustAnchorX509Cache (Cache);
  FreeTrustAnchorX509Cache (NULL);
  UT_ASSERT_STATUS_EQUAL (
    GetTrustAnchorX509FromAuthData (NULL, Hash, sizeof (Hash), mCmsData, MAX_UINTN, &Anchor, &AnchorSize),
    EFI_INVALID_PARAMETER
    );
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestCmsServices (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT8       *Chain;
  UINTN       ChainSize;
  UINTN       Index;
  UINT8       Invalid = 0;
  EFI_STATUS  Status;

  UT_ASSERT_TRUE (
    Pkcs7Verify (
      mCmsData,
      sizeof (mCmsData),
      mCmsCert,
      sizeof (mCmsCert),
      mCmsMessage,
      sizeof (mCmsMessage)
      )
    );
 #if defined (SERVICE_MBEDTLS)
  UT_ASSERT_EQUAL (CmsGetSignerInfoNum (mCmsData, sizeof (mCmsData)), 0);
  UT_ASSERT_TRUE (
    CmsVerify (
      mCmsData,
      sizeof (mCmsData),
      mCmsCert,
      sizeof (mCmsCert),
      mCmsMessage,
      sizeof (mCmsMessage),
      NULL,
      NULL
      )
    );
 #elif defined (OPENSSL_NO_CMS)
  UT_ASSERT_EQUAL (CmsGetSignerInfoNum (mCmsData, sizeof (mCmsData)), 0);
  UT_ASSERT_FALSE (
    CmsVerify (
      mCmsData,
      sizeof (mCmsData),
      mCmsCert,
      sizeof (mCmsCert),
      mCmsMessage,
      sizeof (mCmsMessage),
      NULL,
      NULL
      )
    );
 #else
  UT_ASSERT_EQUAL (CmsGetSignerInfoNum (mCmsData, sizeof (mCmsData)), 1);
  Chain     = NULL;
  ChainSize = 0;
  UT_ASSERT_TRUE (
    CmsVerify (
      mCmsData,
      sizeof (mCmsData),
      mCmsCert,
      sizeof (mCmsCert),
      mCmsMessage,
      sizeof (mCmsMessage),
      &Chain,
      &ChainSize
      )
    );
  UT_ASSERT_NOT_NULL (Chain);
  UT_ASSERT_EQUAL (ChainSize, sizeof (mCmsCert) + sizeof (UINT8) + sizeof (UINT32));
  UT_ASSERT_EQUAL (Chain[0], 1);
  UT_ASSERT_EQUAL (ReadUnaligned32 ((UINT32 *)(Chain + 1)), sizeof (mCmsCert));
  UT_ASSERT_MEM_EQUAL (Chain + 1 + sizeof (UINT32), mCmsCert, sizeof (mCmsCert));
  FreePool (Chain);
 #endif

  Chain     = mCmsCert;
  ChainSize = sizeof (mCmsCert);
  UT_ASSERT_FALSE (
    CmsVerify (
      mCmsData,
      sizeof (mCmsData),
      mCmsCert,
      sizeof (mCmsCert),
      &Invalid,
      sizeof (Invalid),
      &Chain,
      &ChainSize
      )
    );
  UT_ASSERT_TRUE (Chain == NULL);
  UT_ASSERT_EQUAL (ChainSize, 0);
  Chain = mCmsCert;
  UT_ASSERT_FALSE (
    CmsVerify (
      mCmsData,
      sizeof (mCmsData),
      mCmsCert,
      sizeof (mCmsCert),
      mCmsMessage,
      sizeof (mCmsMessage),
      &Chain,
      NULL
      )
    );
  UT_ASSERT_TRUE (Chain == NULL);
  for (Index = 0; Index < 17; Index++) {
    UT_ASSERT_EQUAL (CmsGetSignerInfoNum (mCmsData, Index), 0);
  }

  UT_ASSERT_EQUAL (CmsGetSignerInfoNum (NULL, 0), 0);
  Chain     = mCmsCert;
  ChainSize = sizeof (mCmsCert);
  Status    = AuthenticodeVerifyEx (
                mCmsData,
                sizeof (mCmsData),
                mCmsCert,
                sizeof (mCmsCert),
                mCmsMessage,
                sizeof (mCmsMessage),
                &Chain,
                &ChainSize
                );
 #if defined (SERVICE_MBEDTLS) || defined (OPENSSL_NO_CMS)
  UT_ASSERT_STATUS_EQUAL (Status, EFI_UNSUPPORTED);
 #else
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SECURITY_VIOLATION);
 #endif
  UT_ASSERT_TRUE (Chain == NULL);
  UT_ASSERT_EQUAL (ChainSize, 0);
  UT_ASSERT_STATUS_EQUAL (
    AuthenticodeVerifyEx (NULL, 0, mCmsCert, sizeof (mCmsCert), mCmsMessage, sizeof (mCmsMessage), &Chain, &ChainSize),
    EFI_INVALID_PARAMETER
    );
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestPublicKeyCapability (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT8  Cert[sizeof (mRsaCert)];

  UT_ASSERT_TRUE (X509IsPublicKeySupported (mRsaCert, sizeof (mRsaCert)));
  CopyMem (Cert, mRsaCert, sizeof (Cert));
  Cert[mExponentOffset + 2] = 2;
  UT_ASSERT_FALSE (X509IsPublicKeySupported (Cert, sizeof (Cert)));
  UT_ASSERT_FALSE (X509IsPublicKeySupported (NULL, sizeof (Cert)));
  UT_ASSERT_FALSE (X509IsPublicKeySupported (Cert, 0));
  UT_ASSERT_FALSE (X509IsPublicKeySupported (Cert, sizeof (Cert) - 1));
  return UNIT_TEST_PASSED;
}

#endif

int
main (
  VOID
  )
{
  EFI_STATUS                  Status;
  UNIT_TEST_FRAMEWORK_HANDLE  Framework;
  UNIT_TEST_SUITE_HANDLE      Suite;

  ProcessLibraryConstructorList ();
  Framework = NULL;
  Status    = InitUnitTestFramework (&Framework, "Crypto services", gEfiCallerBaseName, "1.1");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Crypto services", "BaseCryptLib.Services", NULL, NULL);
  if (!EFI_ERROR (Status)) {
 #ifdef SERVICE_NULL
    Status = AddTestCase (Suite, "Null services reset outputs and report unsupported", "Null", TestNullServices, NULL, NULL, NULL);
 #else
    Status = AddTestCase (Suite, "Hash GUID discovery and one-shot hashing", "Hash", TestHashServices, NULL, NULL, NULL);
    if (!EFI_ERROR (Status)) {
      Status = AddTestCase (Suite, "Trust-anchor lookup and cache ownership", "TrustAnchor", TestTrustAnchor, NULL, NULL, NULL);
    }

    if (!EFI_ERROR (Status)) {
      Status = AddTestCase (Suite, "CMS verdict, chain ownership and unsupported behavior", "CMS", TestCmsServices, NULL, NULL, NULL);
    }

    if (!EFI_ERROR (Status)) {
      Status = AddTestCase (Suite, "Valid and invalid RSA public-key capability", "X509", TestPublicKeyCapability, NULL, NULL, NULL);
    }

 #endif
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
