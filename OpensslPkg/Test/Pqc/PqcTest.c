/** @file
  Exercise CMS and PQC using the production UEFI OpenSSL provider.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UnitTestLib.h>
#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "PqcFixtures.h"

VOID EFIAPI
ProcessLibraryConstructorList (
  VOID
  );

STATIC CONST UINT8  mMessage[] = "UEFI CMS provider regression";

STATIC
UNIT_TEST_STATUS
EFIAPI
CmsRoundTrip (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  CMS_FIXTURE  *Fixture;
  UINT8        *CmsDer;
  UINT8        Modified[sizeof (mMessage)];
  BOOLEAN      Passed;

  Fixture = Context;
  CmsDer  = AllocateCopyPool (Fixture->CmsSize, Fixture->Cms);
  UT_ASSERT_NOT_NULL (CmsDer);
  Passed = FALSE;
  if (!Pkcs7Verify (CmsDer, Fixture->CmsSize, Fixture->Certificate, Fixture->CertificateSize, mMessage, sizeof (mMessage))) {
    goto Exit;
  }

  CopyMem (Modified, mMessage, sizeof (Modified));
  Modified[0] ^= 1;
  if (Pkcs7Verify (CmsDer, Fixture->CmsSize, Fixture->Certificate, Fixture->CertificateSize, Modified, sizeof (Modified)) ||
      Pkcs7Verify (CmsDer, Fixture->CmsSize - 1, Fixture->Certificate, Fixture->CertificateSize, mMessage, sizeof (mMessage)))
  {
    goto Exit;
  }

  if (Pkcs7Verify (CmsDer, Fixture->CmsSize, mUntrustedCertificate, sizeof (mUntrustedCertificate), mMessage, sizeof (mMessage))) {
    goto Exit;
  }

  CmsDer[Fixture->CmsSize - 1] ^= 1;
  Passed                        = (BOOLEAN) !Pkcs7Verify (CmsDer, Fixture->CmsSize, Fixture->Certificate, Fixture->CertificateSize, mMessage, sizeof (mMessage));

Exit:
  if (!Passed) {
    UT_LOG_ERROR ("CMS fixture failed: 0x%Lx\n", (UINT64)ERR_peek_last_error ());
  }

  FreePool (CmsDer);
  UT_ASSERT_TRUE (Passed);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
KemRoundTrip (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EVP_PKEY      *Key;
  EVP_PKEY_CTX  *Encap;
  EVP_PKEY_CTX  *Decap;
  UINT8         Ciphertext[2048];
  UINT8         Secret[32];
  UINT8         Recovered[32];
  size_t        CiphertextSize;
  size_t        SecretSize;
  size_t        RecoveredSize;
  BOOLEAN       Passed;

  Key            = EVP_PKEY_Q_keygen (NULL, NULL, (CONST CHAR8 *)Context);
  Encap          = NULL;
  Decap          = NULL;
  CiphertextSize = sizeof (Ciphertext);
  SecretSize     = sizeof (Secret);
  RecoveredSize  = sizeof (Recovered);
  Passed         = FALSE;
  if (Key == NULL) {
    goto Exit;
  }

  Encap = EVP_PKEY_CTX_new_from_pkey (NULL, Key, NULL);
  Decap = EVP_PKEY_CTX_new_from_pkey (NULL, Key, NULL);
  if ((Encap == NULL) || (Decap == NULL) ||
      (EVP_PKEY_encapsulate_init (Encap, NULL) != 1) ||
      (EVP_PKEY_decapsulate_init (Decap, NULL) != 1) ||
      (EVP_PKEY_encapsulate (Encap, Ciphertext, &CiphertextSize, Secret, &SecretSize) != 1) ||
      (EVP_PKEY_decapsulate (Decap, Recovered, &RecoveredSize, Ciphertext, CiphertextSize) != 1) ||
      (SecretSize != sizeof (Secret)) || (RecoveredSize != SecretSize) ||
      (CompareMem (Secret, Recovered, SecretSize) != 0))
  {
    goto Exit;
  }

  Ciphertext[0] ^= 1;
  RecoveredSize  = sizeof (Recovered);
  Passed         = (BOOLEAN)(
                             (EVP_PKEY_decapsulate (Decap, Recovered, &RecoveredSize, Ciphertext, CiphertextSize) == 1) &&
                             (RecoveredSize == SecretSize) &&
                             (CompareMem (Secret, Recovered, SecretSize) != 0)
                             );

Exit:
  if (!Passed) {
    UT_LOG_ERROR ("KEM round trip %a failed: 0x%Lx\n", (CONST CHAR8 *)Context, (UINT64)ERR_peek_last_error ());
  }

  EVP_PKEY_CTX_free (Decap);
  EVP_PKEY_CTX_free (Encap);
  EVP_PKEY_free (Key);
  UT_ASSERT_TRUE (Passed);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
SlhRegistration (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  STATIC CONST CHAR8  *Names[] = {
    "SLH-DSA-SHA2-128s",  "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s",  "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s",  "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
  };
  UINTN               Index;
  EVP_SIGNATURE       *Signature;
  EVP_KEYMGMT         *KeyManagement;
  BOOLEAN             Found;

  for (Index = 0; Index < ARRAY_SIZE (Names); Index++) {
    Signature     = EVP_SIGNATURE_fetch (NULL, Names[Index], NULL);
    KeyManagement = EVP_KEYMGMT_fetch (NULL, Names[Index], NULL);
    Found         = (BOOLEAN)((Signature != NULL) && (KeyManagement != NULL));
    EVP_SIGNATURE_free (Signature);
    EVP_KEYMGMT_free (KeyManagement);
    UT_ASSERT_TRUE (Found);
  }

  return UNIT_TEST_PASSED;
}

int
main (
  int   Argc,
  char  *Argv[]
  )
{
  UNIT_TEST_FRAMEWORK_HANDLE  Framework;
  UNIT_TEST_SUITE_HANDLE      Suite;
  EFI_STATUS                  Status;

  ProcessLibraryConstructorList ();
  if (!RandomSeed (NULL, 0)) {
    return 1;
  }

  Framework = NULL;
  Status    = InitUnitTestFramework (&Framework, "UEFI CMS and PQC", "PQC", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "UEFI provider operations", "PQC", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    AddTestCase (Suite, "ML-DSA-44 CMS and rejection cases", "ML-DSA-44", CmsRoundTrip, NULL, NULL, &mCmsFixtures[0]);
    AddTestCase (Suite, "ML-DSA-65 CMS and rejection cases", "ML-DSA-65", CmsRoundTrip, NULL, NULL, &mCmsFixtures[1]);
    AddTestCase (Suite, "ML-DSA-87 CMS and rejection cases", "ML-DSA-87", CmsRoundTrip, NULL, NULL, &mCmsFixtures[2]);
    AddTestCase (Suite, "SLH-DSA SHA2 CMS and rejection cases", "SLH-SHA2", CmsRoundTrip, NULL, NULL, &mCmsFixtures[3]);
    AddTestCase (Suite, "SLH-DSA SHAKE CMS and rejection cases", "SLH-SHAKE", CmsRoundTrip, NULL, NULL, &mCmsFixtures[4]);
    AddTestCase (Suite, "ML-KEM-512 encapsulation and implicit rejection", "ML-KEM-512", KemRoundTrip, NULL, NULL, "ML-KEM-512");
    AddTestCase (Suite, "ML-KEM-768 encapsulation and implicit rejection", "ML-KEM-768", KemRoundTrip, NULL, NULL, "ML-KEM-768");
    AddTestCase (Suite, "ML-KEM-1024 encapsulation and implicit rejection", "ML-KEM-1024", KemRoundTrip, NULL, NULL, "ML-KEM-1024");
    AddTestCase (Suite, "All twelve SLH-DSA variants are discoverable", "SLH-Registration", SlhRegistration, NULL, NULL, NULL);
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  OPENSSL_cleanup ();
  return EFI_ERROR (Status) ? 1 : 0;
}
