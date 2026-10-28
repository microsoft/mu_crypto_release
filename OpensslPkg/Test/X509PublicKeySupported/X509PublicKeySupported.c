/** @file
  Regression tests for X.509 public-key verification capability.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UnitTestLib.h>
#include "TestData.h"

VOID
EFIAPI
ProcessLibraryConstructorList (
  VOID
  );

STATIC
UNIT_TEST_STATUS
EFIAPI
TestValidRsaKey (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  VOID     *Rsa;
  UINT8    Hash[SHA256_DIGEST_SIZE];
  BOOLEAN  Valid;
  BOOLEAN  Invalid;

  UT_ASSERT_TRUE (X509IsPublicKeySupported (mRsaCert, sizeof (mRsaCert)));
  UT_ASSERT_TRUE (Sha256HashAll (mMessage, sizeof (mMessage), Hash));
  Rsa = NULL;
  UT_ASSERT_TRUE (RsaGetPublicKeyFromX509 (mRsaCert, sizeof (mRsaCert), &Rsa));
  Valid    = RsaPkcs1Verify (Rsa, Hash, sizeof (Hash), mSignature, sizeof (mSignature));
  Hash[0] ^= 1;
  Invalid  = RsaPkcs1Verify (Rsa, Hash, sizeof (Hash), mSignature, sizeof (mSignature));
  RsaFree (Rsa);
  UT_ASSERT_TRUE (Valid);
  UT_ASSERT_FALSE (Invalid);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestInvalidRsaExponent (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT8    Cert[sizeof (mRsaCert)];
  UINT8    Hash[SHA256_DIGEST_SIZE];
  UINT8    Exponent[3];
  UINTN    ExponentSize;
  UINT8    *X509;
  VOID     *Rsa;
  BOOLEAN  Retrieved;
  BOOLEAN  Valid;

  CopyMem (Cert, mRsaCert, sizeof (Cert));
  UT_ASSERT_TRUE (mExponentOffset + sizeof (Exponent) <= sizeof (Cert));
  UT_ASSERT_MEM_EQUAL (&Cert[mExponentOffset], "\x01\x00\x01", sizeof (Exponent));
  // Keep the DER structure intact, but change e from 65537 to invalid 65538.
  Cert[mExponentOffset + sizeof (Exponent) - 1] = 2;
  X509                                          = NULL;
  UT_ASSERT_TRUE (X509ConstructCertificate (Cert, sizeof (Cert), &X509));
  X509Free (X509);
  UT_ASSERT_TRUE (Sha256HashAll (mMessage, sizeof (mMessage), Hash));
  Rsa = NULL;
  UT_ASSERT_TRUE (RsaGetPublicKeyFromX509 (Cert, sizeof (Cert), &Rsa));
  ExponentSize = sizeof (Exponent);
  Retrieved    = RsaGetKey (Rsa, RsaKeyE, Exponent, &ExponentSize);
  Valid        = RsaPkcs1Verify (Rsa, Hash, sizeof (Hash), mSignature, sizeof (mSignature));
  RsaFree (Rsa);
  UT_ASSERT_TRUE (Retrieved);
  UT_ASSERT_EQUAL (ExponentSize, sizeof (Exponent));
  UT_ASSERT_MEM_EQUAL (Exponent, "\x01\x00\x02", sizeof (Exponent));
  UT_ASSERT_FALSE (Valid);
  UT_ASSERT_FALSE (X509IsPublicKeySupported (Cert, sizeof (Cert)));
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestInvalidInput (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  STATIC CONST UINT8  Invalid[] = { 0x30, 0 };

  UT_ASSERT_FALSE (X509IsPublicKeySupported (NULL, sizeof (mRsaCert)));
  UT_ASSERT_FALSE (X509IsPublicKeySupported (mRsaCert, 0));
  UT_ASSERT_FALSE (X509IsPublicKeySupported (Invalid, sizeof (Invalid)));
  UT_ASSERT_FALSE (X509IsPublicKeySupported (mRsaCert, sizeof (mRsaCert) - 1));
  return UNIT_TEST_PASSED;
}

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
  Status    = InitUnitTestFramework (&Framework, "X509 public key support", gEfiCallerBaseName, "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "X509 public key support", "OpensslPkg.BaseCryptLib.X509", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Valid RSA key verifies signatures", "ValidRsa", TestValidRsaKey, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Invalid even RSA exponent is rejected", "InvalidRsaExponent", TestInvalidRsaExponent, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Invalid certificate input is rejected", "InvalidInput", TestInvalidInput, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
