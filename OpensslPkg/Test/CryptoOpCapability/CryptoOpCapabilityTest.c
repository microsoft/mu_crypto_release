/** @file
  Validate OpenSSL-specific crypto-operation capability reporting.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Guid/CryptoOpId.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UnitTestLib.h>

#undef _WIN32
#undef _WIN64
#include <openssl/evp.h>

VOID EFIAPI
ProcessLibraryConstructorList (
  VOID
  );

/**
  Check the RSA-PSS OID count in both CMS and Authenticode capability arrays.

  @param[in] ExpectedCount  Expected PSS occurrences in each operation's result.

  @return Unit-test status.
**/
STATIC
UNIT_TEST_STATUS
CheckPssCapabilities (
  IN UINTN  ExpectedCount
  )
{
  CONST EFI_GUID            *Operations[] = {
    &gCryptoOpCmsVerifyGuid,
    &gCryptoOpAuthenticodeVerifyGuid
  };
  BASE_CRYPT_OP_CAPABILITY  *Capabilities;
  UINTN                     CapabilityCount;
  UINTN                     OpIndex;
  UINTN                     Index;
  UINTN                     PssCount;
  EFI_STATUS                Status;

  for (OpIndex = 0; OpIndex < ARRAY_SIZE (Operations); OpIndex++) {
    Status   = GetCryptoOpCapability (Operations[OpIndex], &Capabilities, &CapabilityCount);
    PssCount = 0;
    if (!EFI_ERROR (Status)) {
      for (Index = 0; Index < CapabilityCount; Index++) {
        if (AsciiStrCmp (Capabilities[Index].AlgorithmOid, "1.2.840.113549.1.1.10") == 0) {
          PssCount++;
        }
      }

      if (Capabilities != NULL) {
        FreePool (Capabilities);
      }
    }

    UT_ASSERT_NOT_EFI_ERROR (Status);
    UT_ASSERT_EQUAL (PssCount, ExpectedCount);
  }

  return UNIT_TEST_PASSED;
}

/**
  Verify that the normal provider reports RSA-PSS exactly once per operation.

  @param[in] Context  Unit-test context; unused.

  @return Unit-test status.
**/
STATIC
UNIT_TEST_STATUS
EFIAPI
PssAvailable (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  return CheckPssCapabilities (1);
}

/**
  Verify PSS is omitted when provider selection fails, then restore properties.

  @param[in] Context  Unit-test context; unused.

  @return Unit-test status.
**/
STATIC
UNIT_TEST_STATUS
EFIAPI
PssUnavailable (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UNIT_TEST_STATUS  Result;
  INT32             Restored;

  UT_ASSERT_EQUAL (EVP_set_default_properties (NULL, "provider=unavailable"), 1);
  Result   = CheckPssCapabilities (0);
  Restored = EVP_set_default_properties (NULL, "");
  UT_ASSERT_EQUAL (Restored, 1);
  return Result;
}

/**
  Run the OpenSSL-specific capability reporting regression tests.

  @param[in] Argc  Command-line argument count; unused.
  @param[in] Argv  Command-line argument values; unused.

  @retval 0  The test suites completed successfully.
  @retval 1  Framework initialization or a test failed.
**/
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
  Framework = NULL;
  Status    = InitUnitTestFramework (&Framework, "OpenSSL crypto capabilities", "CryptoOpCapability", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "RSA-PSS capability reporting", "PSS", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Report available PSS once for CMS and Authenticode", "Available", PssAvailable, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Do not report PSS when no provider matches", "Unavailable", PssUnavailable, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
