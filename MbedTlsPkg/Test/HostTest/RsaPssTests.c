/** @file
  Override for RSA PSS Primitives Validation.

  This file replaces the upstream RsaPssTests.c from CryptoPkg to work around
  a known segfault in RsaPssSign/RsaPssVerify when using the RSA context.
  The test is stubbed to log the known failure and return, allowing the
  remaining test suites to continue running.

  Original: CryptoPkg/Test/UnitTest/Library/BaseCryptLib/RsaPssTests.c

  Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TestBaseCryptLib.h"

STATIC VOID  *mRsa;

UNIT_TEST_STATUS
EFIAPI
TestVerifyRsaPssPreReq (
  UNIT_TEST_CONTEXT  Context
  )
{
  mRsa = RsaNew ();

  if (mRsa == NULL) {
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  return UNIT_TEST_PASSED;
}

VOID
EFIAPI
TestVerifyRsaPssCleanUp (
  UNIT_TEST_CONTEXT  Context
  )
{
  if (mRsa != NULL) {
    RsaFree (mRsa);
    mRsa = NULL;
  }
}

UNIT_TEST_STATUS
EFIAPI
TestVerifyRsaPssSignVerify (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  //
  // Known failure: RsaPssSign/RsaPssVerify causes a segfault when using the
  // RSA context. This test is stubbed out to prevent the segfault from
  // killing the test process and blocking all subsequent test suites.
  //
  // TODO: Investigate and fix the underlying RsaPss implementation issue.
  //
  UT_LOG_WARNING ("Known failure: RsaPssSign/Verify causes segfault with RSA context - test stubbed out\n");
  return UNIT_TEST_ERROR_TEST_FAILED;
}

TEST_DESC  mRsaPssTest[] = {
  //
  // -----Description--------------------------------------Class----------------------Function---------------------------------Pre---------------------Post---------Context
  //
  { "TestVerifyRsaPssSignVerify()", "CryptoPkg.BaseCryptLib.Rsa", TestVerifyRsaPssSignVerify, TestVerifyRsaPssPreReq, TestVerifyRsaPssCleanUp, NULL },
};

UINTN  mRsaPssTestNum = ARRAY_SIZE (mRsaPssTest);
