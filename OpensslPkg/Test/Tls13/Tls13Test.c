/** @file
  TLS cipher policy and supported group configuration regressions.

  Handshake interoperability requires an external reference server because
  the firmware OpenSSL library deliberately substitutes unsupported server stubs.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "../../Library/TlsLib/InternalTlsLib.h"
#include <Library/TlsLib.h>
#include <Library/UnitTestLib.h>
#include <Library/PrintLib.h>

#if defined (__linux__)
// The firmware's unistd.h omits these native, host-only transport functions.
extern long
read (
  int            Descriptor,
  void           *Buffer,
  unsigned long  Size
  );

extern long
write (
  int            Descriptor,
  const void     *Buffer,
  unsigned long  Size
  );

#endif

STATIC VOID            *mClientCtx;
STATIC TLS_CONNECTION  *mTls;

typedef struct {
  UINT32    Id;
  CHAR8     *Name;
} TEST_GROUP;

STATIC TEST_GROUP  mGroups[] = {
  { 23,     "P-256"              },
  { 24,     "P-384"              },
  { 25,     "P-521"              },
  { 29,     "X25519"             },
  { 30,     "X448"               },
  { 0x11EB, "SecP256r1MLKEM768"  },
  { 0x11EC, "X25519MLKEM768"     },
  { 0x11ED, "SecP384r1MLKEM1024" },
};

VOID EFIAPI
ProcessLibraryConstructorList (
  VOID
  );

STATIC
VOID
EFIAPI
CleanConnection (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  TlsFree (mTls);
  TlsCtxFree (mClientCtx);
  mTls       = NULL;
  mClientCtx = NULL;
  ERR_clear_error ();
}

STATIC
UNIT_TEST_STATUS
EFIAPI
CreateConnection (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  mClientCtx = TlsCtxNew (3, 3);
  UT_ASSERT_NOT_NULL (mClientCtx);
  mTls = TlsNew (mClientCtx);
  UT_ASSERT_NOT_NULL (mTls);
  UT_ASSERT_STATUS_EQUAL (TlsSetConnectionEnd (mTls, FALSE), EFI_SUCCESS);
  return UNIT_TEST_PASSED;
}

STATIC
BOOLEAN
CipherListEquals (
  IN CONST UINT16  *Expected,
  IN UINTN         Count
  )
{
  STACK_OF (SSL_CIPHER)  *Ciphers;
  UINTN  Index;

  Ciphers = SSL_get_ciphers (mTls->Ssl);
  if ((Ciphers == NULL) || (sk_SSL_CIPHER_num (Ciphers) != (INT32)Count)) {
    return FALSE;
  }

  for (Index = 0; Index < Count; Index++) {
    if (SSL_CIPHER_get_protocol_id (sk_SSL_CIPHER_value (Ciphers, (INT32)Index)) != Expected[Index]) {
      return FALSE;
    }
  }

  return TRUE;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
Tls13Only (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT16  Ids[] = { 0x1302, 0x1301 };

  ERR_clear_error ();
  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, Ids, ARRAY_SIZE (Ids)), EFI_SUCCESS);
  UT_ASSERT_EQUAL (ERR_peek_error (), 0);
  UT_ASSERT_TRUE (CipherListEquals (Ids, ARRAY_SIZE (Ids)));
  UT_ASSERT_STATUS_EQUAL (TlsSetVersion (mTls, 3, 4), EFI_SUCCESS);
  UT_ASSERT_EQUAL (SSL_get_min_proto_version (mTls->Ssl), TLS1_3_VERSION);
  UT_ASSERT_EQUAL (SSL_get_max_proto_version (mTls->Ssl), TLS1_3_VERSION);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
Tls12Only (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT16  Ids[] = { 0xC02C, 0xC02B };

  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, Ids, ARRAY_SIZE (Ids)), EFI_SUCCESS);
  UT_ASSERT_TRUE (CipherListEquals (Ids, ARRAY_SIZE (Ids)));
  UT_ASSERT_STATUS_EQUAL (TlsSetVersion (mTls, 3, 3), EFI_SUCCESS);
  UT_ASSERT_EQUAL (SSL_get_min_proto_version (mTls->Ssl), TLS1_2_VERSION);
  UT_ASSERT_EQUAL (SSL_get_max_proto_version (mTls->Ssl), TLS1_2_VERSION);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
MixedFamilies (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT16        Ids[]      = { 0xFFFF, 0xC02C, 0x1301, 0x1303, 0xC02B, 0x1302 };
  CONST UINT16  Expected[] = { 0x1301, 0x1302, 0xC02C, 0xC02B };

  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, Ids, ARRAY_SIZE (Ids)), EFI_SUCCESS);
  UT_ASSERT_TRUE (CipherListEquals (Expected, ARRAY_SIZE (Expected)));
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
ReconfigureFamilies (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT16        Tls12[]    = { 0xC02C, 0xC02B };
  UINT16        Tls13[]    = { 0x1302, 0x1301 };
  UINT16        Mixed[]    = { 0xC02B, 0x1301, 0x1302, 0xC02C };
  CONST UINT16  Expected[] = { 0x1301, 0x1302, 0xC02B, 0xC02C };

  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, Tls12, ARRAY_SIZE (Tls12)), EFI_SUCCESS);
  UT_ASSERT_TRUE (CipherListEquals (Tls12, ARRAY_SIZE (Tls12)));
  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, Tls13, ARRAY_SIZE (Tls13)), EFI_SUCCESS);
  UT_ASSERT_TRUE (CipherListEquals (Tls13, ARRAY_SIZE (Tls13)));
  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, Tls12, ARRAY_SIZE (Tls12)), EFI_SUCCESS);
  UT_ASSERT_TRUE (CipherListEquals (Tls12, ARRAY_SIZE (Tls12)));
  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, Mixed, ARRAY_SIZE (Mixed)), EFI_SUCCESS);
  UT_ASSERT_TRUE (CipherListEquals (Expected, ARRAY_SIZE (Expected)));
  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, Tls13, ARRAY_SIZE (Tls13)), EFI_SUCCESS);
  UT_ASSERT_TRUE (CipherListEquals (Tls13, ARRAY_SIZE (Tls13)));
  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, Mixed, ARRAY_SIZE (Mixed)), EFI_SUCCESS);
  UT_ASSERT_TRUE (CipherListEquals (Expected, ARRAY_SIZE (Expected)));
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
RepeatedIds (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT16        Ids[65];
  CONST UINT16  Expected[] = { 0x1301, 0x1302 };
  UINTN         Index;

  for (Index = 0; Index < ARRAY_SIZE (Ids) - 1; Index++) {
    Ids[Index] = 0x1301;
  }

  Ids[ARRAY_SIZE (Ids) - 1] = 0x1302;
  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, Ids, ARRAY_SIZE (Ids)), EFI_SUCCESS);
  UT_ASSERT_TRUE (CipherListEquals (Expected, ARRAY_SIZE (Expected)));
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
UnsupportedCiphers (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT16        Ids[]      = { 0xFFFF, 0x1303, 0xCCA8 };
  UINT16        Supported  = 0x1301;
  CONST UINT16  Expected[] = { 0x1301 };
  UINTN         Index;

  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, &Supported, 1), EFI_SUCCESS);
  for (Index = 0; Index < ARRAY_SIZE (Ids); Index++) {
    UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, &Ids[Index], 1), EFI_UNSUPPORTED);
    UT_ASSERT_TRUE (CipherListEquals (Expected, ARRAY_SIZE (Expected)));
  }

  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, Ids, ARRAY_SIZE (Ids)), EFI_UNSUPPORTED);
  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, Ids, 0), EFI_UNSUPPORTED);
  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, NULL, 1), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, Ids, MAX_UINTN), EFI_OUT_OF_RESOURCES);
  UT_ASSERT_TRUE (CipherListEquals (Expected, ARRAY_SIZE (Expected)));
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
SupportedGroup (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  TEST_GROUP  *Group;
  UINT16      Cipher;

  Group  = Context;
  Cipher = 0x1301;
  UT_ASSERT_STATUS_EQUAL (TlsSetEcCurve (mTls, (UINT8 *)&Group->Id, sizeof (Group->Id)), EFI_SUCCESS);
  UT_ASSERT_STATUS_EQUAL (TlsSetVersion (mTls, 3, 4), EFI_SUCCESS);
  UT_ASSERT_STATUS_EQUAL (TlsSetCipherList (mTls, &Cipher, 1), EFI_SUCCESS);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
UnsupportedGroup (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT32  Group;

  Group = 0xFFFF;
  UT_ASSERT_STATUS_EQUAL (TlsSetEcCurve (mTls, (UINT8 *)&Group, sizeof (Group)), EFI_UNSUPPORTED);
  UT_ASSERT_STATUS_EQUAL (TlsSetEcCurve (mTls, (UINT8 *)&Group, sizeof (Group) - 1), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (TlsSetEcCurve (mTls, NULL, sizeof (Group)), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (TlsSetVersion (mTls, 3, 5), EFI_UNSUPPORTED);
  return UNIT_TEST_PASSED;
}

#if defined (__linux__)
STATIC
BOOLEAN
WriteSocket (
  IN INT32        Socket,
  IN CONST UINT8  *Buffer,
  IN UINTN        Size
  )
{
  INTN  Written;

  while (Size > 0) {
    Written = write (Socket, Buffer, Size);
    if (Written <= 0) {
      return FALSE;
    }

    Buffer += Written;
    Size   -= Written;
  }

  return TRUE;
}

STATIC
int
RunInterop (
  IN INT32   Socket,
  IN UINT32  Group,
  IN UINT16  Version,
  IN UINT16  Cipher
  )
{
  UINT8       BufferIn[32768];
  UINT8       BufferOut[32768];
  CHAR8       Output[512];
  UINTN       InputSize;
  UINTN       OutputSize;
  UINTN       Round;
  INTN        Received;
  EFI_STATUS  Status;
  UINT16      CurrentCipher;
  int         Result;

  Result     = 1;
  mClientCtx = TlsCtxNew (Version >> 8, Version & 0xFF);
  if (mClientCtx == NULL) {
    goto Done;
  }

  mTls = TlsNew (mClientCtx);
  if ((mTls == NULL) ||
      EFI_ERROR (TlsSetVersion (mTls, Version >> 8, Version & 0xFF)) ||
      EFI_ERROR (TlsSetCipherList (mTls, &Cipher, 1)) ||
      EFI_ERROR (TlsSetEcCurve (mTls, (UINT8 *)&Group, sizeof (Group))))
  {
    goto Done;
  }

  // The external server uses a disposable, self-signed interoperability fixture.
  TlsSetVerify (mTls, 0);
  InputSize = 0;
  for (Round = 0; Round < 100; Round++) {
    OutputSize = sizeof (BufferOut);
    Status     = TlsDoHandshake (
                   mTls,
                   (InputSize == 0) ? NULL : BufferIn,
                   InputSize,
                   BufferOut,
                   &OutputSize
                   );
    if (EFI_ERROR (Status) || !WriteSocket (Socket, BufferOut, OutputSize)) {
      goto Done;
    }

    if (!TlsInHandshake (mTls)) {
      if ((TlsGetVersion (mTls) != Version) ||
          EFI_ERROR (TlsGetCurrentCipher (mTls, &CurrentCipher)) ||
          (CurrentCipher != Cipher))
      {
        goto Done;
      }

      OutputSize = AsciiSPrint (
                     Output,
                     sizeof (Output),
                     "TLS_INTEROP protocol=%a cipher=%a group=%a version=%04x id=%04x\n",
                     SSL_get_version (mTls->Ssl),
                     SSL_CIPHER_get_name (SSL_get_current_cipher (mTls->Ssl)),
                     SSL_get0_group_name (mTls->Ssl),
                     TlsGetVersion (mTls),
                     CurrentCipher
                     );
      if (!WriteSocket (1, (UINT8 *)Output, OutputSize)) {
        goto Done;
      }

      OutputSize = sizeof (BufferOut);
      if (!EFI_ERROR (TlsCloseNotify (mTls, BufferOut, &OutputSize))) {
        WriteSocket (Socket, BufferOut, OutputSize);
      }

      Result = 0;
      goto Done;
    }

    Received = read (Socket, BufferIn, sizeof (BufferIn));
    if (Received <= 0) {
      goto Done;
    }

    InputSize = (UINTN)Received;
  }

Done:
  CleanConnection (NULL);
  return Result;
}

#endif

int
main (
  int   Argc,
  char  *Argv[]
  )
{
  UNIT_TEST_FRAMEWORK_HANDLE  Framework;
  UNIT_TEST_SUITE_HANDLE      Suite;
  EFI_STATUS                  Status;
  UINTN                       Index;

  ProcessLibraryConstructorList ();
  if (!TlsInitialize ()) {
    return 1;
  }

 #if defined (__linux__)
  // The runner passes an already-connected socket; no server code is linked here.
  if ((Argc == 6) && (AsciiStrCmp (Argv[1], "--interop") == 0)) {
    return RunInterop (
             (INT32)AsciiStrDecimalToUintn (Argv[2]),
             (UINT32)AsciiStrHexToUintn (Argv[3]),
             (UINT16)AsciiStrHexToUintn (Argv[4]),
             (UINT16)AsciiStrHexToUintn (Argv[5])
             );
  }

 #endif

  Framework = NULL;
  Status    = InitUnitTestFramework (&Framework, "TLS 1.3 policy and groups", "Tls13", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "TLS configuration", "Tls13", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    AddTestCase (Suite, "TLS 1.3 only clears legacy ciphers and sets version bounds", "Tls13Only", Tls13Only, CreateConnection, CleanConnection, NULL);
    AddTestCase (Suite, "TLS 1.2 only clears TLS 1.3 ciphers and sets version bounds", "Tls12Only", Tls12Only, CreateConnection, CleanConnection, NULL);
    AddTestCase (Suite, "Mixed families filter unavailable IDs and preserve preference", "MixedFamilies", MixedFamilies, CreateConnection, CleanConnection, NULL);
    AddTestCase (Suite, "Cipher families can be cleared and restored on the same connection", "ReconfigureFamilies", ReconfigureFamilies, CreateConnection, CleanConnection, NULL);
    AddTestCase (Suite, "Repeated IDs beyond the old fixed buffer retain the final suite", "RepeatedIds", RepeatedIds, CreateConnection, CleanConnection, NULL);
    AddTestCase (Suite, "Unknown and compiled-out suites do not report success", "UnsupportedCiphers", UnsupportedCiphers, CreateConnection, CleanConnection, NULL);
    AddTestCase (Suite, "Unsupported groups and invalid parameters", "UnsupportedGroup", UnsupportedGroup, CreateConnection, CleanConnection, NULL);
    for (Index = 0; Index < ARRAY_SIZE (mGroups); Index++) {
      AddTestCase (Suite, mGroups[Index].Name, mGroups[Index].Name, SupportedGroup, CreateConnection, CleanConnection, &mGroups[Index]);
    }

    Status = RunAllTestSuites (Framework);
  }

  CleanConnection (NULL);
  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
