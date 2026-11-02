/** @file
  Exercise the real CRT wrappers, not the host libc formatting implementation.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UnitTestLib.h>
#include <stdarg.h>

int
CrtTestVsnprintf (
  char        *Buffer,
  UINTN       Size,
  const char  *Format,
  va_list     Args
  );

int
CrtTestSnprintf (
  char        *Buffer,
  UINTN       Size,
  const char  *Format,
  ...
  );

int
CrtTestSprintf (
  char        *Buffer,
  const char  *Format,
  ...
  );

VOID EFIAPI
ProcessLibraryConstructorList (
  VOID
  );

STATIC
int
Format (
  CHAR8        *Buffer,
  UINTN        Size,
  CONST CHAR8  *String,
  ...
  )
{
  va_list  Args;
  int      Result;

  va_start (Args, String);
  Result = CrtTestVsnprintf (Buffer, Size, String, Args);
  va_end (Args);
  return Result;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
Strings (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  CHAR8        Buffer[128];
  CONST CHAR8  BoundedString[3] = { 'a', 'b', 'c' };

  UT_ASSERT_EQUAL (Format (Buffer, sizeof (Buffer), "text:%s %% %c\n", "ascii", 'Z'), 15);
  UT_ASSERT_MEM_EQUAL (Buffer, "text:ascii % Z\n", 16);
  UT_ASSERT_EQUAL (CrtTestSnprintf (Buffer, sizeof (Buffer), "%s", (CHAR8 *)NULL), 6);
  UT_ASSERT_MEM_EQUAL (Buffer, "<NULL>", 7);
  UT_ASSERT_EQUAL (Format (Buffer, sizeof (Buffer), "[%8.3s][%-6s][%.*s]", "abcdef", "xy", 2, "abcd"), 22);
  UT_ASSERT_MEM_EQUAL (Buffer, "[     abc][xy    ][ab]", 23);
  UT_ASSERT_EQUAL (Format (Buffer, sizeof (Buffer), "[%*.*s]", -6, -1, "abc"), 8);
  UT_ASSERT_MEM_EQUAL (Buffer, "[abc   ]", 9);
  UT_ASSERT_EQUAL (Format (Buffer, sizeof (Buffer), "%.0s", (CHAR8 *)NULL), 0);
  UT_ASSERT_EQUAL (Buffer[0], 0);
  UT_ASSERT_EQUAL (Format (Buffer, sizeof (Buffer), "%.3s", BoundedString), 3);
  UT_ASSERT_MEM_EQUAL (Buffer, "abc", 4);
  UT_ASSERT_EQUAL (Format (Buffer, sizeof (Buffer), "[%8.3s]", (CHAR8 *)NULL), 10);
  UT_ASSERT_MEM_EQUAL (Buffer, "[     <NU]", 11);
  UT_ASSERT_EQUAL (Format (Buffer, sizeof (Buffer), "%cX", 0), 2);
  UT_ASSERT_MEM_EQUAL (Buffer, "\0X", 3);
  UT_ASSERT_EQUAL (CrtTestSprintf (Buffer, "%s:%04x", "value", 0xAB), 10);
  UT_ASSERT_MEM_EQUAL (Buffer, "value:00ab", 11);
  return UNIT_TEST_PASSED;
}

STATIC
BOOLEAN
MatchesLibc (
  CONST CHAR8  *String,
  ...
  )
{
  CONST UINTN  Sizes[] = { 0, 1, 2, 7, 128 };
  CHAR8        Actual[128];
  CHAR8        Expected[128];
  va_list      Args;
  va_list      Copy;
  int          Result;
  int          Reference;
  UINTN        Index;

  va_start (Args, String);
  for (Index = 0; Index < ARRAY_SIZE (Sizes); Index++) {
    SetMem (Actual, sizeof (Actual), '!');
    SetMem (Expected, sizeof (Expected), '!');
    va_copy (Copy, Args);
    Result = CrtTestVsnprintf (Actual, Sizes[Index], String, Copy);
    va_end (Copy);
    va_copy (Copy, Args);
    Reference = vsnprintf (Expected, Sizes[Index], String, Copy);
    va_end (Copy);
    if ((Result != Reference) || (CompareMem (Actual, Expected, sizeof (Actual)) != 0)) {
      va_end (Args);
      return FALSE;
    }
  }

  va_end (Args);
  return TRUE;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
NativeReference (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  CONST int  Values[]     = { 0, 1, -1, 2147483647, (-2147483647 - 1) };
  CONST int  Widths[]     = { -12, -1, 0, 1, 12 };
  CONST int  Precisions[] = { -1, 0, 1, 9 };
  UINTN      Value;
  UINTN      Width;
  UINTN      Precision;

  for (Value = 0; Value < ARRAY_SIZE (Values); Value++) {
    for (Width = 0; Width < ARRAY_SIZE (Widths); Width++) {
      for (Precision = 0; Precision < ARRAY_SIZE (Precisions); Precision++) {
        UT_ASSERT_TRUE (
          MatchesLibc (
            "[%+0*.*d][% *.*i]",
            Widths[Width],
            Precisions[Precision],
            Values[Value],
            Widths[Width],
            Precisions[Precision],
            Values[Value]
            )
          );
        UT_ASSERT_TRUE (
          MatchesLibc (
            "[%#0*.*x][%#*.*X][%#0*.*o][%0*.*u]",
            Widths[Width],
            Precisions[Precision],
            (unsigned int)Values[Value],
            Widths[Width],
            Precisions[Precision],
            (unsigned int)Values[Value],
            Widths[Width],
            Precisions[Precision],
            (unsigned int)Values[Value],
            Widths[Width],
            Precisions[Precision],
            (unsigned int)Values[Value]
            )
          );
        UT_ASSERT_TRUE (MatchesLibc ("[%*.*s]", Widths[Width], Precisions[Precision], "string"));
      }
    }
  }

  UT_ASSERT_TRUE (
    MatchesLibc (
      "%ld %lu %lld %llu %llx %llo",
      (long)(-9223372036854775807LL - 1),
      (unsigned long)18446744073709551615ULL,
      (-9223372036854775807LL - 1),
      18446744073709551615ULL,
      18446744073709551615ULL,
      18446744073709551615ULL
      )
    );
  UT_ASSERT_TRUE (MatchesLibc ("%hhd %hhu %hd %hu", 255, 257, 65535, 65537));
  UT_ASSERT_TRUE (MatchesLibc ("%zd %zu %td %tu", (INTN)-1, (UINTN)-1, (INTN)-1, (UINTN)-1));
 #if defined (__GNUC__)
  UT_ASSERT_TRUE (MatchesLibc ("%jd %ju", (__INTMAX_TYPE__)-1, (__UINTMAX_TYPE__)-1));
 #else
  UT_ASSERT_TRUE (MatchesLibc ("%jd %ju", (INT64)-1, (UINT64)-1));
 #endif
  UT_ASSERT_TRUE (MatchesLibc ("%% %s %c\n\r\n", "ascii", 'c'));
  UT_ASSERT_TRUE (MatchesLibc ("%cX", 0));
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
Integers (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  CHAR8  Buffer[256];

  UT_ASSERT_EQUAL (
    Format (
      Buffer,
      sizeof (Buffer),
      "%+08d|% 5i|%-6u|%#08x|%#X|%#o",
      -42,
      7,
      23U,
      0xABU,
      0xABU,
      9U
      ),
    39
    );
  UT_ASSERT_MEM_EQUAL (Buffer, "-0000042|    7|23    |0x0000ab|0XAB|011", 40);
  UT_ASSERT_EQUAL (
    Format (
      Buffer,
      sizeof (Buffer),
      "[%08.4d][%.0u][%#.0o][%#x][%*.*d]",
      -12,
      0U,
      0U,
      0U,
      7,
      3,
      5
      ),
    27
    );
  UT_ASSERT_MEM_EQUAL (Buffer, "[   -0012][][0][0][    005]", 28);
  UT_ASSERT_EQUAL (
    Format (
      Buffer,
      sizeof (Buffer),
      "%hhd %hhu %hd %hu",
      255,
      257,
      65535,
      65537
      ),
    9
    );
  UT_ASSERT_MEM_EQUAL (Buffer, "-1 1 -1 1", 10);
  UT_ASSERT_EQUAL (
    Format (
      Buffer,
      sizeof (Buffer),
      "%ld %lu %lld %llu",
      (long)-123,
      (unsigned long)456,
      (long long)(-9223372036854775807LL - 1),
      (unsigned long long)18446744073709551615ULL
      ),
    50
    );
  UT_ASSERT_MEM_EQUAL (Buffer, "-123 456 -9223372036854775808 18446744073709551615", 51);
  UT_ASSERT_EQUAL (
    Format (
      Buffer,
      sizeof (Buffer),
      "%zd %zu %td %tu",
      (INTN)-12,
      (UINTN)34,
      (INTN)-56,
      (UINTN)78
      ),
    13
    );
  UT_ASSERT_MEM_EQUAL (Buffer, "-12 34 -56 78", 14);
  UT_ASSERT_EQUAL (
    Format (
      Buffer,
      sizeof (Buffer),
      "%llx %llo",
      (unsigned long long)0xFEDCBA9876543210ULL,
      (unsigned long long)18446744073709551615ULL
      ),
    39
    );
  UT_ASSERT_MEM_EQUAL (Buffer, "fedcba9876543210 1777777777777777777777", 40);
  UT_ASSERT_EQUAL (Format (Buffer, sizeof (Buffer), "%p", (VOID *)(UINTN)0x12AB), 6);
  UT_ASSERT_MEM_EQUAL (Buffer, "0x12ab", 7);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
Bounds (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  CHAR8  Buffer[16];
  CHAR8  LongFormat[1026];
  CHAR8  LongString[5001];
  CHAR8  LongOutput[5001];
  UINTN  Index;

  SetMem (Buffer, sizeof (Buffer), '!');
  UT_ASSERT_EQUAL (Format (Buffer, 5, "a%s:%d", "bcdef", 12), 9);
  UT_ASSERT_MEM_EQUAL (Buffer, "abcd", 5);
  UT_ASSERT_EQUAL (Buffer[5], '!');
  UT_ASSERT_EQUAL (Format (Buffer, 1, "%08x", 0xABU), 8);
  UT_ASSERT_EQUAL (Buffer[0], 0);
  Buffer[0] = '!';
  UT_ASSERT_EQUAL (Format (Buffer, 0, "%s:%d", "abc", 12), 6);
  UT_ASSERT_EQUAL (Buffer[0], '!');
  UT_ASSERT_EQUAL (Format (NULL, 0, "%s:%d", "abc", 12), 6);
  UT_ASSERT_EQUAL (Format (NULL, 0, "%2147483647d", 1), 2147483647);
  UT_ASSERT_EQUAL (Format (NULL, 0, "%2147483647d!", 1), -1);
  for (Index = 0; Index < sizeof (LongFormat) - 3; Index++) {
    LongFormat[Index] = 'a';
  }

  LongFormat[Index++] = '%';
  LongFormat[Index++] = 'd';
  LongFormat[Index]   = 0;
  UT_ASSERT_EQUAL (Format (Buffer, sizeof (Buffer), LongFormat, 12), 1025);
  UT_ASSERT_MEM_EQUAL (Buffer, "aaaaaaaaaaaaaaa", sizeof (Buffer));
  UT_ASSERT_EQUAL (Format (NULL, 0, LongFormat, 12), 1025);
  LongFormat[Index - 1] = '\0';
  UT_ASSERT_EQUAL (Format (Buffer, sizeof (Buffer), LongFormat), -1);
  UT_ASSERT_EQUAL (Buffer[0], 0);
  SetMem (LongString, sizeof (LongString) - 1, 'a');
  LongString[sizeof (LongString) - 1] = '\0';
  UT_ASSERT_EQUAL (CrtTestSprintf (LongOutput, "%s", LongString), sizeof (LongString) - 1);
  UT_ASSERT_MEM_EQUAL (LongOutput, LongString, sizeof (LongString));
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
Invalid (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  CONST CHAR8  *Formats[] = {
    "%",            "%1",            "%.", "%ll", "%q", "%n", "%ls", "%lc",
    "%f",           "%F",            "%e", "%E",  "%g", "%G", "%a",  "%A", "%Lf","%1$d",
    "%2147483648d", "%.2147483648s", "%#s"
  };
  CHAR8        Buffer[16];
  UINTN        Index;
  int          NotEvaluated;

  NotEvaluated = 0;
  UT_ASSERT_EQUAL ((assert (++NotEvaluated), 7), 7);
  UT_ASSERT_EQUAL (NotEvaluated, 0);
  for (Index = 0; Index < ARRAY_SIZE (Formats); Index++) {
    Buffer[0] = '!';
    UT_ASSERT_EQUAL (Format (Buffer, sizeof (Buffer), Formats[Index]), -1);
    UT_ASSERT_EQUAL (Buffer[0], 0);
  }

  UT_ASSERT_EQUAL (Format (NULL, 1, "text"), -1);
  UT_ASSERT_EQUAL (Format (Buffer, sizeof (Buffer), NULL), -1);
  UT_ASSERT_EQUAL (Format (Buffer, sizeof (Buffer), "%*s", (-2147483647 - 1), ""), -1);
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
  Framework = NULL;
  Status    = InitUnitTestFramework (&Framework, "OpenSSL CRT wrappers", "CrtWrapper", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "C99 formatting", "CRT", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    AddTestCase (Suite, "ASCII, NULL, precision, percent and sprintf", "Strings", Strings, NULL, NULL, NULL);
    AddTestCase (Suite, "Integer flags, modifiers and exact output", "Integers", Integers, NULL, NULL, NULL);
    AddTestCase (Suite, "Truncation, zero size and long formats", "Bounds", Bounds, NULL, NULL, NULL);
    AddTestCase (Suite, "Unsupported, malformed and overflowing formats", "Invalid", Invalid, NULL, NULL, NULL);
    AddTestCase (Suite, "Native libc reference across flags and output sizes", "NativeReference", NativeReference, NULL, NULL, NULL);
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
