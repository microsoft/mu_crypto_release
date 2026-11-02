/** @file
  C Run-Time Libraries (CRT) Wrapper Implementation for OpenSSL-based
  Cryptographic Library.

Copyright (c) 2009 - 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <CrtLibSupport.h>

int  errno = 0;

FILE  *stderr = NULL;
FILE  *stdin  = NULL;
FILE  *stdout = NULL;

typedef
int
(*SORT_COMPARE)(
  IN  VOID  *Buffer1,
  IN  VOID  *Buffer2
  );

//
// Duplicated from EDKII BaseSortLib for qsort() wrapper
//
STATIC
VOID
QuickSortWorker (
  IN OUT    VOID          *BufferToSort,
  IN CONST  UINTN         Count,
  IN CONST  UINTN         ElementSize,
  IN        SORT_COMPARE  CompareFunction,
  IN        VOID          *Buffer
  )
{
  VOID   *Pivot;
  UINTN  LoopCount;
  UINTN  NextSwapLocation;

  ASSERT (BufferToSort    != NULL);
  ASSERT (CompareFunction != NULL);
  ASSERT (Buffer          != NULL);

  if ((Count < 2) || (ElementSize  < 1)) {
    return;
  }

  NextSwapLocation = 0;

  //
  // Pick a pivot (we choose last element)
  //
  Pivot = ((UINT8 *)BufferToSort + ((Count - 1) * ElementSize));

  //
  // Now get the pivot such that all on "left" are below it
  // and everything "right" are above it
  //
  for (LoopCount = 0; LoopCount < Count - 1; LoopCount++) {
    //
    // If the element is less than the pivot
    //
    if (CompareFunction ((VOID *)((UINT8 *)BufferToSort + ((LoopCount) * ElementSize)), Pivot) <= 0) {
      //
      // Swap
      //
      CopyMem (Buffer, (UINT8 *)BufferToSort + (NextSwapLocation * ElementSize), ElementSize);
      CopyMem ((UINT8 *)BufferToSort + (NextSwapLocation * ElementSize), (UINT8 *)BufferToSort + ((LoopCount) * ElementSize), ElementSize);
      CopyMem ((UINT8 *)BufferToSort + ((LoopCount) * ElementSize), Buffer, ElementSize);

      //
      // Increment NextSwapLocation
      //
      NextSwapLocation++;
    }
  }

  //
  // Swap pivot to its final position (NextSwapLocation)
  //
  CopyMem (Buffer, Pivot, ElementSize);
  CopyMem (Pivot, (UINT8 *)BufferToSort + (NextSwapLocation * ElementSize), ElementSize);
  CopyMem ((UINT8 *)BufferToSort + (NextSwapLocation * ElementSize), Buffer, ElementSize);

  //
  // Now recurse on 2 partial lists.  Neither of these will have the 'pivot' element.
  // IE list is sorted left half, pivot element, sorted right half...
  //
  QuickSortWorker (
    BufferToSort,
    NextSwapLocation,
    ElementSize,
    CompareFunction,
    Buffer
    );

  QuickSortWorker (
    (UINT8 *)BufferToSort + (NextSwapLocation + 1) * ElementSize,
    Count - NextSwapLocation - 1,
    ElementSize,
    CompareFunction,
    Buffer
    );

  return;
}

// ---------------------------------------------------------
// Standard C Run-time Library Interface Wrapper
// ---------------------------------------------------------

//
// -- String Manipulation Routines --
//

char *
strchr (
  const char  *str,
  int         ch
  )
{
  return ScanMem8 (str, AsciiStrSize (str), (UINT8)ch);
}

/* Scan a string for the last occurrence of a character */
char *
strrchr (
  const char  *str,
  int         c
  )
{
  char  *save;

  for (save = NULL; ; ++str) {
    if (*str == c) {
      save = (char *)str;
    }

    if (*str == 0) {
      return (save);
    }
  }
}

/* Compare first n bytes of string s1 with string s2, ignoring case */
int
strncasecmp (
  const char  *s1,
  const char  *s2,
  size_t      n
  )
{
  int  Val;

  ASSERT (s1 != NULL);
  ASSERT (s2 != NULL);

  if (n != 0) {
    do {
      Val = tolower (*s1) - tolower (*s2);
      if (Val != 0) {
        return Val;
      }

      ++s1;
      ++s2;
      if (*s1 == '\0') {
        break;
      }
    } while (--n != 0);
  }

  return 0;
}

/* Read formatted data from a string */
int
sscanf (
  const char  *buffer,
  const char  *format,
  ...
  )
{
  //
  // Null sscanf() function implementation to satisfy the linker, since
  // no direct functionality logic dependency in present UEFI cases.
  //
  return 0;
}

/* Maps errnum to an error-message string */
char *
strerror (
  int  errnum
  )
{
  return NULL;
}

/* Computes the length of the maximum initial segment of the string pointed to by s1
   which consists entirely of characters from the string pointed to by s2. */
size_t
strspn (
  const char  *s1,
  const char  *s2
  )
{
  UINT8   Map[32];
  UINT32  Index;
  size_t  Count;

  for (Index = 0; Index < 32; Index++) {
    Map[Index] = 0;
  }

  while (*s2) {
    Map[*s2 >> 3] |= (1 << (*s2 & 7));
    s2++;
  }

  if (*s1) {
    Count = 0;
    while (Map[*s1 >> 3] & (1 << (*s1 & 7))) {
      Count++;
      s1++;
    }

    return Count;
  }

  return 0;
}

/* Computes the length of the maximum initial segment of the string pointed to by s1
   which consists entirely of characters not from the string pointed to by s2. */
size_t
strcspn (
  const char  *s1,
  const char  *s2
  )
{
  UINT8   Map[32];
  UINT32  Index;
  size_t  Count;

  for (Index = 0; Index < 32; Index++) {
    Map[Index] = 0;
  }

  while (*s2) {
    Map[*s2 >> 3] |= (1 << (*s2 & 7));
    s2++;
  }

  Map[0] |= 1;

  Count = 0;
  while (!(Map[*s1 >> 3] & (1 << (*s1 & 7)))) {
    Count++;
    s1++;
  }

  return Count;
}

char *
strcpy (
  char        *strDest,
  const char  *strSource
  )
{
  AsciiStrCpyS (strDest, AsciiStrnSizeS (strSource, MAX_STRING_SIZE - 1), strSource);
  return strDest;
}

char *
strncpy (
  char        *strDest,
  const char  *strSource,
  size_t      count
  )
{
  UINTN  DestMax = MAX_STRING_SIZE;

  if (count < MAX_STRING_SIZE) {
    DestMax = count + 1;
  } else {
    count = MAX_STRING_SIZE-1;
  }

  AsciiStrnCpyS (strDest, DestMax, strSource, (UINTN)count);

  return strDest;
}

char *
strcat (
  char        *strDest,
  const char  *strSource
  )
{
  UINTN  DestMax;

  DestMax = AsciiStrnLenS (strDest, MAX_STRING_SIZE) + AsciiStrnSizeS (strSource, MAX_STRING_SIZE);

  if (DestMax > MAX_STRING_SIZE) {
    DestMax = MAX_STRING_SIZE;
  }

  AsciiStrCatS (strDest, DestMax, strSource);

  return strDest;
}

int
strcmp (
  const char  *s1,
  const char  *s2
  )
{
  return (int)AsciiStrCmp (s1, s2);
}

//
// -- Character Classification Routines --
//

/* Determines if a particular character is a decimal-digit character */
int
isdigit (
  int  c
  )
{
  //
  // <digit> ::= [0-9]
  //
  return (('0' <= (c)) && ((c) <= '9'));
}

/* Determine if an integer represents character that is a hex digit */
int
isxdigit (
  int  c
  )
{
  //
  // <hexdigit> ::= [0-9] | [a-f] | [A-F]
  //
  return ((('0' <= (c)) && ((c) <= '9')) ||
          (('a' <= (c)) && ((c) <= 'f')) ||
          (('A' <= (c)) && ((c) <= 'F')));
}

/* Determines if a particular character represents a space character */
int
isspace (
  int  c
  )
{
  //
  // <space> ::= [ ]
  //
  return ((c) == ' ');
}

/* Determine if a particular character is an alphanumeric character */
int
isalnum (
  int  c
  )
{
  //
  // <alnum> ::= [0-9] | [a-z] | [A-Z]
  //
  return ((('0' <= (c)) && ((c) <= '9')) ||
          (('a' <= (c)) && ((c) <= 'z')) ||
          (('A' <= (c)) && ((c) <= 'Z')));
}

/* Determines if a particular character is in upper case */
int
isupper (
  int  c
  )
{
  //
  // <uppercase letter> := [A-Z]
  //
  return (('A' <= (c)) && ((c) <= 'Z'));
}

//
// -- Data Conversion Routines --
//

/* Convert strings to a long-integer value */
long
strtol (
  const char  *nptr,
  char        **endptr,
  int         base
  )
{
  //
  // Null strtol() function implementation to satisfy the linker, since there is
  // no direct functionality logic dependency in present UEFI cases.
  //
  return 0;
}

/* Convert strings to an unsigned long-integer value */
unsigned long
strtoul (
  const char  *nptr,
  char        **endptr,
  int         base
  )
{
  //
  // Null strtoul() function implementation to satisfy the linker, since there is
  // no direct functionality logic dependency in present UEFI cases.
  //
  return 0;
}

char *
strpbrk (
  const char  *s,
  const char  *accept
  )
{
  int  i;

  for ( ; *s != '\0'; s++) {
    for (i = 0; accept[i] != '\0'; i++) {
      if (*s == accept[i]) {
        return (char *)s;
      }
    }
  }

  return NULL;
}

/* Convert character to lowercase */
int
tolower (
  int  c
  )
{
  if (('A' <= (c)) && ((c) <= 'Z')) {
    return (c - ('A' - 'a'));
  }

  return (c);
}

//
// -- Searching and Sorting Routines --
//

/* Performs a quick sort */
void
qsort (
  void *base,
  size_t num,
  size_t width,
  int ( *compare )(const void *, const void *)
  )
{
  VOID  *Buffer;

  ASSERT (base    != NULL);
  ASSERT (compare != NULL);

  //
  // Use CRT-style malloc to cover BS and RT memory allocation.
  //
  Buffer = malloc (width);
  if (Buffer == NULL) {
    ASSERT (Buffer != NULL);
    return;
  }

  //
  // Re-use PerformQuickSort() function Implementation in EDKII BaseSortLib.
  //
  QuickSortWorker (base, (UINTN)num, (UINTN)width, (SORT_COMPARE)compare, Buffer);

  free (Buffer);
  return;
}

//
// -- Process and Environment Control Routines --
//

/* Get a value from the current environment */
char *
getenv (
  const char  *varname
  )
{
  //
  // Null getenv() function implementation to satisfy the linker, since there is
  // no direct functionality logic dependency in present UEFI cases.
  //
  return NULL;
}

/* Get a value from the current environment */
char *
secure_getenv (
  const char  *varname
  )
{
  //
  // Null secure_getenv() function implementation to satisfy the linker, since
  // there is no direct functionality logic dependency in present UEFI cases.
  //
  // From the secure_getenv() manual: 'just like getenv() except that it
  // returns NULL in cases where "secure execution" is required'.
  //
  return NULL;
}

//
// -- Stream I/O Routines --
//

/* Write data to a stream */
size_t
fwrite (
  const void  *buffer,
  size_t      size,
  size_t      count,
  FILE        *stream
  )
{
  return 0;
}

#ifdef __GNUC__

typedef
VOID
(EFIAPI *NoReturnFuncPtr)(
  VOID
  ) __attribute__ ((__noreturn__));

STATIC
VOID
EFIAPI
NopFunction (
  VOID
  )
{
}

void
abort (
  void
  )
{
  NoReturnFuncPtr  NoReturnFunc;

  NoReturnFunc = (NoReturnFuncPtr)NopFunction;

  NoReturnFunc ();
}

#else

void
abort (
  void
  )
{
  // Do nothing
}

#endif

int
fclose (
  FILE  *f
  )
{
  return 0;
}

FILE *
fopen (
  const char  *c,
  const char  *m
  )
{
  return NULL;
}

size_t
fread (
  void    *b,
  size_t  c,
  size_t  i,
  FILE    *f
  )
{
  return 0;
}

uid_t
getuid (
  void
  )
{
  return 0;
}

uid_t
geteuid (
  void
  )
{
  return 0;
}

gid_t
getgid (
  void
  )
{
  return 0;
}

gid_t
getegid (
  void
  )
{
  return 0;
}

int
printf (
  char const  *fmt,
  ...
  )
{
  return 0;
}

//
// BasePrintLib uses different vararg types, hexadecimal case, string and newline
// semantics. Only use it to convert bounded integer digits, not C format strings.
// No allocations: these entry points are also used after ExitBootServices().
//
STATIC
BOOLEAN
CrtPrintWrite (
  OUT CHAR8        *Buffer,
  IN  UINTN        Size,
  IN OUT UINTN     *Count,
  IN  CONST CHAR8  *Text,
  IN  CHAR8        Pad,
  IN  UINTN        Length
  )
{
  UINTN  CopyLength;

  if (Length > (UINTN)INT_MAX - *Count) {
    return FALSE;
  }

  if ((Size != 0) && (*Count < Size - 1)) {
    CopyLength = MIN (Length, Size - 1 - *Count);
    if (Text == NULL) {
      SetMem (Buffer + *Count, CopyLength, (UINT8)Pad);
    } else {
      CopyMem (Buffer + *Count, Text, CopyLength);
    }
  }

  *Count += Length;
  return TRUE;
}

STATIC
BOOLEAN
CrtPrintNumber (
  IN OUT CONST CHAR8  **Format,
  OUT UINTN           *Number
  )
{
  *Number = 0;
  while ((**Format >= '0') && (**Format <= '9')) {
    if (*Number > ((UINTN)INT_MAX - (**Format - '0')) / 10) {
      return FALSE;
    }

    *Number = *Number * 10 + (**Format - '0');
    (*Format)++;
  }

  return TRUE;
}

typedef enum {
  CrtInt,
  CrtChar,
  CrtShort,
  CrtLong,
  CrtLongLong,
  CrtIntMax,
  CrtSize,
  CrtPtrDiff
} CRT_PRINT_LENGTH;

/**
  Allocation-free C integer/string formatter for OpenSSL.

  Supports d/i/u/o/x/X, c/s/p, %%, standard flags, width, precision and
  hh/h/l/ll/j/z/t integer modifiers. A NULL %s prints "<NULL>" (the historical
  OpenSSL fallback). Floating point remains unsupported, matching OpenSSL 3.5's
  UEFI formatter. Wide characters, %n and positional arguments also return -1,
  as do malformed/overflowing formats. No limit is placed on format length.
**/
int
vsnprintf (
  char        *buf,
  size_t      size,
  const char  *fmt,
  va_list     args
  )
{
  va_list           Marker;
  UINTN             Count;
  UINTN             Width;
  UINTN             Precision;
  UINTN             Length;
  UINTN             Zeros;
  UINTN             Padding;
  UINTN             PrefixLength;
  UINTN             Index;
  INTN              Star;
  UINT64            Value;
  INT64             SignedValue;
  UINT32            Remainder;
  BOOLEAN           Left;
  BOOLEAN           Plus;
  BOOLEAN           Blank;
  BOOLEAN           Alternate;
  BOOLEAN           Zero;
  BOOLEAN           HasPrecision;
  BOOLEAN           Signed;
  CHAR8             Conversion;
  CHAR8             Digits[32];
  CHAR8             Prefix[2];
  CONST CHAR8       *Text;
  CRT_PRINT_LENGTH  Modifier;

  if ((fmt == NULL) || ((size != 0) && (buf == NULL))) {
    return -1;
  }

  Count = 0;
  va_copy (Marker, args);
  while (*fmt != '\0') {
    Text = fmt;
    while ((*fmt != '\0') && (*fmt != '%')) {
      fmt++;
    }

    if (!CrtPrintWrite (buf, size, &Count, Text, 0, (UINTN)(fmt - Text))) {
      goto Error;
    }

    if (*fmt == '\0') {
      break;
    }

    fmt++;
    if (*fmt == '%') {
      if (!CrtPrintWrite (buf, size, &Count, fmt++, 0, 1)) {
        goto Error;
      }

      continue;
    }

    Left = Plus = Blank = Alternate = Zero = FALSE;
    for ( ; ; fmt++) {
      if (*fmt == '-') {
        Left = TRUE;
      } else if (*fmt == '+') {
        Plus = TRUE;
      } else if (*fmt == ' ') {
        Blank = TRUE;
      } else if (*fmt == '#') {
        Alternate = TRUE;
      } else if (*fmt == '0') {
        Zero = TRUE;
      } else {
        break;
      }
    }

    if (*fmt == '*') {
      fmt++;
      Star  = va_arg (Marker, int);
      Left  = Left || (Star < 0);
      Width = (Star < 0) ? (UINTN)(-(Star + 1)) + 1 : (UINTN)Star;
      if (Width > INT_MAX) {
        goto Error;
      }
    } else if (!CrtPrintNumber (&fmt, &Width)) {
      goto Error;
    }

    HasPrecision = (*fmt == '.');
    Precision    = 0;
    if (HasPrecision) {
      fmt++;
      if (*fmt == '*') {
        fmt++;
        Star         = va_arg (Marker, int);
        HasPrecision = (Star >= 0);
        Precision    = HasPrecision ? (UINTN)Star : 0;
      } else if (!CrtPrintNumber (&fmt, &Precision)) {
        goto Error;
      }
    }

    Modifier = CrtInt;
    if (*fmt == 'h') {
      Modifier = CrtShort;
      if (*++fmt == 'h') {
        Modifier = CrtChar;
        fmt++;
      }
    } else if (*fmt == 'l') {
      Modifier = CrtLong;
      if (*++fmt == 'l') {
        Modifier = CrtLongLong;
        fmt++;
      }
    } else if (*fmt == 'j') {
      Modifier = CrtIntMax;
      fmt++;
    } else if (*fmt == 'z') {
      Modifier = CrtSize;
      fmt++;
    } else if (*fmt == 't') {
      Modifier = CrtPtrDiff;
      fmt++;
    }

    Conversion = *fmt;
    if (Conversion == '\0') {
      goto Error;
    }

    fmt++;
    PrefixLength = Zeros = 0;
    if ((Conversion == 's') || (Conversion == 'c')) {
      if ((Modifier != CrtInt) || Plus || Blank || Alternate || Zero ||
          ((Conversion == 'c') && HasPrecision))
      {
        goto Error;
      }

      if (Conversion == 's') {
        Text = va_arg (Marker, CONST CHAR8 *);
        if (Text == NULL) {
          Text = "<NULL>";
        }

        for (Length = 0; (!HasPrecision || (Length < Precision)) && (Text[Length] != '\0'); Length++) {
          if (Length == INT_MAX) {
            goto Error;
          }
        }
      } else {
        Digits[0] = (CHAR8)va_arg (Marker, int);
        Text      = Digits;
        Length    = 1;
      }
    } else {
      Signed = (Conversion == 'd') || (Conversion == 'i');
      if (Conversion == 'p') {
        if ((Modifier != CrtInt) || Plus || Blank || Alternate) {
          goto Error;
        }

        Value     = (UINTN)va_arg (Marker, VOID *);
        Alternate = TRUE;
      } else {
        if (!Signed && (Conversion != 'u') && (Conversion != 'o') &&
            (Conversion != 'x') && (Conversion != 'X'))
        {
          goto Error;
        }

        if (Signed) {
          switch (Modifier) {
            case CrtLong:
              SignedValue = va_arg (Marker, long);
              break;
            case CrtLongLong:
              SignedValue = va_arg (Marker, long long);
              break;
            case CrtIntMax:
              SignedValue = (sizeof (long) == sizeof (INT64)) ?
                            va_arg (Marker, long) : va_arg (Marker, long long);
              break;
            case CrtSize:
            case CrtPtrDiff:
              SignedValue = va_arg (Marker, INTN);
              break;
            default:
              SignedValue = va_arg (Marker, int);
              if (Modifier == CrtChar) {
                SignedValue = (signed char)SignedValue;
              } else if (Modifier == CrtShort) {
                SignedValue = (short)SignedValue;
              }

              break;
          }

          Value = (SignedValue < 0) ? 0 - (UINT64)SignedValue : (UINT64)SignedValue;
          if ((SignedValue < 0) || Plus || Blank) {
            Prefix[PrefixLength++] = (SignedValue < 0) ? '-' : (Plus ? '+' : ' ');
          }
        } else {
          switch (Modifier) {
            case CrtLong:
              Value = va_arg (Marker, unsigned long);
              break;
            case CrtLongLong:
              Value = va_arg (Marker, unsigned long long);
              break;
            case CrtIntMax:
              Value = (sizeof (long) == sizeof (UINT64)) ?
                      va_arg (Marker, unsigned long) : va_arg (Marker, unsigned long long);
              break;
            case CrtSize:
            case CrtPtrDiff:
              Value = va_arg (Marker, UINTN);
              break;
            case CrtChar:
              Value = (unsigned char)va_arg (Marker, int);
              break;
            case CrtShort:
              Value = (unsigned short)va_arg (Marker, int);
              break;
            default:
              Value = va_arg (Marker, unsigned int);
              break;
          }
        }
      }

      if (Conversion == 'o') {
        Index = sizeof (Digits);
        do {
          Value           = DivU64x32Remainder (Value, 8, &Remainder);
          Digits[--Index] = (CHAR8)('0' + Remainder);
        } while (Value != 0);

        Length = sizeof (Digits) - Index;
        Text   = Digits + Index;
      } else {
        Length = AsciiSPrint (
                   Digits,
                   sizeof (Digits),
                   (Signed || (Conversion == 'u')) ? "%Lu" : "%Lx",
                   Value
                   );
        Text = Digits;
        if (Conversion != 'X') {
          for (Index = 0; Index < Length; Index++) {
            if ((Digits[Index] >= 'A') && (Digits[Index] <= 'F')) {
              Digits[Index] += 'a' - 'A';
            }
          }
        }

        if (Alternate && ((Conversion == 'p') ||
                          (((Conversion == 'x') || (Conversion == 'X')) && (Value != 0))))
        {
          Prefix[PrefixLength++] = '0';
          Prefix[PrefixLength++] = (Conversion == 'X') ? 'X' : 'x';
        }
      }

      if (HasPrecision && (Precision == 0) && (Length == 1) && (Text[0] == '0')) {
        Length = 0;
      }

      Zeros = (Precision > Length) ? Precision - Length : 0;
      if ((Conversion == 'o') && Alternate && ((Length == 0) || (Text[0] != '0')) && (Zeros == 0)) {
        Zeros = 1;
      }

      if (Zero && !Left && !HasPrecision && (Width > PrefixLength + Length)) {
        Zeros = Width - PrefixLength - Length;
      }
    }

    Padding = PrefixLength + Zeros + Length;
    Padding = (Width > Padding) ? Width - Padding : 0;
    if ((!Left && !CrtPrintWrite (buf, size, &Count, NULL, ' ', Padding)) ||
        !CrtPrintWrite (buf, size, &Count, Prefix, 0, PrefixLength) ||
        !CrtPrintWrite (buf, size, &Count, NULL, '0', Zeros) ||
        !CrtPrintWrite (buf, size, &Count, Text, 0, Length) ||
        (Left && !CrtPrintWrite (buf, size, &Count, NULL, ' ', Padding)))
    {
      goto Error;
    }
  }

  if (size != 0) {
    buf[MIN (Count, size - 1)] = '\0';
  }

  va_end (Marker);
  return (int)Count;

Error:
  if (size != 0) {
    buf[0] = '\0';
  }

  va_end (Marker);
  return -1;
}

int
snprintf (
  char        *buf,
  size_t      size,
  const char  *fmt,
  ...
  )
{
  va_list  Args;
  int      Result;

  va_start (Args, fmt);
  Result = vsnprintf (buf, size, fmt, Args);
  va_end (Args);
  return Result;
}

int
sprintf (
  char        *buf,
  const char  *fmt,
  ...
  )
{
  va_list  Args;
  int      Result;

  va_start (Args, fmt);
  Result = vsnprintf (buf, (UINTN)-1, fmt, Args);
  va_end (Args);
  return Result;
}
