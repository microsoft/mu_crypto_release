#ifndef SHARED_CRT_LIB_H
#define SHARED_CRT_LIB_H

#include <Uefi.h>

typedef UINTN size_t;

// Typedefs for UEFI functions
typedef VOID *(*ALLOCATE_POOL)(
  UINTN  AllocationSize
  );
typedef VOID (*FREE_POOL)(
  VOID  *Buffer
  );
typedef VOID *(*COPY_MEM)(
  VOID        *Destination,
  CONST VOID  *Source,
  UINTN       Length
  );
typedef VOID (*ASSERT_T)(
  BOOLEAN  Expression
  );

typedef
VOID
(EFIAPI *DEBUG_PRINT)(
  IN UINTN        ErrorLevel,
  IN CONST CHAR8  *Format,
  ...
  );

typedef EFI_STATUS (EFIAPI *GET_TIME)(
  OUT  EFI_TIME               *Time,
  OUT  EFI_TIME_CAPABILITIES  *Capabilities OPTIONAL
  );

/**
  Copies a string to a destination buffer.

  @param[out]  Destination  Pointer to the destination buffer.
  @param[in]   DestMax      Maximum size of the destination buffer.
  @param[in]   Source       Pointer to the source string.

  @retval RETURN_SUCCESS           The string was copied successfully.
  @retval RETURN_BUFFER_TOO_SMALL  The destination buffer is too small.
**/
typedef
RETURN_STATUS
(EFIAPI *ASCII_STR_CPY_S)(
    OUT CHAR8        *Destination,
    IN  UINTN        DestMax,
    IN  CONST CHAR8  *Source
    );

/**
  Returns the size of a Null-terminated ASCII string in bytes, including the Null terminator.

  @param[in]  String  Pointer to the Null-terminated ASCII string.

  @return The size of the Null-terminated ASCII string in bytes, including the Null terminator.
**/
typedef UINTN (EFIAPI *ASCII_STR_SIZE)(
  IN      CONST CHAR8  *String
  );

/**
  Compares two Null-terminated ASCII strings.

  @param[in]  FirstString   Pointer to the first Null-terminated ASCII string.
  @param[in]  SecondString  Pointer to the second Null-terminated ASCII string.

  @retval 0   The strings are identical.
  @retval <0  The first string is less than the second string.
  @retval >0  The first string is greater than the second string.
**/
typedef INTN (EFIAPI *ASCII_STR_CMP)(
  IN      CONST CHAR8  *FirstString,
  IN      CONST CHAR8  *SecondString
  );
/**
  Returns the length of a Null-terminated ASCII string.

  @param[in]  String  Pointer to the Null-terminated ASCII string.
  @param[in]  MaxSize Maximum number of ASCII characters to examine.

  @return The length of the Null-terminated ASCII string.
**/
typedef UINTN (EFIAPI *ASCII_STRN_LEN_S)(
  IN CONST CHAR8  *String,
  IN UINTN        MaxSize
  );

/**
  Compares two Null-terminated ASCII strings with a specified length.

  @param[in]  FirstString   Pointer to the first Null-terminated ASCII string.
  @param[in]  SecondString  Pointer to the second Null-terminated ASCII string.
  @param[in]  Length        Maximum number of ASCII characters to compare.

  @retval 0   The strings are identical.
  @retval <0  The first string is less than the second string.
  @retval >0  The first string is greater than the second string.
**/
typedef INTN (EFIAPI *ASCII_STRN_CMP)(
  IN      CONST CHAR8  *FirstString,
  IN      CONST CHAR8  *SecondString,
  IN      UINTN        Length
  );

/**
  Converts a Null-terminated ASCII string to an unsigned integer.

  @param[in]  String  Pointer to the Null-terminated ASCII string.

  @return The unsigned integer value of the string.
**/
typedef UINTN (EFIAPI *ASCII_STR_DECIMAL_TO_UINTN)(
  IN      CONST CHAR8  *String
  );

/**
  Copies a specified length of a string to a destination buffer.

  @param[out]  Destination  Pointer to the destination buffer.
  @param[in]   DestMax      Maximum size of the destination buffer.
  @param[in]   Source       Pointer to the source string.
  @param[in]   Length       Number of characters to copy.

  @retval RETURN_SUCCESS           The string was copied successfully.
  @retval RETURN_BUFFER_TOO_SMALL  The destination buffer is too small.
**/
typedef RETURN_STATUS (EFIAPI *ASCII_STRN_CPY_S)(
  OUT CHAR8        *Destination,
  IN  UINTN        DestMax,
  IN  CONST CHAR8  *Source,
  IN  UINTN        Length
  );

/**
  Compares two Null-terminated ASCII strings in a case-insensitive manner.

  @param[in]  FirstString   Pointer to the first Null-terminated ASCII string.
  @param[in]  SecondString  Pointer to the second Null-terminated ASCII string.

  @retval 0   The strings are identical.
  @retval <0  The first string is less than the second string.
  @retval >0  The first string is greater than the second string.
**/
typedef INTN (EFIAPI *ASCII_STRI_CMP)(
  IN      CONST CHAR8  *FirstString,
  IN      CONST CHAR8  *SecondString
  );

/**
  Concatenates a source string to the end of a destination string.

  @param[in, out]  Destination  Pointer to the destination buffer.
  @param[in]       DestMax      Maximum size of the destination buffer.
  @param[in]       Source       Pointer to the source string.

  @retval RETURN_SUCCESS           The string was concatenated successfully.
  @retval RETURN_BUFFER_TOO_SMALL  The destination buffer is too small.
**/
typedef RETURN_STATUS (EFIAPI *ASCII_STR_CAT_S)(
  IN OUT CHAR8        *Destination,
  IN     UINTN        DestMax,
  IN     CONST CHAR8  *Source
  );

/**
  Produces a Null-terminated ASCII string in an output buffer based on a Null-terminated
  ASCII format string and variable argument list.

  @param[out]  StartOfBuffer  Pointer to the output buffer.
  @param[in]   BufferSize     Size of the output buffer in bytes.
  @param[in]   FormatString   Pointer to the Null-terminated ASCII format string.
  @param[in]   ...            Variable argument list.

  @return The number of ASCII characters printed to the output buffer, not including
          the Null-terminator.
**/
typedef UINTN (EFIAPI *ASCII_S_PRINT)(
  OUT CHAR8        *StartOfBuffer,
  IN  UINTN        BufferSize,
  IN  CONST CHAR8  *FormatString,
  ...
  );

/**
  Returns the length of a Null-terminated ASCII string.

  @param[in]  String  Pointer to the Null-terminated ASCII string.

  @return The length of the Null-terminated ASCII string.
**/
typedef UINTN (EFIAPI *ASCII_STR_LEN)(
  IN      CONST CHAR8  *String
  );

typedef
BOOLEAN
(EFIAPI *GET_RANDOM_NUMBER_64)(
  OUT UINT64  *Rand
  );

// Structure to hold function pointers
typedef struct  _SHARED_DEPENDENCIES {
  ALLOCATE_POOL           AllocatePool;
  FREE_POOL               FreePool;
  COPY_MEM                CopyMem;
  ASSERT_T                ASSERT;       // TODO
  GET_TIME                GetTime;
  DEBUG_PRINT             DebugPrint;
  GET_RANDOM_NUMBER_64    GetRandomNumber64;
  ASCII_STR_CPY_S         AsciiStrCpyS;
  ASCII_STR_SIZE          AsciiStrSize;
  ASCII_STR_CMP           AsciiStrCmp;
  ASCII_STRN_LEN_S        AsciiStrnLenS;
  ASCII_STRN_CMP          AsciiStrnCmp;
  ASCII_STR_DECIMAL_TO_UINTN  AsciiStrDecimalToUintn;
  ASCII_STRN_CPY_S        AsciiStrnCpyS;
  ASCII_STRI_CMP          AsciiStriCmp;
  ASCII_STR_CAT_S         AsciiStrCatS;
  ASCII_S_PRINT           AsciiSPrint;
  ASCII_STR_LEN           AsciiStrLen;
} SHARED_DEPENDENCIES;

SHARED_DEPENDENCIES  *gSharedDepends;


///////////////////////////////////////////////////////////////////////////////
///
///////////////////////////////////////////////////////////////////////////////

#define ASSERT  gSharedDepends->ASSERT;

// TODO might make more sense to move this to a separate file
#define DEBUG_ERROR  0x80000000
#define DEBUG_WARN   0x40000000
#define DEBUG_INFO   0x20000000
#define DEBUG_VERBOSE 0x10000000
#define DEBUG(Args) \
  do { \
    if (gSharedDepends != NULL && gSharedDepends->DebugPrint != NULL) { \
      gSharedDepends->DebugPrint Args; \
    } \
  } while (0)

VOID *
EFIAPI
AllocatePool (
  IN UINTN  AllocationSize
  );

VOID
EFIAPI
FreePool (
  IN VOID  *Buffer
  );

VOID *
EFIAPI
ScanMem8 (
  IN CONST VOID  *Buffer,
  IN UINTN       Length,
  IN UINT8       Value
  );

VOID
ZeroMem (
  IN VOID   *Buffer,
  IN UINTN  Size
  );

VOID
EFIAPI
SetMem (
  OUT VOID  *Buffer,
  IN UINTN  Size,
  IN UINT8  Value
  );

INTN
EFIAPI
CompareMem (
  IN CONST VOID  *DestinationBuffer,
  IN CONST VOID  *SourceBuffer,
  IN UINTN       Length
  );

VOID *
EFIAPI
CopyMem (
  OUT VOID        *DestinationBuffer,
  IN  CONST VOID  *SourceBuffer,
  IN  UINTN       Length
  );

EFI_STATUS
EFIAPI
GetTime (
  OUT  EFI_TIME               *Time,
  OUT  EFI_TIME_CAPABILITIES  *Capabilities OPTIONAL
  );

BOOLEAN
EFIAPI
GetRandomNumber64 (
  OUT UINT64  *Rand
  );

INT64
EFIAPI
DivS64x64Remainder (
  IN      INT64  Dividend,
  IN      INT64  Divisor,
  OUT     INT64  *Remainder  OPTIONAL
  );

RETURN_STATUS
EFIAPI
AsciiStrCpyS (
  OUT CHAR8        *Destination,
  IN  UINTN        DestMax,
  IN  CONST CHAR8  *Source
  );


UINTN
EFIAPI
AsciiStrLen (
  IN      CONST CHAR8  *String
  );

RETURN_STATUS
EFIAPI
AsciiStrCpyS (
  OUT CHAR8        *Destination,
  IN  UINTN        DestMax,
  IN  CONST CHAR8  *Source
  );

UINTN
EFIAPI
AsciiStrSize (
  IN      CONST CHAR8  *String
  );

INTN
EFIAPI
AsciiStrCmp (
  IN      CONST CHAR8  *FirstString,
  IN      CONST CHAR8  *SecondString
  );


UINTN
EFIAPI
AsciiStrnLenS (
  IN CONST CHAR8  *String,
  IN UINTN        MaxSize
  );

  // AsciiStrnCmp
INTN
EFIAPI
AsciiStrnCmp (
  IN      CONST CHAR8  *FirstString,
  IN      CONST CHAR8  *SecondString,
  IN      UINTN        Length
  );

// AsciiStrDecimalToUintn

UINTN
EFIAPI
AsciiStrDecimalToUintn (
  IN      CONST CHAR8  *String
  );

RETURN_STATUS
EFIAPI
AsciiStrnCpyS (
  OUT CHAR8        *Destination,
  IN  UINTN        DestMax,
  IN  CONST CHAR8  *Source,
  IN  UINTN        Length
  );

INTN
EFIAPI
AsciiStriCmp (
  IN      CONST CHAR8  *FirstString,
  IN      CONST CHAR8  *SecondString
  );

RETURN_STATUS
EFIAPI
AsciiStrCatS (
  IN OUT CHAR8        *Destination,
  IN     UINTN        DestMax,
  IN     CONST CHAR8  *Source
  );

UINTN
EFIAPI
AsciiSPrint (
  OUT CHAR8        *StartOfBuffer,
  IN  UINTN        BufferSize,
  IN  CONST CHAR8  *FormatString,
  ...
  );

UINT16
EFIAPI
WriteUnaligned16 (
  OUT UINT16  *Buffer,
  IN  UINT16  Value
  );

UINT32
EFIAPI
WriteUnaligned32 (
  OUT UINT32  *Buffer,
  IN  UINT32  Value
  );


#endif // SHARED_CRT_LIB_H