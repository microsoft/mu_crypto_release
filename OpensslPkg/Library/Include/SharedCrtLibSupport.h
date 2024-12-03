#ifndef SHARED_CRT_LIB_H
#define SHARED_CRYPTO_LIB_H

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

// AsciiStrCpyS
// AsciiStrCmp

typedef
RETURN_STATUS
(EFIAPI *ASCII_STR_CPY_S)(
    OUT CHAR8        *Destination,
    IN  UINTN        DestMax,
    IN  CONST CHAR8  *Source
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
} SHARED_DEPENDENCIES;

SHARED_DEPENDENCIES  *gSharedDepends;


///////////////////////////////////////////////////////////////////////////////
///
///////////////////////////////////////////////////////////////////////////////

#define ASSERT  gSharedDepends->ASSERT;

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

#endif // SHARED_CRYPTO_LIB_H
