#include "SharedCrtLibSupport.h"

VOID *
CopyMem (
  IN VOID        *Destination,
  IN CONST VOID  *Source,
  IN UINTN       Length
  )
{
  CHAR8  *Destination8;
  CHAR8  *Source8;

  Destination8 = Destination;
  Source8      = (CHAR8 *)Source;
  while (Length--) {
    *(Destination8++) = *(Source8++);
  }

  return Destination;
}

CONST VOID *
EFIAPI
InternalMemScanMem8 (
  IN      CONST VOID  *Buffer,
  IN      UINTN       Length,
  IN      UINT8       Value
  )
{
  CONST UINT8  *Pointer;

  Pointer = (CONST UINT8 *)Buffer;
  do {
    if (*(Pointer++) == Value) {
      return --Pointer;
    }
  } while (--Length != 0);

  return NULL;
}

VOID
EFIAPI
ZeroMem (
  IN VOID   *Buffer,
  IN UINTN  Size
  )
{
  INT8  *Ptr;

  Ptr = Buffer;
  while (Size--) {
    *(Ptr++) = 0;
  }
}

VOID
EFIAPI
SetMem (
  OUT VOID  *Buffer,
  IN UINTN  Size,
  IN UINT8  Value
  )
{
  UINT8  *Ptr;

  Ptr = Buffer;
  while (Size-- != 0) {
    *(Ptr++) = Value;
  }
}

INTN
EFIAPI
CompareMem (
  IN CONST VOID  *DestinationBuffer,
  IN CONST VOID  *SourceBuffer,
  IN UINTN       Length
  )
{
  CONST UINT8  *Destination8;
  CONST UINT8  *Source8;

  Destination8 = (CONST UINT8 *)DestinationBuffer;
  Source8      = (CONST UINT8 *)SourceBuffer;
  while (Length-- != 0) {
    if (*(Destination8++) != *(Source8++)) {
      return *(--Destination8) - *(--Source8);
    }
  }

  return 0;
}

VOID *
EFIAPI
ScanMem8 (
  IN CONST VOID  *Buffer,
  IN UINTN       Length,
  IN UINT8       Value
  )
{
  if (Length == 0) {
    return NULL;
  }

  ASSERT (Buffer != NULL);
  ASSERT ((Length - 1) <= (MAX_ADDRESS - (UINTN)Buffer));

  return (VOID *)InternalMemScanMem8 (Buffer, Length, Value);
}

VOID *
EFIAPI
AllocatePool (
  IN UINTN  AllocationSize
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->AllocatePool == NULL)) {
    return NULL;
  }

  return gSharedDepends->AllocatePool (AllocationSize);
}

VOID
EFIAPI
FreePool (
  IN VOID  *Buffer
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->FreePool == NULL)) {
    return;
  }

  gSharedDepends->FreePool (Buffer);
}

/*
VOID
EFIAPI
DebugPrint (
  IN  UINTN        ErrorLevel,
  IN  CONST CHAR8  *Format,
  ...
  )
{
  VA_LIST  Marker;

  if ((gSharedDepends == NULL) || (gSharedDepends->DebugPrint == NULL)) {
    return;
  }

  VA_START (Marker, Format);
  gSharedDepends->DebugPrint (ErrorLevel, Format, Marker);
  VA_END (Marker);
}*/

EFI_STATUS
EFIAPI
GetTime (
  OUT  EFI_TIME               *Time,
  OUT  EFI_TIME_CAPABILITIES  *Capabilities OPTIONAL
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->GetTime == NULL)) {
    return EFI_UNSUPPORTED;
  }

  return gSharedDepends->GetTime (Time, Capabilities);
}

BOOLEAN
EFIAPI
GetRandomNumber64 (
  OUT UINT64  *Rand
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->GetRandomNumber64 == NULL)) {
    return FALSE;
  }

  return gSharedDepends->GetRandomNumber64 (Rand);
}

RETURN_STATUS
EFIAPI
AsciiStrCpyS (
  OUT CHAR8        *Destination,
  IN  UINTN        DestMax,
  IN  CONST CHAR8  *Source
  )
{
  // TODO
  return 0;
}

UINTN
EFIAPI
AsciiStrSize (
  IN      CONST CHAR8  *String
  )
{
  return 0; // (AsciiStrLen (String) + 1) * sizeof (*String);
}

INTN
EFIAPI
AsciiStrCmp (
  IN      CONST CHAR8  *FirstString,
  IN      CONST CHAR8  *SecondString
  )
{
  // TODO
  return 0;
}

// AsciiStrnLenS
UINTN
EFIAPI
AsciiStrnLenS (
  IN CONST CHAR8  *String,
  IN UINTN        MaxSize
  )
{
  // TODO
  return 0;
}

// AsciiStrnCmp
INTN
EFIAPI
AsciiStrnCmp (
  IN      CONST CHAR8  *FirstString,
  IN      CONST CHAR8  *SecondString,
  IN      UINTN        Length
  )
{
  // TODO
  return 0;
}

UINTN
EFIAPI
AsciiStrDecimalToUintn (
  IN      CONST CHAR8  *String
  )
{
  // TODO
  return 0;
}

// AsciiStrnCpyS

RETURN_STATUS
EFIAPI
AsciiStrnCpyS (
  OUT CHAR8        *Destination,
  IN  UINTN        DestMax,
  IN  CONST CHAR8  *Source,
  IN  UINTN        Length
  )
{
  // TODO
  return 0;
}

INTN
EFIAPI
AsciiStriCmp (
  IN      CONST CHAR8  *FirstString,
  IN      CONST CHAR8  *SecondString
  )
{
  // TODO
  return 0;
}

RETURN_STATUS
EFIAPI
AsciiStrCatS (
  IN OUT CHAR8        *Destination,
  IN     UINTN        DestMax,
  IN     CONST CHAR8  *Source
  ) {
    // TODO
    return 0;
  }

UINTN
EFIAPI
AsciiSPrint (
  OUT CHAR8        *StartOfBuffer,
  IN  UINTN        BufferSize,
  IN  CONST CHAR8  *FormatString,
  ...
  ) {
    return 0;
  }

UINTN
EFIAPI
AsciiStrLen (
  IN      CONST CHAR8  *String
  )
{
  UINTN  Length;

  // TODO

  for (Length = 0; *String != '\0'; String++, Length++) {
    //
    // If PcdMaximumUnicodeStringLength is not zero,
    // length should not more than PcdMaximumUnicodeStringLength
    //
  }

  return Length;
}
