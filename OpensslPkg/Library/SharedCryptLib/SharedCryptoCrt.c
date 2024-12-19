/** @file
  C Run-Time Libraries (CRT) implementations
  These either call the shared implementations or implement the logic itself
  if the implementation is simple enough that the code may be throughly vetted
  to ensure safety.

  Copyright (c) Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <SharedCrtLibSupport.h>

/**
  Copies a source buffer to a destination buffer.

  This function copies Length bytes from Source to Destination. The implementation
  handles overlapping memory regions correctly.

  @param[in]  Destination  Pointer to the destination buffer.
  @param[in]  Source       Pointer to the source buffer.
  @param[in]  Length       Number of bytes to copy.

  @return     Destination  Pointer to the destination buffer.
**/
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

/**
  Scans a target buffer for an 8-bit value and returns a pointer to the matching byte in the buffer.

  @param[in]  Buffer  The target buffer to scan.
  @param[in]  Length  The number of bytes in the buffer to scan.
  @param[in]  Value   The value to search for in the target buffer.

  @retval  Pointer to the matching byte in the buffer if found.
  @retval  NULL if the value is not found in the buffer.
**/
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

/**
  Sets a buffer to all zeros.

  This function sets the first Size bytes of the buffer specified by Buffer to zero.

  @param[in]  Buffer  A pointer to the buffer to set to zero.
  @param[in]  Size    The number of bytes to set to zero.

**/
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

/**
  Sets a buffer to a specified value.

  @param[out]  Buffer  A pointer to the buffer to set.
  @param[in]   Size    The number of bytes to set in the buffer.
  @param[in]   Value   The value to set each byte of the buffer to.

**/
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

/**
  Compares the contents of two memory buffers.

  @param[in]  DestinationBuffer  A pointer to the destination buffer.
  @param[in]  SourceBuffer       A pointer to the source buffer.
  @param[in]  Length             The number of bytes to compare.

  @retval 0   All Length bytes of the two buffers are identical.
  @retval >0  The first byte that does not match in both buffers has a greater value in DestinationBuffer than in SourceBuffer.
  @retval <0  The first byte that does not match in both buffers has a lesser value in DestinationBuffer than in SourceBuffer.
**/
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

/**
  Scans a memory buffer for an 8-bit value.

  @param[in]  Buffer  The pointer to the memory buffer to scan.
  @param[in]  Length  The number of bytes in the memory buffer to scan.
  @param[in]  Value   The value to search for in the memory buffer.

  @retval     NULL    If Length is 0 or the value is not found in the buffer.
  @retval     Others  A pointer to the first occurrence of Value in the buffer.

  @note This function asserts if Buffer is NULL or if Length is too large.
**/
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

/**
  Allocates a buffer of a specified size from the pool.

  This function allocates a buffer of size AllocationSize from the pool. If the
  global shared dependencies or the AllocatePool function pointer within it is
  NULL, the function returns NULL.

  @param[in]  AllocationSize  The number of bytes to allocate.

  @retval  NULL    If gSharedDepends or gSharedDepends->AllocatePool is NULL.
  @retval  Others  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocatePool (
  IN UINTN  AllocationSize
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->AllocatePool == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->AllocatePool != NULL);
    return NULL;
  }

  return gSharedDepends->AllocatePool (AllocationSize);
}

/**
  Frees a pool of memory.

  This function checks if the global shared dependencies and its FreePool function
  pointer are not NULL. If both are valid, it calls the FreePool function to free
  the memory pool pointed to by Buffer.

  @param[in]  Buffer  Pointer to the memory pool to be freed.
**/
VOID
EFIAPI
FreePool (
  IN VOID  *Buffer
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->FreePool == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->FreePool != NULL);
    return;
  }

  gSharedDepends->FreePool (Buffer);
}

/**
  Retrieves the current time and date information, and the time-keeping capabilities of the hardware platform.

  @param[out] Time          A pointer to storage to receive a snapshot of the current time.
  @param[out] Capabilities  An optional pointer to a buffer to receive the real time clock device's capabilities.

  @retval EFI_SUCCESS       The operation completed successfully.
  @retval EFI_UNSUPPORTED   The operation is not supported.
**/
EFI_STATUS
EFIAPI
GetTime (
  OUT  EFI_TIME               *Time,
  OUT  EFI_TIME_CAPABILITIES  *Capabilities OPTIONAL
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->GetTime == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->GetTime != NULL);
    return EFI_UNSUPPORTED;
  }

  return gSharedDepends->GetTime (Time, Capabilities);
}

/**
  Generates a 64-bit random number.

  This function attempts to generate a 64-bit random number and store it in the
  location pointed to by Rand. If the shared dependency or the GetRandomNumber64
  function pointer is NULL, the function returns FALSE.

  @param[out] Rand  Pointer to the buffer to store the 64-bit random number.

  @retval TRUE   The 64-bit random number was generated successfully.
  @retval FALSE  The shared dependency or the GetRandomNumber64 function pointer
                 is NULL, and the random number could not be generated.
**/
BOOLEAN
EFIAPI
GetRandomNumber64 (
  OUT UINT64  *Rand
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->GetRandomNumber64 == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->GetRandomNumber64 != NULL);
    return FALSE;
  }

  return gSharedDepends->GetRandomNumber64 (Rand);
}

/**
  Copies a Null-terminated ASCII string, including the Null terminator, from a source
  string to a destination buffer with a maximum length.

  If gSharedDepends or gSharedDepends->AsciiStrCpyS is NULL, the function asserts and
  returns EFI_UNSUPPORTED.

  @param[out] Destination  Pointer to the destination buffer where the content is to be copied.
  @param[in]  DestMax      Maximum number of bytes that can be written to the Destination buffer,
                           including the Null terminator.
  @param[in]  Source       Pointer to the Null-terminated ASCII string to be copied.

  @retval EFI_SUCCESS           The string was copied successfully.
  @retval EFI_UNSUPPORTED       gSharedDepends or gSharedDepends->AsciiStrCpyS is NULL.
**/
EFI_STATUS
EFIAPI
AsciiStrCpyS (
  OUT CHAR8        *Destination,
  IN  UINTN        DestMax,
  IN  CONST CHAR8  *Source
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->AsciiStrCpyS == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->AsciiStrCpyS != NULL);
    return EFI_UNSUPPORTED;
  }

  return gSharedDepends->AsciiStrCpyS (Destination, DestMax, Source);
}

/**
  Returns the size of a Null-terminated ASCII string, including the Null terminator.

  This function calculates the size of the ASCII string specified by String,
  including the Null terminator. If the global shared dependency structure
  or its AsciiStrSize function pointer is NULL, the function asserts and
  returns 0.

  @param[in]  String  A pointer to a Null-terminated ASCII string.

  @retval 0           If gSharedDepends or gSharedDepends->AsciiStrSize is NULL.
  @retval Others      The size of the Null-terminated ASCII string, including
                      the Null terminator.
**/
UINTN
EFIAPI
AsciiStrSize (
  IN      CONST CHAR8  *String
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->AsciiStrSize == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->AsciiStrSize != NULL);
    return 0;
  }

  return gSharedDepends->AsciiStrSize (String);
}

/**
  Compares two Null-terminated ASCII strings and returns the difference
  between the first mismatched ASCII characters.

  If gSharedDepends or gSharedDepends->AsciiStrCmp is NULL, the function
  asserts and returns 0.

  @param[in]  FirstString   A pointer to a Null-terminated ASCII string.
  @param[in]  SecondString  A pointer to a Null-terminated ASCII string.

  @retval 0   If gSharedDepends or gSharedDepends->AsciiStrCmp is NULL.
  @retval     The difference between the first mismatched ASCII characters
              if gSharedDepends->AsciiStrCmp is not NULL.
**/
INTN
EFIAPI
AsciiStrCmp (
  IN      CONST CHAR8  *FirstString,
  IN      CONST CHAR8  *SecondString
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->AsciiStrCmp == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->AsciiStrCmp != NULL);
    return 0;
  }

  return gSharedDepends->AsciiStrCmp (FirstString, SecondString);
}

/**
  Returns the length of a Null-terminated ASCII string, up to a maximum number of characters.

  This function returns the number of characters in the Null-terminated ASCII string specified
  by String, not including the Null-terminator, but at most MaxSize. If the length of the string
  is greater than MaxSize, then MaxSize is returned. If String is NULL, then ASSERT() is triggered
  and 0 is returned.

  @param[in]  String   Pointer to a Null-terminated ASCII string.
  @param[in]  MaxSize  Maximum number of ASCII characters to return.

  @retval 0       If gSharedDepends or gSharedDepends->AsciiStrnLenS is NULL.
  @retval Others  The number of characters in the string or MaxSize, whichever is smaller.
**/
UINTN
EFIAPI
AsciiStrnLenS (
  IN CONST CHAR8  *String,
  IN UINTN        MaxSize
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->AsciiStrnLenS == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->AsciiStrnLenS != NULL);
    return 0;
  }

  return gSharedDepends->AsciiStrnLenS (String, MaxSize);
}

/**
  Compares two Null-terminated ASCII strings with a maximum length.

  @param[in]  FirstString   A pointer to the first Null-terminated ASCII string.
  @param[in]  SecondString  A pointer to the second Null-terminated ASCII string.
  @param[in]  Length        The maximum number of ASCII characters to compare.

  @retval 0   If gSharedDepends or gSharedDepends->AsciiStrnCmp is NULL.
  @retval     The return value of gSharedDepends->AsciiStrnCmp if it is not NULL.

  @note This function asserts if gSharedDepends or gSharedDepends->AsciiStrnCmp is NULL.
**/
INTN
EFIAPI
AsciiStrnCmp (
  IN      CONST CHAR8  *FirstString,
  IN      CONST CHAR8  *SecondString,
  IN      UINTN        Length
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->AsciiStrnCmp == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->AsciiStrnCmp != NULL);
    return 0;
  }

  return gSharedDepends->AsciiStrnCmp (FirstString, SecondString, Length);
}

/**
  Converts a Null-terminated ASCII decimal string to a UINTN value.

  This function assumes that the input string represents a valid decimal number.
  If the global shared dependency structure or the function pointer within it
  is NULL, the function asserts and returns 0.

  @param[in]  String  A pointer to a Null-terminated ASCII string that represents
                      a decimal number.

  @retval     The UINTN value that corresponds to the decimal number in the input string.
              If the shared dependency structure or the function pointer is NULL, returns 0.
**/
UINTN
EFIAPI
AsciiStrDecimalToUintn (
  IN      CONST CHAR8  *String
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->AsciiStrDecimalToUintn == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->AsciiStrDecimalToUintn != NULL);
    return 0;
  }

  return gSharedDepends->AsciiStrDecimalToUintn (String);
}

/**
  Copies a specified length of a source ASCII string to a destination ASCII string.

  This function copies up to Length characters from the Source string to the
  Destination string, ensuring that the Destination string is null-terminated
  if the Length is less than DestMax. If the global shared dependency
  gSharedDepends or its AsciiStrnCpyS function pointer is NULL, the function
  returns EFI_UNSUPPORTED.

  @param[out] Destination  Pointer to the destination buffer where the content
                           is to be copied.
  @param[in]  DestMax      Maximum number of characters that Destination can hold.
  @param[in]  Source       Pointer to the source null-terminated ASCII string.
  @param[in]  Length       Number of characters to copy from Source to Destination.

  @retval EFI_SUCCESS           The string was copied successfully.
  @retval EFI_UNSUPPORTED       The shared dependency or its function pointer is NULL.
**/
EFI_STATUS
EFIAPI
AsciiStrnCpyS (
  OUT CHAR8        *Destination,
  IN  UINTN        DestMax,
  IN  CONST CHAR8  *Source,
  IN  UINTN        Length
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->AsciiStrnCpyS == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->AsciiStrnCpyS != NULL);
    return EFI_UNSUPPORTED;
  }

  return gSharedDepends->AsciiStrnCpyS (Destination, DestMax, Source, Length);
}

/**
  Compares two Null-terminated ASCII strings in a case-insensitive manner.

  This function compares the Null-terminated ASCII string FirstString to the
  Null-terminated ASCII string SecondString in a case-insensitive manner.
  If gSharedDepends or gSharedDepends->AsciiStriCmp is NULL, the function
  asserts and returns 0.

  @param[in]  FirstString   A pointer to a Null-terminated ASCII string.
  @param[in]  SecondString  A pointer to a Null-terminated ASCII string.

  @retval 0   If gSharedDepends or gSharedDepends->AsciiStriCmp is NULL.
  @retval     The return value of gSharedDepends->AsciiStriCmp (FirstString, SecondString).
**/
INTN
EFIAPI
AsciiStriCmp (
  IN      CONST CHAR8  *FirstString,
  IN      CONST CHAR8  *SecondString
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->AsciiStriCmp == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->AsciiStriCmp != NULL);
    return 0;
  }

  return gSharedDepends->AsciiStriCmp (FirstString, SecondString);
}

/**
  Concatenates a Null-terminated ASCII string to another Null-terminated ASCII string.

  This function appends the Null-terminated ASCII string specified by Source to the end of the
  Null-terminated ASCII string specified by Destination, and returns Destination. The function
  checks if the global shared dependency gSharedDepends and its member function AsciiStrCatS
  are not NULL before calling the member function. If either is NULL, the function asserts and
  returns EFI_UNSUPPORTED.

  @param[in, out] Destination  A pointer to a Null-terminated ASCII string.
  @param[in]      DestMax      The maximum number of Destination buffer.
  @param[in]      Source       A pointer to a Null-terminated ASCII string.

  @retval EFI_SUCCESS          The strings were concatenated successfully.
  @retval EFI_UNSUPPORTED      The shared dependency or its member function is NULL.
**/
EFI_STATUS
EFIAPI
AsciiStrCatS (
  IN OUT CHAR8        *Destination,
  IN     UINTN        DestMax,
  IN     CONST CHAR8  *Source
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->AsciiStrCatS == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->AsciiStrCatS != NULL);
    return EFI_UNSUPPORTED;
  }

  return gSharedDepends->AsciiStrCatS (Destination, DestMax, Source);
}

/**
  Prints a formatted ASCII string to a buffer.

  This function formats a string using a format string and variable argument list,
  and writes the result to the specified buffer. It relies on an external dependency
  to perform the actual formatting.

  @param[out] StartOfBuffer  A pointer to the buffer where the formatted string will be stored.
  @param[in]  BufferSize     The size of the buffer in bytes.
  @param[in]  FormatString   A null-terminated format string.
  @param[in]  ...            Additional arguments for the format string.

  @retval The number of characters printed to the buffer, excluding the null-terminator.
  @retval 0 if the external dependency is not available or if an error occurs.
**/
UINTN
EFIAPI
AsciiSPrint (
  OUT CHAR8        *StartOfBuffer,
  IN  UINTN        BufferSize,
  IN  CONST CHAR8  *FormatString,
  ...
  )
{
  VA_LIST  Marker;
  UINTN    Result;

  if ((gSharedDepends == NULL) || (gSharedDepends->AsciiSPrint == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->AsciiSPrint != NULL);
    return 0;
  }

  VA_START (Marker, FormatString);
  Result = gSharedDepends->AsciiSPrint (StartOfBuffer, BufferSize, FormatString, Marker);
  VA_END (Marker);

  return Result;
}

/**
  Returns the length of a Null-terminated ASCII string.

  This function determines the length of the Null-terminated ASCII string
  specified by String. If gSharedDepends or gSharedDepends->AsciiStrLen is NULL,
  the function asserts and returns 0.

  @param[in]  String  A pointer to a Null-terminated ASCII string.

  @retval 0           If gSharedDepends or gSharedDepends->AsciiStrLen is NULL.
  @retval Others      The length of the Null-terminated ASCII string.
**/
UINTN
EFIAPI
AsciiStrLen (
  IN      CONST CHAR8  *String
  )
{
  if ((gSharedDepends == NULL) || (gSharedDepends->AsciiStrLen == NULL)) {
    ASSERT (gSharedDepends != NULL);
    ASSERT (gSharedDepends->AsciiStrLen != NULL);
    return 0;
  }

  return gSharedDepends->AsciiStrLen (String);
}

/**
  Writes a 16-bit value to the specified buffer in an unaligned manner.

  This function writes the 16-bit value to the buffer in little-endian order,
  regardless of the alignment of the buffer.

  @param[out] Buffer  Pointer to the buffer where the 16-bit value will be written.
                      This buffer must be at least 2 bytes in size.
  @param[in]  Value   The 16-bit value to write to the buffer.

  @retval     The 16-bit value that was written to the buffer.

  @note       This function assumes that the buffer is not NULL. An assertion
              is used to enforce this precondition.
**/
UINT16
EFIAPI
WriteUnaligned16 (
  OUT UINT16  *Buffer,
  IN  UINT16  Value
  )
{
  ASSERT (Buffer != NULL);

  ((volatile UINT8 *)Buffer)[0] = (UINT8)Value;
  ((volatile UINT8 *)Buffer)[1] = (UINT8)(Value >> 8);

  return Value;
}

/**
  Writes a 32-bit value to an unaligned buffer.

  This function writes the 32-bit value specified by Value to the buffer
  specified by Buffer in an unaligned manner. The buffer is treated as an
  array of bytes, and the value is written byte by byte.

  @param[out]  Buffer  Pointer to the buffer where the 32-bit value will be written.
  @param[in]   Value   The 32-bit value to write to the buffer.

  @retval      Value   The 32-bit value that was written to the buffer.

  @note This function assumes that Buffer is not NULL. An assertion is used
        to enforce this assumption.
**/
UINT32
EFIAPI
WriteUnaligned32 (
  OUT UINT32  *Buffer,
  IN  UINT32  Value
  )
{
  ASSERT (Buffer != NULL);

  ((volatile UINT8 *)Buffer)[0] = (UINT8)Value;
  ((volatile UINT8 *)Buffer)[1] = (UINT8)(Value >> 8);
  ((volatile UINT8 *)Buffer)[2] = (UINT8)(Value >> 16);
  ((volatile UINT8 *)Buffer)[3] = (UINT8)(Value >> 24);

  return Value;
}
