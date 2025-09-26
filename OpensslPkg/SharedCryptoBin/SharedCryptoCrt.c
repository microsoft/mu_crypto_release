/** @file
  C Run-Time Libraries (CRT) implementations
  These either call the shared implementations or implement the logic itself
  if the implementation is simple enough that the code may be throughly vetted
  to ensure safety.

  Copyright (c) Microsoft Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <CrtLibSupport.h>

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
  Allocates and zeros a buffer of a specified size from the pool.

  This function allocates a buffer of size AllocationSize from the pool and then
  zeros the entire allocated buffer. If the allocation fails, the function returns NULL.

  @param[in]  AllocationSize  The number of bytes to allocate and zero.

  @retval  NULL    If the allocation fails, or if AllocationSize is 0.
  @retval  Others  A pointer to the allocated and zeroed buffer.
**/
VOID *
EFIAPI
AllocateZeroPool (
  IN UINTN  AllocationSize
  )
{
  VOID  *Buffer;

  Buffer = AllocatePool (AllocationSize);
  if (Buffer != NULL) {
    ZeroMem (Buffer, AllocationSize);
  }

  return Buffer;
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
