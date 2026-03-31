/** @file
  Memory Allocation Library implementation for OneCrypto.

  This library provides memory allocation wrappers that call into OneCrypto's
  dependency structure for functions used by OpensslLib. Unused functions assert.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/OneCryptoCrtLib.h>
#include <Private/OneCryptoDependencySupport.h>

/**
  Allocates a buffer of type EfiBootServicesData.

  @param[in]  AllocationSize  The number of bytes to allocate.

  @retval NULL    Allocation failed or OneCrypto dependencies not initialized.
  @retval Other   Pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocatePool (
  IN UINTN  AllocationSize
  )
{
  return OneCryptoAllocatePool (AllocationSize);
}

/**
  Allocates and zeros a buffer of type EfiBootServicesData.

  @param[in]  AllocationSize  The number of bytes to allocate and zero.

  @retval NULL    Allocation failed.
  @retval Other   Pointer to the allocated and zeroed buffer.
**/
VOID *
EFIAPI
AllocateZeroPool (
  IN UINTN  AllocationSize
  )
{
  return OneCryptoAllocateZeroPool (AllocationSize);
}

/**
  Frees a buffer that was previously allocated.

  @param[in]  Buffer  Pointer to the buffer to free. If NULL, this function has no effect.
**/
VOID
EFIAPI
FreePool (
  IN VOID  *Buffer
  )
{
  OneCryptoFreePool(Buffer);
}

//
// Stub functions that are not used by Crypto providers today
//

/**
  Allocates a buffer of type EfiRuntimeServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiRuntimeServicesData and returns
  a pointer to the allocated buffer. If AllocationSize is 0, then a valid buffer of 0 size is
  returned. If there is not enough memory remaining to satisfy the request, then NULL is returned.

  @param[in]  AllocationSize  The number of bytes to allocate.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocateRuntimePool (
  IN UINTN  AllocationSize
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Allocates a buffer of type EfiReservedMemoryType.

  Allocates the number bytes specified by AllocationSize of type EfiReservedMemoryType and returns
  a pointer to the allocated buffer. If AllocationSize is 0, then a valid buffer of 0 size is
  returned. If there is not enough memory remaining to satisfy the request, then NULL is returned.

  @param[in]  AllocationSize  The number of bytes to allocate.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocateReservedPool (
  IN UINTN  AllocationSize
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Allocates and zeros a buffer of type EfiRuntimeServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiRuntimeServicesData, clears the
  buffer with zeros, and returns a pointer to the allocated buffer. If AllocationSize is 0, then a
  valid buffer of 0 size is returned. If there is not enough memory remaining to satisfy the
  request, then NULL is returned.

  @param[in]  AllocationSize  The number of bytes to allocate and zero.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocateRuntimeZeroPool (
  IN UINTN  AllocationSize
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Allocates and zeros a buffer of type EfiReservedMemoryType.

  Allocates the number bytes specified by AllocationSize of type EfiReservedMemoryType, clears the
  buffer with zeros, and returns a pointer to the allocated buffer. If AllocationSize is 0, then a
  valid buffer of 0 size is returned. If there is not enough memory remaining to satisfy the
  request, then NULL is returned.

  @param[in]  AllocationSize  The number of bytes to allocate and zero.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocateReservedZeroPool (
  IN UINTN  AllocationSize
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Copies a buffer to an allocated buffer of type EfiBootServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiBootServicesData, copies
  AllocationSize bytes from Buffer to the newly allocated buffer, and returns a pointer to the
  allocated buffer. If AllocationSize is 0, then a valid buffer of 0 size is returned. If there
  is not enough memory remaining to satisfy the request, then NULL is returned.

  If Buffer is NULL, then ASSERT().
  If AllocationSize is greater than (MAX_ADDRESS - Buffer + 1), then ASSERT().

  @param[in]  AllocationSize  The number of bytes to allocate and zero.
  @param[in]  Buffer          The buffer to copy to the allocated buffer.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocateCopyPool (
  IN UINTN       AllocationSize,
  IN CONST VOID  *Buffer
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Copies a buffer to an allocated buffer of type EfiRuntimeServicesData.

  Allocates the number bytes specified by AllocationSize of type EfiRuntimeServicesData, copies
  AllocationSize bytes from Buffer to the newly allocated buffer, and returns a pointer to the
  allocated buffer. If AllocationSize is 0, then a valid buffer of 0 size is returned. If there
  is not enough memory remaining to satisfy the request, then NULL is returned.

  If Buffer is NULL, then ASSERT().
  If AllocationSize is greater than (MAX_ADDRESS - Buffer + 1), then ASSERT().

  @param[in]  AllocationSize  The number of bytes to allocate and zero.
  @param[in]  Buffer          The buffer to copy to the allocated buffer.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocateRuntimeCopyPool (
  IN UINTN       AllocationSize,
  IN CONST VOID  *Buffer
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Copies a buffer to an allocated buffer of type EfiReservedMemoryType.

  Allocates the number bytes specified by AllocationSize of type EfiReservedMemoryType, copies
  AllocationSize bytes from Buffer to the newly allocated buffer, and returns a pointer to the
  allocated buffer. If AllocationSize is 0, then a valid buffer of 0 size is returned. If there
  is not enough memory remaining to satisfy the request, then NULL is returned.

  If Buffer is NULL, then ASSERT().
  If AllocationSize is greater than (MAX_ADDRESS - Buffer + 1), then ASSERT().

  @param[in]  AllocationSize  The number of bytes to allocate and zero.
  @param[in]  Buffer          The buffer to copy to the allocated buffer.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocateReservedCopyPool (
  IN UINTN       AllocationSize,
  IN CONST VOID  *Buffer
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Reallocates a buffer of type EfiBootServicesData.

  Allocates and zeros the number bytes specified by NewSize from memory of type
  EfiBootServicesData. If OldBuffer is not NULL, then the smaller of OldSize and NewSize bytes are
  copied from OldBuffer to the newly allocated buffer, and OldBuffer is freed. A pointer to the
  newly allocated buffer is returned. If NewSize is 0, then a valid buffer of 0 size is returned.
  If there is not enough memory remaining to satisfy the request, then NULL is returned.

  If the allocation of the new buffer is successful and the smaller of NewSize and OldSize is
  greater than (MAX_ADDRESS - OldBuffer + 1), then ASSERT().

  @param[in]  OldSize    The size, in bytes, of OldBuffer.
  @param[in]  NewSize    The size, in bytes, of the buffer to reallocate.
  @param[in]  OldBuffer  The buffer to copy to the allocated buffer. This is an optional
                         parameter that may be NULL.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
ReallocatePool (
  IN UINTN  OldSize,
  IN UINTN  NewSize,
  IN VOID   *OldBuffer  OPTIONAL
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Reallocates a buffer of type EfiRuntimeServicesData.

  Allocates and zeros the number bytes specified by NewSize from memory of type
  EfiRuntimeServicesData. If OldBuffer is not NULL, then the smaller of OldSize and NewSize bytes
  are copied from OldBuffer to the newly allocated buffer, and OldBuffer is freed. A pointer to
  the newly allocated buffer is returned. If NewSize is 0, then a valid buffer of 0 size is
  returned. If there is not enough memory remaining to satisfy the request, then NULL is returned.

  If the allocation of the new buffer is successful and the smaller of NewSize and OldSize is
  greater than (MAX_ADDRESS - OldBuffer + 1), then ASSERT().

  @param[in]  OldSize    The size, in bytes, of OldBuffer.
  @param[in]  NewSize    The size, in bytes, of the buffer to reallocate.
  @param[in]  OldBuffer  The buffer to copy to the allocated buffer. This is an optional
                         parameter that may be NULL.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
ReallocateRuntimePool (
  IN UINTN  OldSize,
  IN UINTN  NewSize,
  IN VOID   *OldBuffer  OPTIONAL
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Reallocates a buffer of type EfiReservedMemoryType.

  Allocates and zeros the number bytes specified by NewSize from memory of type
  EfiReservedMemoryType. If OldBuffer is not NULL, then the smaller of OldSize and NewSize bytes
  are copied from OldBuffer to the newly allocated buffer, and OldBuffer is freed. A pointer to
  the newly allocated buffer is returned. If NewSize is 0, then a valid buffer of 0 size is
  returned. If there is not enough memory remaining to satisfy the request, then NULL is returned.

  If the allocation of the new buffer is successful and the smaller of NewSize and OldSize is
  greater than (MAX_ADDRESS - OldBuffer + 1), then ASSERT().

  @param[in]  OldSize    The size, in bytes, of OldBuffer.
  @param[in]  NewSize    The size, in bytes, of the buffer to reallocate.
  @param[in]  OldBuffer  The buffer to copy to the allocated buffer. This is an optional
                         parameter that may be NULL.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
ReallocateReservedPool (
  IN UINTN  OldSize,
  IN UINTN  NewSize,
  IN VOID   *OldBuffer  OPTIONAL
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Frees one or more 4KB pages that were previously allocated with one of the aligned page
  allocation functions in the Memory Allocation Library.

  Frees the number of 4KB pages specified by Pages from the buffer specified by Buffer. Buffer
  must have been allocated on a previous call to the aligned page allocation services of the
  Memory Allocation Library. If it is not possible to free allocated pages, then this function
  will perform no actions.

  If Buffer was not allocated with an aligned page allocation function in the Memory Allocation
  Library, then ASSERT().
  If Pages is zero, then ASSERT().

  @param[in]  Buffer  Pointer to the buffer of pages to free.
  @param[in]  Pages   The number of 4 KB pages to free.
**/
VOID
EFIAPI
FreeAlignedPages (
  IN VOID   *Buffer,
  IN UINTN  Pages
  )
{
  ASSERT (FALSE);
}

/**
  Allocates one or more 4KB pages of type EfiBootServicesData.

  Allocates the number of 4KB pages of type EfiBootServicesData and returns a pointer to the
  allocated buffer. The buffer returned is aligned on a 4KB boundary. If Pages is 0, then NULL
  is returned. If there is not enough memory remaining to satisfy the request, then NULL is
  returned.

  @param[in]  Pages  The number of 4 KB pages to allocate.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocatePages (
  IN UINTN  Pages
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Allocates one or more 4KB pages of type EfiRuntimeServicesData.

  Allocates the number of 4KB pages of type EfiRuntimeServicesData and returns a pointer to the
  allocated buffer. The buffer returned is aligned on a 4KB boundary. If Pages is 0, then NULL
  is returned. If there is not enough memory remaining to satisfy the request, then NULL is
  returned.

  @param[in]  Pages  The number of 4 KB pages to allocate.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocateRuntimePages (
  IN UINTN  Pages
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Allocates one or more 4KB pages of type EfiReservedMemoryType.

  Allocates the number of 4KB pages of type EfiReservedMemoryType and returns a pointer to the
  allocated buffer. The buffer returned is aligned on a 4KB boundary. If Pages is 0, then NULL
  is returned. If there is not enough memory remaining to satisfy the request, then NULL is
  returned.

  @param[in]  Pages  The number of 4 KB pages to allocate.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocateReservedPages (
  IN UINTN  Pages
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Frees one or more 4KB pages that were previously allocated with one of the page allocation
  functions in the Memory Allocation Library.

  Frees the number of 4KB pages specified by Pages from the buffer specified by Buffer. Buffer
  must have been allocated on a previous call to the page allocation services of the Memory
  Allocation Library. If it is not possible to free allocated pages, then this function will
  perform no actions.

  If Buffer was not allocated with a page allocation function in the Memory Allocation Library,
  then ASSERT().
  If Pages is zero, then ASSERT().

  @param[in]  Buffer  Pointer to the buffer of pages to free.
  @param[in]  Pages   The number of 4 KB pages to free.
**/
VOID
EFIAPI
FreePages (
  IN VOID   *Buffer,
  IN UINTN  Pages
  )
{
  ASSERT (FALSE);
}

/**
  Allocates one or more 4KB pages of type EfiBootServicesData at a specified alignment.

  Allocates the number of 4KB pages specified by Pages of type EfiBootServicesData with an
  alignment specified by Alignment. The allocated buffer is returned. If Pages is 0, then NULL is
  returned. If there is not enough memory at the specified alignment remaining to satisfy the
  request, then NULL is returned.

  If Alignment is not a power of two and Alignment is not zero, then ASSERT().
  If Pages plus EFI_SIZE_TO_PAGES (Alignment) overflows, then ASSERT().

  @param[in]  Pages      The number of 4 KB pages to allocate.
  @param[in]  Alignment  The requested alignment of the allocation. Must be a power of two.
                         If Alignment is zero, then byte alignment is used.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocateAlignedPages (
  IN UINTN  Pages,
  IN UINTN  Alignment
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Allocates one or more 4KB pages of type EfiRuntimeServicesData at a specified alignment.

  Allocates the number of 4KB pages specified by Pages of type EfiRuntimeServicesData with an
  alignment specified by Alignment. The allocated buffer is returned. If Pages is 0, then NULL is
  returned. If there is not enough memory at the specified alignment remaining to satisfy the
  request, then NULL is returned.

  If Alignment is not a power of two and Alignment is not zero, then ASSERT().
  If Pages plus EFI_SIZE_TO_PAGES (Alignment) overflows, then ASSERT().

  @param[in]  Pages      The number of 4 KB pages to allocate.
  @param[in]  Alignment  The requested alignment of the allocation. Must be a power of two.
                         If Alignment is zero, then byte alignment is used.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocateAlignedRuntimePages (
  IN UINTN  Pages,
  IN UINTN  Alignment
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Allocates one or more 4KB pages of type EfiReservedMemoryType at a specified alignment.

  Allocates the number of 4KB pages specified by Pages of type EfiReservedMemoryType with an
  alignment specified by Alignment. The allocated buffer is returned. If Pages is 0, then NULL is
  returned. If there is not enough memory at the specified alignment remaining to satisfy the
  request, then NULL is returned.

  If Alignment is not a power of two and Alignment is not zero, then ASSERT().
  If Pages plus EFI_SIZE_TO_PAGES (Alignment) overflows, then ASSERT().

  @param[in]  Pages      The number of 4 KB pages to allocate.
  @param[in]  Alignment  The requested alignment of the allocation. Must be a power of two.
                         If Alignment is zero, then byte alignment is used.

  @retval NULL   Allocation failed.
  @retval Other  A pointer to the allocated buffer.
**/
VOID *
EFIAPI
AllocateAlignedReservedPages (
  IN UINTN  Pages,
  IN UINTN  Alignment
  )
{
  ASSERT (FALSE);
  return NULL;
}
