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

VOID *
EFIAPI
AllocateRuntimePool (
  IN UINTN  AllocationSize
  )
{
  ASSERT (FALSE);
  return NULL;
}

VOID *
EFIAPI
AllocateReservedPool (
  IN UINTN  AllocationSize
  )
{
  ASSERT (FALSE);
  return NULL;
}

VOID *
EFIAPI
AllocateRuntimeZeroPool (
  IN UINTN  AllocationSize
  )
{
  ASSERT (FALSE);
  return NULL;
}

VOID *
EFIAPI
AllocateReservedZeroPool (
  IN UINTN  AllocationSize
  )
{
  ASSERT (FALSE);
  return NULL;
}

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

VOID
EFIAPI
FreeAlignedPages (
  IN VOID   *Buffer,
  IN UINTN  Pages
  )
{
  ASSERT (FALSE);
}

VOID *
EFIAPI
AllocatePages (
  IN UINTN  Pages
  )
{
  ASSERT (FALSE);
  return NULL;
}

VOID *
EFIAPI
AllocateRuntimePages (
  IN UINTN  Pages
  )
{
  ASSERT (FALSE);
  return NULL;
}

VOID *
EFIAPI
AllocateReservedPages (
  IN UINTN  Pages
  )
{
  ASSERT (FALSE);
  return NULL;
}

VOID
EFIAPI
FreePages (
  IN VOID   *Buffer,
  IN UINTN  Pages
  )
{
  ASSERT (FALSE);
}

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
