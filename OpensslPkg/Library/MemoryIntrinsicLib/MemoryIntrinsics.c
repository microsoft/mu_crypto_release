/** @file
  Memory intrinsic functions for OpenSSL Library.
  
  This file provides memory intrinsic functions (like memset, memcpy) that are needed
  by OpenSSL but not provided by the standard UEFI environment when IntrinsicLib
  is disabled.

Copyright (c) 2025, Microsoft Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Base.h>
#include <Library/BaseMemoryLib.h>

typedef UINTN size_t;

/**
  Sets buffers to a specified character.
  
  This function is needed for OpenSSL's function pointer usage in mem_clr.c
  and other places where memset is referenced as a function symbol rather
  than a macro.

  @param  dest   Pointer to the buffer to set.
  @param  ch     Character to set each byte of the buffer to.
  @param  count  Number of bytes to set.
  
  @return Returns a pointer to dest.
**/
void *
memset (
  void    *dest,
  int     ch,
  size_t  count
  )
{
  return SetMem(dest, (UINTN)count, (UINT8)ch);
}

/**
  Copies bytes from source to destination.
  
  This function is needed for OpenSSL's function pointer usage and other places
  where memcpy is referenced as a function symbol rather than a macro.

  @param  dest    Pointer to the destination buffer.
  @param  source  Pointer to the source buffer.
  @param  count   Number of bytes to copy.
  
  @return Returns a pointer to dest.
**/
void *
memcpy (
  void        *dest,
  const void  *source,
  size_t      count
  )
{
  return CopyMem(dest, source, (UINTN)count);
}