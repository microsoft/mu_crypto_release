/** @file
  RNG Library implementation for OneCrypto.

  This library provides random number generation wrappers that call into OneCrypto's
  dependency structure. It implements RngLib by using OneCrypto's GetRandomNumber64
  function pointer.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Uefi.h>
#include <Base.h>
#include <Library/RngLib.h>
#include <Library/BaseLib.h>
#include <Library/OneCryptoCrtLib.h>

/**
  Generates a 16-bit random number.

  if Rand is NULL, return FALSE.

  @param[out] Rand     Buffer pointer to store the 16-bit random value.

  @retval TRUE         Random number generated successfully.
  @retval FALSE        Failed to generate the random number.

**/
BOOLEAN
EFIAPI
GetRandomNumber16 (
  OUT     UINT16  *Rand
  )
{
  UINT64  Rand64;

  if (Rand == NULL) {
    return FALSE;
  }

  if (!GetRandomNumber64 (&Rand64)) {
    return FALSE;
  }

  *Rand = (UINT16)(Rand64 & 0xFFFF);
  return TRUE;
}

/**
  Generates a 32-bit random number.

  if Rand is NULL, return FALSE.

  @param[out] Rand     Buffer pointer to store the 32-bit random value.

  @retval TRUE         Random number generated successfully.
  @retval FALSE        Failed to generate the random number.

**/
BOOLEAN
EFIAPI
GetRandomNumber32 (
  OUT     UINT32  *Rand
  )
{
  UINT64  Rand64;

  if (Rand == NULL) {
    return FALSE;
  }

  if (!GetRandomNumber64 (&Rand64)) {
    return FALSE;
  }

  *Rand = (UINT32)(Rand64 & 0xFFFFFFFF);
  return TRUE;
}

/**
  Generates a 64-bit random number.

  if Rand is NULL, return FALSE.

  @param[out] Rand     Buffer pointer to store the 64-bit random value.

  @retval TRUE         Random number generated successfully.
  @retval FALSE        Failed to generate the random number.

**/
BOOLEAN
EFIAPI
GetRandomNumber64 (
  OUT     UINT64  *Rand
  )
{
  if (Rand == NULL) {
    return FALSE;
  }

  return OneCryptoGetRandomNumber64 (Rand);
}

/**
  Generates a 128-bit random number.

  if Rand is NULL, return FALSE.

  @param[out] Rand     Buffer pointer to store the 128-bit random value.

  @retval TRUE         Random number generated successfully.
  @retval FALSE        Failed to generate the random number.

**/
BOOLEAN
EFIAPI
GetRandomNumber128 (
  OUT     UINT64  *Rand
  )
{
  if (Rand == NULL) {
    return FALSE;
  }

  if (!GetRandomNumber64 (&Rand[0])) {
    return FALSE;
  }

  if (!GetRandomNumber64 (&Rand[1])) {
    return FALSE;
  }

  return TRUE;
}

/**
  Get a GUID identifying the RNG algorithm implementation.

  @param [out] RngGuid  If success, contains the GUID identifying
                        the RNG algorithm implementation.

  @retval EFI_SUCCESS             Success.
  @retval EFI_UNSUPPORTED         Not supported.
  @retval EFI_INVALID_PARAMETER   Invalid parameter.
**/
EFI_STATUS
EFIAPI
GetRngGuid (
  GUID  *RngGuid
  )
{
  return EFI_UNSUPPORTED;
}
