/** @file
  Timer Library implementation for OneCrypto.

  This library provides TimerLib implementation for OneCrypto that calls into
  OneCryptoCrtLib's MicroSecondDelay function pointer.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Base.h>
#include <Library/TimerLib.h>
#include <Library/OneCryptoCrtLib.h>

/**
  Stalls the CPU for at least the given number of microseconds.

  @param[in]  MicroSeconds  The minimum number of microseconds to delay.

  @return     The value of MicroSeconds input.

**/
UINTN
EFIAPI
MicroSecondDelay (
  IN      UINTN  MicroSeconds
  )
{
  return OneCryptoMicroSecondDelay (MicroSeconds);
}

/**
  Stalls the CPU for at least the given number of nanoseconds.

  This is a stub implementation that returns immediately.

  @param[in]  NanoSeconds   The minimum number of nanoseconds to delay.

  @return     The value of NanoSeconds input.

**/
UINTN
EFIAPI
NanoSecondDelay (
  IN      UINTN  NanoSeconds
  )
{
  return NanoSeconds;
}

/**
  Retrieves the current value of a 64-bit free running performance counter.

  This is a stub implementation that returns 0.

  @return     The current value of the free running performance counter.

**/
UINT64
EFIAPI
GetPerformanceCounter (
  VOID
  )
{
  return 0;
}

/**
  Retrieves the 64-bit frequency in Hz and the range of performance counter
  values.

  This is a stub implementation.

  @param[out]  StartValue  The value the performance counter starts with when
                           it rolls over.
  @param[out]  EndValue    The value that the performance counter ends with
                           before it rolls over.

  @return     The frequency in Hz.

**/
UINT64
EFIAPI
GetPerformanceCounterProperties (
  OUT      UINT64  *StartValue   OPTIONAL,
  OUT      UINT64  *EndValue     OPTIONAL
  )
{
  if (StartValue != NULL) {
    *StartValue = 0;
  }

  if (EndValue != NULL) {
    *EndValue = 0;
  }

  return 0;
}

/**
  Converts elapsed ticks of performance counter to time in nanoseconds.

  This is a stub implementation that returns 0.

  @param[in]  Ticks     The number of elapsed ticks of the performance counter.

  @return     The elapsed time in nanoseconds.

**/
UINT64
EFIAPI
GetTimeInNanoSecond (
  IN      UINT64  Ticks
  )
{
  return 0;
}
