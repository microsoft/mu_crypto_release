#ifndef SHARED_CRT_LIB_H
#define SHARED_CRT_LIB_H

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>

#include <Library/SharedCryptoDependencySupport.h>

VOID *
EFIAPI
AllocatePool (
  IN UINTN  AllocationSize
  );

VOID *
EFIAPI
AllocateZeroPool (
  IN UINTN  AllocationSize
  );

VOID
EFIAPI
FreePool (
  IN VOID  *Buffer
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


#endif // SHARED_CRT_LIB_H
