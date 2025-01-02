#ifndef SHARED_CRT_LIB_H
#define SHARED_CRT_LIB_H

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>

// Typedefs for UEFI functions
typedef VOID *(*ALLOCATE_POOL)(
  UINTN  AllocationSize
  );
typedef VOID (*FREE_POOL)(
  VOID  *Buffer
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

typedef
BOOLEAN
(EFIAPI *GET_RANDOM_NUMBER_64)(
  OUT UINT64  *Rand
  );

// Structure to hold function pointers
typedef struct  _SHARED_DEPENDENCIES {
  ALLOCATE_POOL                 AllocatePool;
  FREE_POOL                     FreePool;
  ASSERT_T                      ASSERT;
  GET_TIME                      GetTime;
  DEBUG_PRINT                   DebugPrint;
  GET_RANDOM_NUMBER_64          GetRandomNumber64;
} SHARED_DEPENDENCIES;

SHARED_DEPENDENCIES  *gSharedDepends;

///////////////////////////////////////////////////////////////////////////////
///
///////////////////////////////////////////////////////////////////////////////

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
