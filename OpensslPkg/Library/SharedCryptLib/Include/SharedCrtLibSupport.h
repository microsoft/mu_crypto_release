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

#define ASSERT(Expression) \
  do { \
    if (gSharedDepends != NULL && gSharedDepends->ASSERT != NULL) { \
      gSharedDepends->ASSERT(Expression); \
    } else { \
      while (!(Expression)) { \
        /* Spin loop */ \
      } \
    } \
  } while (0)

// TODO might make more sense to move this to a separate file
#define DEBUG_ERROR    0x80000000
#define DEBUG_WARN     0x40000000
#define DEBUG_INFO     0x20000000
#define DEBUG_VERBOSE  0x10000000

/**
  Macro to print debug messages.

  This macro checks if the global shared dependencies and the DebugPrint function
  pointer within it are not NULL. If both are valid, it calls the DebugPrint function
  with the provided arguments.

  @param[in] Args  The arguments to pass to the DebugPrint function.

  @note This macro does nothing if gSharedDepends or gSharedDepends->DebugPrint is NULL.

  @since 1.0.0
  @ingroup External
**/
#define DEBUG(Args)                                                   \
  do                                                                  \
  {                                                                   \
    if (gSharedDepends != NULL && gSharedDepends->DebugPrint != NULL) \
    {                                                                 \
      gSharedDepends->DebugPrint Args;                                \
    }                                                                 \
  } while (0)

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
