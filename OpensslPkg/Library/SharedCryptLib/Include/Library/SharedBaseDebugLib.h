#ifndef SHARED_DEBUG_LIB
#define SHARED_DEBUG_LIB

#include <Library/SharedCrtLibSupport.h>

extern SHARED_DEPENDENCIES *gSharedDepends;

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

#endif // SHARED_DEBUG_LIB