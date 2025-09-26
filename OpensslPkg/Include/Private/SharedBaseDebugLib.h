#ifndef SHARED_DEBUG_LIB
#define SHARED_DEBUG_LIB

#include <Private/SharedCrtLibSupport.h>

extern SHARED_DEPENDENCIES  *gSharedDepends;

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

/**
  Returns TRUE if DEBUG_CODE() macros are enabled.

  This function returns TRUE if the DEBUG_PROPERTY_DEBUG_CODE_ENABLED bit of
  PcdDebugProperyMask is set.  Otherwise FALSE is returned.

  @retval  TRUE    The DEBUG_PROPERTY_DEBUG_CODE_ENABLED bit of PcdDebugProperyMask is set.
  @retval  FALSE   The DEBUG_PROPERTY_DEBUG_CODE_ENABLED bit of PcdDebugProperyMask is clear.

**/
BOOLEAN
EFIAPI
DebugCodeEnabled (
  VOID
  );

/**
  Macro that marks the beginning of debug source code.

  If the DEBUG_PROPERTY_DEBUG_CODE_ENABLED bit of PcdDebugProperyMask is set,
  then this macro marks the beginning of source code that is included in a module.
  Otherwise, the source lines between DEBUG_CODE_BEGIN() and DEBUG_CODE_END()
  are not included in a module.

**/
#define DEBUG_CODE_BEGIN()  do { if (DebugCodeEnabled ()) { UINT8  __DebugCodeLocal

/**
  The macro that marks the end of debug source code.

  If the DEBUG_PROPERTY_DEBUG_CODE_ENABLED bit of PcdDebugProperyMask is set,
  then this macro marks the end of source code that is included in a module.
  Otherwise, the source lines between DEBUG_CODE_BEGIN() and DEBUG_CODE_END()
  are not included in a module.

**/
#define DEBUG_CODE_END()  __DebugCodeLocal = 0; __DebugCodeLocal++; } } while (FALSE)

#endif // SHARED_DEBUG_LIB
