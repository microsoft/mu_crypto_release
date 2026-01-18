# Manual Update Guide for OneCrypto Protocol and Libraries

This guide documents how to manually update the OneCrypto protocol and library files after the removal of the automated generation script (`CreateCryptoProtocol.py`).

## Overview

Previously, `CreateCryptoProtocol.py` would parse `BaseCryptDefs.h` and automatically generate:
- Protocol definitions
- Library headers  
- Library implementation wrappers

These files are now maintained manually. When adding, modifying, or removing crypto functions, you must update multiple files by hand.

## Source of Truth

**`MU_BASECORE/CryptoPkg/Include/Library/BaseCryptDefs.h`**

This file contains the canonical definitions of all crypto functions, including:
- Function signatures
- Parameter documentation
- Version information (`@since` tags)
- Grouping information (`@ingroup` tags)
- Return value documentation

When making changes, start here first, then propagate changes to the generated files listed below.

## Files That Must Be Updated Manually

### 1. Protocol Definition
**File:** `OneCryptoPkg/Include/Protocol/OneCryptoProtocol.h`

**Purpose:** Defines the protocol structure with function pointers for all crypto operations.

**What to update:**
- Add/remove function pointer typedefs in the protocol structure
- Update version numbers (VERSION_MAJOR, VERSION_MINOR)
- Maintain the protocol GUID

**Example structure:**
```c
typedef struct {
  UINT32 Major;
  UINT32 Minor;
  
  // Function pointers
  HMAC_SHA256_NEW HmacSha256New;
  HMAC_SHA256_FREE HmacSha256Free;
  // ... more function pointers
} ONE_CRYPTO_PROTOCOL;
```

### 2. Library Headers (Function Declarations)

#### Main Library Header
**File:** `OneCryptoPkg/Include/Library/OneCryptoLib.h`

**Purpose:** Provides function declarations for the main crypto library interface.

**What to update:**
- Add/remove function declarations
- Keep function signatures in sync with BaseCryptDefs.h
- Update comments/documentation

#### Specialized Library Headers
**Files:**
- `OneCryptoPkg/Include/Library/HmacLib.h` - HMAC functions
- `OneCryptoPkg/Include/Library/TlsLib.h` - TLS functions

**Purpose:** Grouped function declarations for specialized crypto operations.

**What to update:**
- Add/remove function declarations within the appropriate group
- Maintain consistency with BaseCryptDefs.h

### 3. Library Implementation (Protocol Consumer)

**File:** `OneCryptoPkg/Library/BaseCryptLibOnProtocolPpi/OneCryptoLib.c`

**Purpose:** Implements library functions by calling through to the protocol.

**What to update:**
- Add/remove wrapper functions that call `CALL_CRYPTO_SERVICE` or `CALL_VOID_CRYPTO_SERVICE`
- Match function signatures exactly
- Handle return values and error cases

**Example wrapper function:**
```c
VOID *
EFIAPI
HmacSha256New (
  VOID
  )
{
  CALL_CRYPTO_SERVICE (HmacSha256New, (), NULL);
}
```

**For functions with return values:**
```c
BOOLEAN
EFIAPI
HmacSha256SetKey (
  VOID         *HmacContext,
  CONST UINT8  *Key,
  UINTN        KeySize
  )
{
  CALL_CRYPTO_SERVICE (HmacSha256SetKey, (HmacContext, Key, KeySize), FALSE);
}
```

**For void functions:**
```c
VOID
EFIAPI
HmacSha256Free (
  VOID  *HmacCtx
  )
{
  CALL_VOID_CRYPTO_SERVICE (HmacSha256Free, (HmacCtx));
}
```

## Update Workflow

When adding a new crypto function:

1. **Define in BaseCryptDefs.h**
   - Add complete function signature
   - Include full documentation (description, parameters, return values)
   - Add `@since` version tag (e.g., `@since 1.0`)
   - Add `@ingroup` tag for categorization (e.g., `@ingroup HMAC`)

2. **Update Protocol (OneCryptoProtocol.h)**
   - Add typedef for the function pointer
   - Add function pointer to the `ONE_CRYPTO_PROTOCOL` structure
   - Place in the appropriate section with related functions

3. **Update Library Header**
   - Add function declaration to `OneCryptoLib.h` (or specialized header if grouped)
   - Copy documentation from BaseCryptDefs.h
   - Ensure EFIAPI calling convention is specified

4. **Implement Wrapper (OneCryptoLib.c)**
   - Add wrapper function that calls through protocol
   - Use `CALL_CRYPTO_SERVICE` for functions with return values
   - Use `CALL_VOID_CRYPTO_SERVICE` for void functions
   - Pass all parameters through correctly
   - Provide appropriate error return value (FALSE, NULL, 0, etc.)

5. **Test**
   - Build OneCryptoPkg: `python SingleFlavorBuild.py OneCryptoPkg`
   - Verify all function signatures match
   - Test runtime behavior with the actual protocol implementation

## Version Management

Version numbers are defined in `OneCryptoProtocol.h`:

```c
#define VERSION_MAJOR     1ULL
#define VERSION_MINOR     0ULL
```

**Increment rules:**
- **MAJOR**: Breaking changes (function signature changes, removals)
- **MINOR**: New functions added (backward compatible)
- **REVISION**: Bug fixes, documentation updates (no interface changes)

Update `@since` tags in BaseCryptDefs.h when adding functions to reflect the version they were introduced.

## Common Mistakes to Avoid

1. **Mismatched signatures** - Function signature in library header must exactly match BaseCryptDefs.h
2. **Missing EFIAPI** - All functions must use EFIAPI calling convention
3. **Wrong macro** - Use `CALL_VOID_CRYPTO_SERVICE` for void functions, `CALL_CRYPTO_SERVICE` for others
4. **Incorrect error returns** - Ensure default error return values are appropriate for the function's return type
5. **Forgotten protocol pointer** - New functions must be added to the protocol structure
6. **Parameter order** - When passing parameters in the wrapper, maintain exact order from signature

## File Header Comments

All generated files have headers indicating they were originally auto-generated. When making manual changes, you may want to update these headers to reflect manual maintenance:

```c
// ------------------------------------------------------------------------------
// MANUALLY MAINTAINED
// LAST UPDATED: 2025-Nov-11
// VERSION: 1.0
// ------------------------------------------------------------------------------
```

## Backup Information

The original generation script and templates have been backed up to a separate branch for reference:
- Branch: `backup/codegen-scripts`
- Files preserved:
  - `OneCryptoPkg/OneCryptoBin/Scripts/CreateCryptoProtocol.py`
  - `OneCryptoPkg/OneCryptoBin/Scripts/Templates/*`