# OneCrypto RNG Security Model

This document describes the Random Number Generation (RNG) security model implemented across different UEFI execution phases, including the technic### Library Dependencies

```ini
# DXE Phase - Hybrid RNG approach
[Components.X64]
  CryptoBinPkg/Driver/OneCryptoLoaderDxe.inf {
    <LibraryClasses>
      # Use NULL RNG to prevent boot hangs
      RngLib|MdePkg/Library/BaseRngLibNull/BaseRngLibNull.inf
  }

# MM Phase - No RNG by default  
[Components.X64.MM_STANDALONE]
  CryptoBinPkg/Driver/OneCryptoLoaderMm.inf {
    <LibraryClasses>  
      # Always use NULL for MM phase
      RngLib|MdePkg/Library/BaseRngLibNull/BaseRngLibNull.inf
  }
```

**Critical**: Do NOT use `BaseRngLibTimerLib` as it causes boot hangs due to timer hardware access during library constructor execution.

## Testing Strategy

### Boot Validation Tests

1. **Boot Completion Test**
   - System must boot completely without hangs
   - OneCrypto driver loads successfully
   - No dependency on RNG protocol availability

2. **RNG Detection Test**
   - Monitor debug output for RNG protocol detection results
   - Verify lazy initialization occurs on first use
   - Confirm graceful degradation when RNG unavailable

3. **Crypto Operation Tests**
   - Test deterministic operations (hashing, signature verification)
   - Test entropy-dependent operations (key generation, OAEP)
   - Verify appropriate failure behavior when RNG unavailable

### Integration Tests

1. **Cross-phase crypto workflows**
2. **Error handling validation** 
3. **Security boundary enforcement**

## Implementation History

This solution was developed through systematic debugging of boot hanging issues:

1. **Initial Problem**: 47.5% crypto test failures due to BaseRngLibNull
2. **First Attempt**: Direct EFI_RNG_PROTOCOL usage with DEPEX - caused boot hangs
3. **Second Attempt**: Early RNG initialization in driver entry point - caused hangs
4. **Root Cause Discovery**: BaseRngLibTimerLib library constructors accessing timer hardware
5. **Final Solution**: BaseRngLibNull + lazy EFI_RNG_PROTOCOL detection

This hybrid approach provides the best balance of boot reliability and crypto functionality. the hybrid RNG approach used to solve boot hanging issues.

## Overview

The OneCrypto implementation uses a **hybrid RNG strategy** that combines:
1. **BaseRngLibNull** as the base library to prevent boot hangs
2. **Lazy EFI_RNG_PROTOCOL detection** for hardware entropy when available
3. **Graceful degradation** when hardware RNG is not available

This approach was developed to solve critical boot hanging issues while maintaining security when possible.

## Technical Problem Solved

### The Boot Hanging Issue

**Root Cause**: Using `BaseRngLibTimerLib` as the RNG library caused the system to hang during driver initialization, specifically during library constructor execution before the main entry point.

**Why It Happened**:
- `BaseRngLibTimerLib` attempts to access timer hardware during library constructor initialization
- Timer hardware access during early boot phases can cause system hangs on some platforms
- Library constructors run before the driver's entry point, making debugging difficult
- The hang occurred before any debug output could be generated

**Failed Approaches**:
1. **DEPEX-based RNG protocol dependency** - Caused boot hangs waiting for protocol
2. **Early RNG protocol location** - Caused hangs during `LocateProtocol` calls
3. **Timer-based RNG library** - Caused hangs during library constructor execution

**Working Solution**: Hybrid approach with BaseRngLibNull + Lazy EFI_RNG_PROTOCOL detection

## Phase-Specific RNG Implementation

### DXE Phase (OneCryptoLoaderDxe)

**Security Level: HYBRID - Lazy Hardware Entropy with Safe Fallback**

- **Base RNG Library**: BaseRngLibNull (prevents boot hangs)
- **Hardware RNG**: Lazy EFI_RNG_PROTOCOL detection on first use
- **Fallback**: Graceful failure when hardware RNG unavailable
- **Dependencies**: No DEPEX requirements (TRUE DEPEX for immediate loading)

**Technical Implementation:**
```c
// Lazy initialization - only locate protocol when needed
STATIC BOOLEAN mRngInitAttempted = FALSE;
STATIC EFI_RNG_PROTOCOL *mCachedRngProtocol = NULL;

BOOLEAN LazyPlatformGetRandomNumber64(OUT UINT64 *Rand) {
  if (!mRngInitAttempted) {
    gBS->LocateProtocol(&gEfiRngProtocolGuid, NULL, (VOID**)&mCachedRngProtocol);
    mRngInitAttempted = TRUE;
  }
  
  if (mCachedRngProtocol != NULL) {
    return (EFI_SUCCESS == mCachedRngProtocol->GetRNG(...));
  }
  
  return FALSE; // Graceful failure
}
```

**Security Guarantees:**
- Uses hardware entropy when available via EFI_RNG_PROTOCOL
- Fails safely rather than using weak entropy sources
- No boot hangs due to RNG initialization issues
- Crypto operations requiring randomness fail predictably when no hardware RNG available

**Boot Process:**
1. **Driver loads immediately** (TRUE DEPEX, no protocol dependencies)
2. **Library constructors complete safely** (BaseRngLibNull causes no hardware access)
3. **RNG protocol detection deferred** until first crypto operation needs randomness
4. **Hardware entropy used when available**, graceful failure when not

**Platform Requirements:**
- Platform should provide EFI_RNG_PROTOCOL for secure random operations
- If no EFI_RNG_PROTOCOL, crypto operations requiring randomness will fail safely
- No timer hardware dependencies that could cause boot hangs

### MM Phase (OneCryptoLoaderMm)

**Security Level: RESTRICTED - No Entropy by Default**

- **RNG Source**: BaseRngLibNull (returns FALSE)
- **Fallback**: None - RNG operations fail by design
- **Validation**: None - assumes no entropy available
- **Dependencies**: No RNG protocol dependencies

**Security Rationale:**
- MM phase has limited protocol access
- No EFI_RNG_PROTOCOL available in MM environment
- Intentionally fails entropy-dependent operations
- Prevents accidental use of weak entropy sources

**Recommended Usage:**
- Use MM crypto only for deterministic operations:
  - Cryptographic hashing (SHA-256, SHA-384, etc.)
  - Signature verification (RSA, ECDSA)
  - HMAC with pre-established keys
  - Symmetric decryption with known keys
- **Avoid in MM phase:**
  - Key generation
  - Random nonce generation
  - PKCS#1 OAEP padding (requires randomness)
  - Any operation requiring entropy

**Platform Customization:**
Platforms requiring MM phase entropy can override RngLib:

```ini
[Components.X64.MM_STANDALONE]
  CryptoBinPkg/Driver/OneCryptoLoaderMm.inf {
    <LibraryClasses>
      RngLib|YourPlatform/Library/MmRngLib/MmRngLib.inf
  }
```

## Security Best Practices

### For Platform Developers

1. **Always provide hardware RNG in DXE phase**
   - Implement EFI_RNG_PROTOCOL with true hardware entropy
   - Ensure RNG availability before OneCrypto drivers load
   - Test RNG implementation thoroughly

2. **Design crypto workflows appropriately**
   - Perform entropy-dependent operations in DXE phase
   - Use MM phase only for deterministic crypto operations
   - Generate keys/nonces in DXE, use them in MM if needed

3. **Validate RNG functionality**
   - Test that crypto operations requiring randomness work in DXE
   - Verify that inappropriate MM crypto operations fail safely
   - Monitor for unexpected RNG failures in production

### For Application Developers

1. **Phase-aware crypto design**
   - Check execution phase before crypto operations
   - Use DXE phase for key generation and random operations
   - Use MM phase only for verification and deterministic operations

2. **Error handling**
   - Handle RNG failures gracefully
   - Don't assume random number generation will always succeed
   - Implement appropriate fallback strategies at application level

3. **Security validation**
   - Verify crypto operations use proper entropy sources
   - Test failure paths when RNG is unavailable
   - Audit code for inappropriate entropy usage

## Common Pitfalls

### ❌ Incorrect Usage
```c
// DON'T: Assuming RNG works in all phases
Status = RandomBytes(Buffer, Size);
// This will fail in MM phase with BaseRngLibNull
```

### ✅ Correct Usage
```c
// DO: Check phase and handle appropriately
if (InDxePhase()) {
    Status = RandomBytes(Buffer, Size);  // Hardware RNG available
} else {
    // Use pre-generated values or fail safely
    return EFI_UNSUPPORTED;
}
```

## Implementation Notes

### OpenSSL Integration

The RNG implementation integrates with OpenSSL's DRBG (Deterministic Random Bit Generator):

1. **DXE Phase**: Hardware entropy seeds OpenSSL DRBG properly
2. **MM Phase**: No seeding occurs, DRBG operations fail
3. **Error Propagation**: OpenSSL errors propagate to calling code

### Library Dependencies

```ini
# DXE Phase - Hardware RNG required
[Components.X64]
  CryptoBinPkg/Driver/OneCryptoLoaderDxe.inf {
    <LibraryClasses>
      RngLib|MdePkg/Library/BaseRngLib/BaseRngLib.inf  # Hardware-backed
  }

# MM Phase - No RNG by default  
[Components.X64.MM_STANDALONE]
  CryptoBinPkg/Driver/OneCryptoLoaderMm.inf {
    <LibraryClasses>  
      RngLib|MdePkg/Library/BaseRngLibNull/BaseRngLibNull.inf  # Always fails
  }
```

## Troubleshooting Guide

### Boot Hanging Issues

**Symptom**: System hangs during OneCrypto driver loading
```
INFO - Loading driver 4F25834D-11D0-4A8F-9860-72B303B9F242
INFO - Loading driver at 0x0007C63C000 EntryPoint=0x0007C63D074 OneCryptoDxeLoader.efi
[System hangs here]
```

**Root Causes & Solutions**:

1. **Timer-based RNG Library Issue**
   - **Cause**: Using BaseRngLibTimerLib causes hardware access during library constructors
   - **Solution**: Use BaseRngLibNull + lazy EFI_RNG_PROTOCOL detection
   - **DSC Setting**: `RngLib|MdePkg/Library/BaseRngLibNull/BaseRngLibNull.inf`

2. **DEPEX Protocol Dependencies**
   - **Cause**: DEPEX waiting for gEfiRngProtocolGuid that never arrives
   - **Solution**: Use TRUE DEPEX with lazy protocol detection
   - **INF Setting**: `[Depex] TRUE`

3. **Early Protocol Location**
   - **Cause**: Trying to locate protocols during driver initialization
   - **Solution**: Defer protocol location until first use

**Diagnostic Steps**:
1. Check if ConOut message appears: `*** DXE ENTRY POINT REACHED ***`
2. If no ConOut message: Issue is in library constructors
3. If ConOut appears but no debug: Issue is in driver code
4. Check RngLib implementation in build report

### RNG Functionality Testing

**Test Hardware RNG Availability**:
```c
// This will show in debug output on first RNG use:
// INFO - LazyPlatformGetRandomNumber64: First call, locating EFI_RNG_PROTOCOL
// INFO - LazyPlatformGetRandomNumber64: EFI_RNG_PROTOCOL located at [address]
// OR
// WARN - LazyPlatformGetRandomNumber64: EFI_RNG_PROTOCOL not available, Status=[status]
```

**Expected Behavior**:
- **With hardware RNG**: Crypto operations requiring randomness work
- **Without hardware RNG**: Operations fail gracefully with clear error messages
- **No hangs**: System boots regardless of RNG availability

This security model ensures that cryptographic operations maintain high security standards while clearly documenting the limitations and appropriate usage patterns for each UEFI execution phase.
