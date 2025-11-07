# OneCrypto Architecture

This document explains the architectural design of the OneCrypto system, focusing on the relationship between the loader drivers and the OneCrypto binary.

> **⚠️ Platform Support Notice:**  
> This architecture is currently **X64 ONLY**. AArch64 platforms require a different model due to architectural differences in StandaloneMm and firmware volume handling. See [Platform and Architecture Considerations](#platform-and-architecture-considerations) for details.

## Overview

OneCrypto implements a **shared binary architecture** where a single cryptographic implementation (the OneCrypto binary) is loaded and used by multiple firmware phases (DXE and MM/SMM). This design reduces firmware size, improves maintainability, and ensures cryptographic consistency across boot phases.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        OneCrypto Architecture                       │
└─────────────────────────────────────────────────────────────────────┘

    ┌──────────────────────┐              ┌──────────────────────┐
    │    DXE Phase         │              │    MM/SMM Phase      │
    │                      │              │                      │
    │  ┌────────────────┐  │              │  ┌────────────────┐  │
    │  │ Consumer       │  │              │  │ Consumer       │  │
    │  │ Drivers        │  │              │  │ Drivers        │  │
    │  └────────┬───────┘  │              │  └────────┬───────┘  │
    │           │          │              │           │          │
    │           │ Locate   │              │           │ Locate   │
    │           │ Protocol │              │           │ Protocol │
    │           ▼          │              │           ▼          │
    │  ┌────────────────┐  │              │  ┌────────────────┐  │
    │  │ OneCryptoDxe   │  │              │  │ OneCryptoMm    │  │
    │  │ Protocol       │  │              │  │ Protocol       │  │
    │  └────────┬───────┘  │              │  └────────┬───────┘  │
    │           │          │              │           │          │
    │           │ Published│              │           │ Published│
    │           │ by       │              │           │ by       │
    │           ▼          │              │           ▼          │
    │  ┌────────────────┐  │              │  ┌────────────────┐  │
    │  │ OneCrypto      │  │              │  │ OneCrypto      │  │
    │  │ DxeLoader      │  │              │  │ LoaderMm       │  │
    │  └────────┬───────┘  │              │  └────────┬───────┘  │
    │           │          │              │           │          │
    └───────────┼──────────┘              └───────────┼──────────┘
                │                                     │
                │ Loads                               │ Loads
                │ & Inits                             │ & Inits
                ▼                                     ▼
        ┌───────────────────────────────────────────────────┐
        │                                                   │
        │          OneCrypto Binary (PE/COFF)               │
        │                                                   │
        │  ┌─────────────────────────────────────────────┐  │
        │  │  OpenSSL Cryptographic Implementation       │  │
        │  │  • SHA-256/384/512  • RSA                   │  │
        │  │  • HMAC             • Random                │  │
        │  │  • TLS              • X.509                 │  │
        │  └─────────────────────────────────────────────┘  │
        │                                                   │
        └───────────────────────────────────────────────────┘
                    Phase-Independent Binary
                  (Loaded at Runtime in Both Phases)
```

## Architecture Components

### 1. OneCrypto Binary (`OneCryptoBin`)

**Location:** `OpensslPkg/OneCryptoBin/`

The OneCrypto binary is a **phase-independent, position-independent** cryptographic library that contains:
- OpenSSL-based cryptographic implementations
- Hash functions (SHA-256, SHA-384, SHA-512, etc.)
- RSA operations
- HMAC functions
- Random number generation
- TLS support
- X.509 certificate handling

**Key Characteristics:**
- **Phase Independent:** Works in both DXE and MM environments
- **Position Independent:** Can be loaded at any memory address
- **Self-Contained:** Minimal external dependencies
- **Protocol-Based Interface:** Exposes functionality through a structured protocol

**Built From:**
- Source: `OpensslPkg/OneCryptoBin/OneCryptoBin.c`
- Dependencies Structure: `ONE_CRYPTO_DEPENDENCIES` (minimal BaseLib, DebugLib, etc.)
- OpenSSL library integration

### 2. Loader Drivers

The loader drivers are responsible for locating, loading, and initializing the OneCrypto binary, then publishing protocols that consumer drivers can use.

#### OneCryptoDxeLoader

**Location:** `CryptoBinPkg/Driver/OneCryptoLoaderDxe.c`  
**INF:** `CryptoBinPkg/Driver/OneCryptoLoaderDxe.inf`

**Responsibilities:**
1. **Locate Binary:** Searches firmware volumes for the OneCrypto binary
2. **Load Binary:** Loads the binary into memory at runtime
3. **Initialize:** Calls the binary's initialization function with DXE dependencies
4. **Publish Protocol:** Installs `gOneCryptoDxeProtocolGuid` on a handle

**Protocol Published:**
```c
extern EFI_GUID gOneCryptoDxeProtocolGuid;
// Protocol contains function pointers to all cryptographic operations
```

**Usage Phase:** DXE (Driver Execution Environment)

**Memory Management:**
- Allocates memory for the binary using DXE memory services
- Binary remains resident in memory throughout DXE phase

#### OneCryptoLoaderMm

**Location:** `CryptoBinPkg/Driver/OneCryptoLoaderMm.c`  
**INF:** `CryptoBinPkg/Driver/OneCryptoLoaderMm.inf`

**Responsibilities:**
1. **Locate Constructor Protocol:** Finds `gOneCryptoPrivateProtocolGuid` published by the StandaloneMm core
2. **Initialize Dependencies:** Creates and populates MM-specific dependencies structure
3. **Call Constructor:** Invokes the constructor function from the private protocol with MM dependencies
4. **Publish Protocol:** Installs `gOneCryptoMmProtocolGuid` on a handle for MM consumers

**Protocol Published:**
```c
extern EFI_GUID gOneCryptoMmProtocolGuid;
// Protocol contains function pointers to all cryptographic operations
```

**Usage Phase:** MM/SMM (Management Mode / System Management Mode)

**Memory Management:**
- Dependencies structure allocated in MMRAM
- Binary was already loaded by StandaloneMm core during FV processing
- Loader acts as a shim to initialize and publish the protocol

## Architectural Flow

### DXE Phase Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                      DXE Phase Boot Flow                            │
└─────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐
  │  DXE Core    │
  │   Starts     │
  └──────┬───────┘
         │
         ▼
  ┌──────────────────────┐
  │ OneCryptoDxeLoader   │ ◄──── Dispatched by DXE Core
  │ Entry Point          │
  └──────┬───────────────┘
         │
         ├─────► [1] Search Firmware Volumes for OneCryptoBin
         │                    │
         │                    ▼
         │              ┌────────────────┐
         │              │ Find PE/COFF   │
         │              │ Binary in FV   │
         │              └────────┬───────┘
         │                       │
         ├─────► [2] Allocate DXE Memory
         │                    │
         │                    ▼
         │              ┌────────────────┐
         │              │ Allocate Pool  │
         │              │ for Binary     │
         │              └────────┬───────┘
         │                       │
         ├─────► [3] Load PE/COFF Binary
         │                    │
         │                    ▼
         │              ┌────────────────┐
         │              │ Parse Headers  │
         │              │ Load Sections  │
         │              │ Apply Relocs   │
         │              └────────┬───────┘
         │                       │
         ├─────► [4] Initialize Binary with Dependencies
         │                    │
         │                    ▼
         │       ┌──────────────────────────┐
         │       │ ONE_CRYPTO_DEPENDENCIES  │
         │       │  • AllocatePool          │
         │       │  • FreePool              │
         │       │  • DebugPrint            │
         │       │  • ... (DXE Services)    │
         │       └────────┬─────────────────┘
         │                │
         │                │ Call Entry Point
         │                ▼
         │       ┌─────────────────────┐
         │       │  OneCryptoBin       │
         │       │  Initialization     │
         │       └────────┬────────────┘
         │                │
         │                │ Returns Protocol
         │                ▼
         │       ┌─────────────────────┐
         │       │ ONE_CRYPTO_PROTOCOL │
         │       │ Function Pointers   │
         │       └────────┬────────────┘
         │                │
         ├─────► [5] Publish Protocol
         │                │
         │                ▼
         │       ┌──────────────────────────┐
         │       │ InstallProtocolInterface │
         │       │ gOneCryptoDxeProtocolGuid│
         │       └────────┬─────────────────┘
         │                │
         └────────────────┘
                          │
                          ▼
                ┌──────────────────┐
                │  Protocol Ready  │
                │  for Consumers   │
                └──────────────────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
         ▼                ▼                ▼
  ┌──────────┐    ┌──────────┐    ┌──────────┐
  │Consumer  │    │Consumer  │    │Consumer  │
  │Driver 1  │    │Driver 2  │    │Driver 3  │
  └──────────┘    └──────────┘    └──────────┘
       │                │                │
       └────────────────┴────────────────┘
                        │
                        ▼
          LocateProtocol(gOneCryptoDxeProtocolGuid)
                        │
                        ▼
              Call Crypto Functions
              (Sha256, RsaVerify, etc.)
```

### MM/SMM Phase Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    MM/SMM Phase Boot Flow                           │
└─────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐
  │   MM Core    │
  │   Starts     │
  └──────┬───────┘
         │
         ├─────► Loads OneCryptoBin from FV
         │       (Part of StandaloneMm FV processing)
         │                    │
         │                    ▼
         │       ┌─────────────────────────┐
         │       │ OneCryptoBin loaded     │
         │       │ into MMRAM              │
         │       │                         │
         │       │ Publishes:              │
         │       │ gOneCryptoPrivate       │
         │       │   ProtocolGuid          │
         │       └────────┬────────────────┘
         │                │
         ▼                ▼
  ┌──────────────────────┐
  │ OneCryptoLoaderMm    │ ◄──── Dispatched by MM Core
  │ Entry Point          │
  └──────┬───────────────┘
         │
         ├─────► [1] Locate Constructor Protocol
         │                    │
         │                    ▼
         │       ┌──────────────────────────┐
         │       │ MmLocateProtocol(        │
         │       │   gOneCryptoPrivate      │
         │       │   ProtocolGuid)          │
         │       └────────┬─────────────────┘
         │                │
         │                │ Returns Constructor
         │                ▼
         │       ┌──────────────────────────┐
         │       │ ONE_CRYPTO_MM_           │
         │       │ CONSTRUCTOR_PROTOCOL     │
         │       │  • Signature             │
         │       │  • Constructor()         │
         │       └────────┬─────────────────┘
         │                │
         ├─────► [2] Allocate & Populate Dependencies
         │                    │
         │                    ▼
         │       ┌──────────────────────────┐
         │       │ ONE_CRYPTO_DEPENDENCIES  │
         │       │  • AllocatePool (MMRAM)  │
         │       │  • FreePool              │
         │       │  • DebugPrint            │
         │       │  • GetRandomNumber64     │
         │       │  • ... (MM Services)     │
         │       └────────┬─────────────────┘
         │                │
         ├─────► [3] Call Constructor with MM Dependencies
         │                    │
         │                    ▼
         │       ┌──────────────────────────┐
         │       │ ConstructorProtocol->    │
         │       │   Constructor(           │
         │       │     Dependencies,        │
         │       │     &OneCryptoProtocol)  │
         │       └────────┬─────────────────┘
         │                │
         │                │ Returns Protocol
         │                ▼
         │       ┌─────────────────────┐
         │       │ ONE_CRYPTO_PROTOCOL │
         │       │ Function Pointers   │
         │       └────────┬────────────┘
         │                │
         ├─────► [4] Publish Public Protocol
         │                │
         │                ▼
         │       ┌─────────────────────────┐
         │       │ MmInstallProtocol       │
         │       │   Interface(            │
         │       │   gOneCryptoMm          │
         │       │   ProtocolGuid)         │
         │       └────────┬────────────────┘
         │                │
         └────────────────┘
                          │
                          ▼
                ┌──────────────────┐
                │  Protocol Ready  │
                │  for Consumers   │
                │  (in MMRAM)      │
                └──────────────────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
         ▼                ▼                ▼
  ┌──────────┐    ┌──────────┐    ┌──────────┐
  │MM Driver │    │MM Driver │    │MM Driver │
  │    1     │    │    2     │    │    3     │
  └──────────┘    └──────────┘    └──────────┘
       │                │                │
       └────────────────┴────────────────┘
                        │
                        ▼
          MmLocateProtocol(gOneCryptoMmProtocolGuid)
                        │
                        ▼
              Call Crypto Functions
              (Secure Boot, TPM, etc.)

Key Difference from DXE:
  • MM Core loads OneCryptoBin as part of FV processing
  • OneCryptoBin publishes gOneCryptoPrivateProtocolGuid
  • OneCryptoLoaderMm acts as shim/wrapper
  • Loader locates private protocol, not binary
  • Loader calls constructor, then publishes public protocol
```

## Binary Loading Mechanism

### PE/COFF Format

The OneCrypto binary is built as a PE/COFF (Portable Executable/Common Object File Format) image, which allows:
- **Relocation:** Can be loaded at any memory address
- **Standard Format:** Uses UEFI-standard executable format
- **Section Management:** Code, data, and relocation sections

### Loading Process

The loaders use a custom PE/COFF loader (`PeCoffLib.c`) to:

1. **Parse Headers:** Read PE/COFF headers to determine size and sections
2. **Allocate Memory:** Allocate appropriate memory (DXE memory or MMRAM)
3. **Load Sections:** Copy code and data sections to allocated memory
4. **Apply Relocations:** Fix up addresses based on load address
5. **Set Permissions:** Mark code as executable, data as read/write
6. **Call Entry Point:** Invoke the binary's entry point function

**Key Function:**
```c
EFI_STATUS
LoadPeCoffImage (
  IN  VOID   *ImageBuffer,
  OUT VOID   **LoadedImage,
  OUT UINTN  *ImageSize
  );
```

## Dependency Injection

The OneCrypto binary has **minimal dependencies** that are injected at runtime by the loader drivers.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Dependency Injection Pattern                     │
└─────────────────────────────────────────────────────────────────────┘

    Loader Driver                    OneCrypto Binary
    ─────────────                    ────────────────

  ┌──────────────────┐
  │  Populate        │
  │  Dependencies    │
  │  Structure       │
  └────────┬─────────┘
           │
           │  ONE_CRYPTO_DEPENDENCIES
           │  ┌─────────────────────────┐
           │  │ Version                 │
           │  │ AllocatePool      ──────┼──► DXE: gBS->AllocatePool
           │  │                         │    MM:  gMmst->MmAllocatePool
           │  │ FreePool          ──────┼──► DXE: gBS->FreePool
           │  │                         │    MM:  gMmst->MmFreePool
           │  │ DebugPrint        ──────┼──► DebugLib function
           │  │ DebugAssert       ──────┼──► DebugLib function
           │  │ CopyMem, SetMem   ──────┼──► BaseMemoryLib functions
           │  └─────────────────────────┘
           │
           │  Call Entry Point
           ▼
  ┌─────────────────────┐          ┌──────────────────────┐
  │ Status = BinEntry(  │─────────►│ OneCryptoBinEntry(   │
  │   &Dependencies     │          │   Dependencies)      │
  │ );                  │          └──────────┬───────────┘
  └─────────┬───────────┘                     │
            │                                 │
            │                                 │ Initialize
            │                                 │ OpenSSL
            │                                 │
            │                                 ▼
            │                        ┌─────────────────┐
            │                        │ Store Deps      │
            │                        │ Pointer         │
            │                        │ Globally        │
            │                        └────────┬────────┘
            │                                 │
            │                                 │ Populate
            │                                 │ Protocol
            │                                 ▼
            │                        ┌─────────────────┐
            │  Returns Protocol      │ Create Protocol │
            │◄───────────────────────│ with Function   │
            │                        │ Pointers        │
            │                        └─────────────────┘
            │
            │  ONE_CRYPTO_PROTOCOL
            │  ┌──────────────────────┐
            │  │ Sha256Init      ─────┼──► Uses Dependencies.AllocatePool
            │  │ Sha256Update    ─────┼──► Calls OpenSSL internally
            │  │ RsaVerify       ─────┼──► Uses Dependencies.DebugPrint
            │  │ RandomBytes     ─────┼──► etc.
            │  │ ... (200+ funcs)     │
            │  └──────────────────────┘
            │
            ▼
  ┌──────────────────┐
  │ Install Protocol │
  │ Interface        │
  └──────────────────┘

Key Benefits:
  • Binary doesn't link against phase-specific libraries
  • Same binary code works in DXE and MM
  • Loader provides appropriate services for each phase
  • Clean separation of concerns
```

### ONE_CRYPTO_DEPENDENCIES Structure

```c
typedef struct {
  UINT64  Version;           // Protocol version
  
  // Memory Services
  VOID* (*AllocatePool)(UINTN Size);
  VOID  (*FreePool)(VOID *Buffer);
  VOID* (*AllocateZeroPool)(UINTN Size);
  VOID* (*CopyMem)(VOID *Dest, CONST VOID *Src, UINTN Length);
  VOID* (*SetMem)(VOID *Buffer, UINTN Size, UINT8 Value);
  
  // Debug Services
  VOID  (*DebugPrint)(UINTN ErrorLevel, CONST CHAR8 *Format, ...);
  VOID  (*DebugAssert)(CONST CHAR8 *File, UINTN Line, CONST CHAR8 *Desc);
  
  // Other minimal services...
} ONE_CRYPTO_DEPENDENCIES;
```

**Initialization Flow:**
```c
// In Loader Driver:
ONE_CRYPTO_DEPENDENCIES Dependencies;
Dependencies.AllocatePool = MyAllocatePool;
Dependencies.FreePool = MyFreePool;
// ... populate other fields ...

// Call binary's entry point:
OneCryptoProtocol = OneCryptoBinEntry(&Dependencies);
```

This dependency injection allows the binary to:
- Use phase-appropriate memory services (DXE vs MM)
- Use phase-appropriate debug output
- Remain phase-independent in implementation

## Protocol Interface

### Protocol Structure

Both DXE and MM protocols expose the same interface (different GUIDs, same structure):

```c
typedef struct {
  // Version information
  UINT64  Version;
  
  // Hash Functions
  BOOLEAN (*Sha256Init)(VOID *Context);
  BOOLEAN (*Sha256Update)(VOID *Context, CONST VOID *Data, UINTN DataSize);
  BOOLEAN (*Sha256Final)(VOID *Context, UINT8 *HashValue);
  // ... more hash functions ...
  
  // RSA Functions
  BOOLEAN (*RsaPkcs1Verify)(VOID *RsaContext, CONST UINT8 *Message, ...);
  // ... more RSA functions ...
  
  // HMAC Functions
  BOOLEAN (*HmacSha256Init)(VOID *Context, CONST UINT8 *Key, UINTN KeySize);
  // ... more HMAC functions ...
  
  // Random Number Generation
  BOOLEAN (*RandomSeed)(CONST UINT8 *Seed, UINTN SeedSize);
  BOOLEAN (*RandomBytes)(UINT8 *Output, UINTN Size);
  
  // TLS Functions
  // ... TLS support functions ...
  
  // 200+ cryptographic functions total
} ONE_CRYPTO_PROTOCOL;
```

### Consumer Usage

Consumer drivers use the protocol like this:

```c
EFI_STATUS Status;
ONE_CRYPTO_PROTOCOL *Crypto;

// Locate the protocol
Status = gBS->LocateProtocol(
  &gOneCryptoDxeProtocolGuid,
  NULL,
  (VOID **)&Crypto
);

if (!EFI_ERROR(Status)) {
  // Use cryptographic functions
  UINT8 Hash[32];
  VOID *Sha256Ctx = AllocatePool(Crypto->Sha256GetContextSize());
  
  Crypto->Sha256Init(Sha256Ctx);
  Crypto->Sha256Update(Sha256Ctx, Data, DataSize);
  Crypto->Sha256Final(Sha256Ctx, Hash);
  
  FreePool(Sha256Ctx);
}
```

## Benefits of This Architecture

### 1. **Reduced Firmware Size**
- Single cryptographic implementation shared across phases
- No duplication of OpenSSL code in multiple drivers
- Typical savings: 500KB - 1MB per firmware image

### 2. **Improved Security**
- Single implementation to audit and maintain
- Centralized cryptographic updates
- Consistent behavior across all phases

### 3. **Simplified Maintenance**
- Update OpenSSL version in one place
- Add new crypto functions in one location
- Easier to apply security patches

### 4. **Phase Independence**
- Same binary works in DXE and MM/SMM
- No need to maintain separate implementations
- Consistent cryptographic behavior

### 5. **Protocol-Based Design**
- Clean interface separation
- Easy to mock for testing
- Supports multiple implementations

## Platform Integration

### Required Components

Platforms must include three components:

1. **OneCryptoBin** - The phase-independent binary (REQUIRED)
2. **OneCryptoDxeLoader** - DXE loader driver
3. **OneCryptoLoaderMm** - MM loader driver

### Firmware Volume Placement

**Critical Rule:** The OneCryptoBin binary must be in the **same firmware volume** as the environment that will use it.

```
┌─────────────────────────────────────────────────────────────────────┐
│                   Firmware Volume Layout                            │
└─────────────────────────────────────────────────────────────────────┘

 FLASH IMAGE
 ───────────

  ┌────────────────────────────────────────────────────────────┐
  │                        FV.DXEFV                            │
  │  ┌──────────────────────────────────────────────────────┐  │
  │  │  DXE Core                                            │  │
  │  ├──────────────────────────────────────────────────────┤  │
  │  │  OneCryptoDxeLoader.efi         ◄─── Loader Driver   │  │
  │  ├──────────────────────────────────────────────────────┤  │
  │  │  OneCryptoBin.efi (optional)    ◄─── Binary          │  │
  │  ├──────────────────────────────────────────────────────┤  │
  │  │  Other DXE Drivers                                   │  │
  │  │  • NetworkPkg drivers (use crypto)                   │  │
  │  │  • SecureBoot drivers (use crypto)                   │  │
  │  └──────────────────────────────────────────────────────┘  │
  └────────────────────────────────────────────────────────────┘
                             │
                             │ OneCryptoDxeLoader searches
                             │ for binary in accessible FVs
                             ▼
  ┌────────────────────────────────────────────────────────────┐
  │                       FV.MMFV (SMM)                        │
  │  ┌──────────────────────────────────────────────────────┐  │
  │  │  MM Core / StandaloneMm Core                         │  │
  │  ├──────────────────────────────────────────────────────┤  │
  │  │  OneCryptoBin.efi               ◄─── Binary (MUST!)  │  │◄─┐
  │  ├──────────────────────────────────────────────────────┤  │  │
  │  │  OneCryptoLoaderMm.efi          ◄─── Loader Driver   │  │  │
  │  ├──────────────────────────────────────────────────────┤  │  │
  │  │  Other MM Drivers                                    │  │  │
  │  │  • Variable services (use crypto)                    │  │  │
  │  │  • TPM drivers (use crypto)                          │  │  │
  │  │  • FTW drivers (use crypto)                          │  │  │
  │  └──────────────────────────────────────────────────────┘  │  │
  └────────────────────────────────────────────────────────────┘  │
                                                                  │
      CRITICAL: Binary MUST be in same FV as MM environment ──────┘
                (StandaloneMm core loads all drivers from its FV
                 during initialization, including OneCryptoBin)

Memory Layout After Loading:
─────────────────────────────

  DXE Memory Space                    MMRAM Space
  ────────────────                    ───────────

  ┌──────────────────┐                ┌──────────────────┐
  │ OneCryptoBin     │                │ OneCryptoBin     │
  │ (Loaded by       │                │ (Loaded by       │
  │  DxeLoader)      │                │  MM Core)        │
  │ Code: 0x12340000 │                │ Code: 0xFED10000 │
  │ Data: 0x12380000 │                │ Data: 0xFED20000 │
  └──────────────────┘                └──────────────────┘
         │                                     │
         │ Protocol                            │ Private Protocol
         │ gOneCryptoDxe                       │ gOneCryptoPrivate
         │ ProtocolGuid                        │ ProtocolGuid
         │                                     │
         ▼                                     ▼
  ┌──────────────────┐                ┌──────────────────┐
  │ OneCryptoDxe     │                │ OneCryptoLoaderMm│
  │ Loader           │                │ (Shim)           │
  │ (loaded binary)  │                │                  │
  └────────┬─────────┘                └────────┬─────────┘
           │                                   │
           │ Published                         │ Published
           ▼                                   ▼
  gOneCryptoDxeProtocolGuid           gOneCryptoMmProtocolGuid
           │                                   │
           │ Used by                           │ Used by
           ▼                                   ▼
  ┌──────────────────┐                ┌──────────────────┐
  │ DXE Crypto       │                │ MM Crypto        │
  │ Consumers        │                │ Consumers        │
  └──────────────────┘                └──────────────────┘

  DXE: Loader actively loads binary and calls it
  MM:  Binary loaded by MM Core, Loader is just a shim
```

**DXE:**
- OneCryptoDxeLoader actively loads the binary from firmware volumes
- OneCryptoBin can be in any accessible DXE firmware volume
- Loader performs PE/COFF loading and initialization

**MM/SMM:**
- OneCryptoBin **must** be in the same FV as StandaloneMm core
- StandaloneMm core loads OneCryptoBin during FV processing
- OneCryptoLoaderMm is a shim that locates the private protocol
- Incorrect placement causes boot failure

### Example Platform Integration

See [Platform Integration Guide](PlatformIntegration.md) for detailed DSC/FDF examples.

## Troubleshooting

### Common Issues

**Issue:** "OneCrypto binary not found" error in DXE  
**Cause:** OneCryptoBin not in accessible firmware volume  
**Solution:** Ensure OneCryptoBin.inf is in a firmware volume accessible to DXE

**Issue:** "Failed to locate OneCrypto private protocol" error in MM  
**Cause:** OneCryptoBin not in same FV as StandaloneMm core, or not loaded before OneCryptoLoaderMm  
**Solution:** Ensure OneCryptoBin.inf is in the same firmware volume as StandaloneMm core

**Issue:** Protocol not found in consumer driver  
**Cause:** Loader driver not built or not loading  
**Solution:** 
- DXE: Verify OneCryptoDxeLoader is in DSC Components section and FDF
- MM: Verify both OneCryptoBin and OneCryptoLoaderMm are in MM firmware volume

**Issue:** MM loader signature validation fails  
**Cause:** OneCryptoBin published protocol with incorrect signature  
**Solution:** Rebuild OneCryptoBin and ensure version compatibility

**Issue:** Crash when calling crypto functions  
**Cause:** Dependencies structure not properly populated  
**Solution:** 
- DXE: Check that DxeLoader populated all dependency function pointers
- MM: Check that LazyMmGetRandomNumber64 can locate EFI_RNG_PROTOCOL

## Related Documentation

- [Platform Integration Guide](PlatformIntegration.md) - How to integrate into your platform
- [CreateCryptoProtocol Tool](CreateCryptoProtocol.md) - Generating protocol interfaces
- [RNG Security Model](RngSecurityModel.md) - Random number generation security
- [Driver README](../CryptoBinPkg/Driver/readme.md) - Loader driver implementation details

## Technical Details

### Build Process

1. **Build OneCryptoBin:**
   ```bash
   python SingleFlavorBuild.py OpensslPkg
   ```
   - Compiles OneCrypto binary from OpenSSL sources
   - Outputs PE/COFF image

2. **Build Loaders:**
   ```bash
   python SingleFlavorBuild.py CryptoBinPkg
   ```
   - Compiles OneCryptoDxeLoader and OneCryptoLoaderMm
   - Links against protocol headers

3. **Platform Build:**
   - Platform build system includes all three components
   - Places them in appropriate firmware volumes

### Version Management

The protocol includes version information:
```c
#define ONE_CRYPTO_VERSION_MAJOR     1ULL
#define ONE_CRYPTO_VERSION_MINOR     0ULL
#define ONE_CRYPTO_VERSION_REVISION  0ULL
```

Loaders can verify binary compatibility before using it.

## Platform and Architecture Considerations

### Current Implementation: X64 Only

**Important:** This OneCrypto shared binary architecture is currently **only supported on X64 platforms**. The design relies on specific characteristics of the x64 architecture and StandaloneMm implementation.

**X64-Specific Characteristics:**
- PE/COFF binary format with x64 relocations
- StandaloneMm core can load and execute position-independent code
- Firmware volumes can contain executable PE/COFF images
- MM environment on x64 supports protocol-based architecture

### AArch64 Considerations

**Different Model Required:** AArch64 platforms will likely need a different architecture due to:

1. **Firmware Volume Constraints:**
   - AArch64 StandaloneMm may have different FV processing model
   - Binary loading mechanisms may differ from x64

2. **Position Independence:**
   - AArch64 PIC (Position Independent Code) requirements differ from x64
   - Relocation formats are architecture-specific

3. **MM Environment Differences:**
   - AArch64 StandaloneMm implementation may have different initialization flow
   - Protocol publication mechanisms may vary

4. **Security Model:**
   - ARM TrustZone integration may require different approach
   - Memory isolation requirements differ from x64 SMM

**Potential AArch64 Approaches:**
- Static linking of crypto into each consumer driver (traditional approach)
- Library-based architecture instead of protocol-based
- Different binary loading mechanism specific to AArch64 StandaloneMm
- Platform-specific crypto service implementation

**Future Work:**
If AArch64 support is needed, the architecture should be re-evaluated to:
- Determine if shared binary approach is feasible on AArch64
- Design AArch64-specific loader mechanism if applicable
- Consider alternative approaches that achieve similar size/maintenance benefits
- Ensure compatibility with ARM-specific security features

### Supported Configurations

| Architecture | DXE Support | MM/SMM Support | Status |
|--------------|-------------|----------------|--------|
| X64          | ✅ Yes      | ✅ Yes         | Fully Supported |
| AArch64      | ❌ No       | ❌ No          | Not Supported - Different model needed |
| IA32         | ❌ No       | ❌ No          | Not Supported |

**Note:** Platforms attempting to use OneCrypto on non-x64 architectures will encounter build or runtime errors. Alternative cryptographic solutions should be used for AArch64 platforms.

## Summary

The OneCrypto architecture provides a robust, efficient way to deliver cryptographic services across firmware phases:

- **OneCrypto Binary:** Phase-independent cryptographic implementation
- **Loader Drivers:** Load binary and publish protocols
- **Protocol Interface:** Clean, standardized access to crypto functions
- **Dependency Injection:** Phase-appropriate services provided at runtime

This design achieves significant firmware size reduction while maintaining security and simplifying maintenance.

**Platform Support:** Currently X64 only. AArch64 platforms require different architecture.
