# OneCrypto Platform Integration Guide

This guide describes how to integrate OneCrypto into your platform's DSC and FDF files.

## Required Components

Platforms using OneCrypto must include the following components:

### 1. **OneCryptoMmBin** - Phase Independent Binary (REQUIRED)
   - **Path**: `$(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoMmBin.inf`
   - **Phase**: MM/SMM (StandaloneMm or Traditional SMM)
   - **Critical**: This binary MUST be located in the same firmware volume as the StandaloneMm environment
   - Incorrect placement will cause the binary to not be found on first boot

### 2. **OneCryptoDxeLoader** - DXE Loader Driver
   - **Path**: `$(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoDxeLoader.inf`
   - **Phase**: DXE
   - **Purpose**: Loads and initializes the shared cryptographic library for DXE phase
   - Provides cryptographic services to DXE components

### 3. **OneCryptoLoaderMm** - MM Loader Driver
   - **Path**: `$(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoLoaderMm.inf`
   - **Phase**: MM/SMM (StandaloneMm)
   - **Purpose**: Loads and initializes the shared cryptographic library for MM phase
   - Provides cryptographic services to MM components

## Platform DSC Integration

Add the following to your platform's `.dsc` file in the `[Components.X64]` section:

```dsc
[Components.X64]
  #
  # OneCrypto Support - Shared Cryptographic Services
  #
  
  # Phase Independent Binary - Common precompiled component shared across phases
  $(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoMmBin.inf

  # DXE Phase Loader - Provides crypto services to DXE drivers
  $(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoDxeLoader.inf

  # MM Phase Loader - Provides crypto services to StandaloneMm drivers
  $(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoLoaderMm.inf
```

**Note**: The path variable `SHARED_SHARED_CRYPTO_PATH` should be defined in your platform's `[Defines]` section, for example:
```dsc
[Defines]
  SHARED_SHARED_CRYPTO_PATH = MU_BASECORE/CryptoPkg/Binaries/edk2-onecrypto-driver-bin
```

## Platform FDF Integration

Add the following to your platform's `.fdf` file:

### In the DXEFV Firmware Volume:

```fdf
[FV.DXEFV]
  # ... other DXE components ...

  #
  # OneCrypto DXE Support
  # This loader provides cryptographic services to DXE phase drivers
  #
  INF $(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoDxeLoader.inf
```

### In the StandaloneMm Firmware Volume:

```fdf
[FV.DXEFV]  # or your MM firmware volume
  # ... other MM components ...

  #
  # OneCrypto MM Support
  #
  # CRITICAL: The phase-independent binary MUST be in the same FV as the StandaloneMm environment
  # Incorrect placement will cause boot failure as the binary won't be found on first boot
  #
  INF $(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoMmBin.inf

  #
  # MM Phase Loader - Provides cryptographic services to StandaloneMm drivers
  #
  INF $(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoLoaderMm.inf
```

## Example: QemuQ35 Platform Integration

Here's how the QemuQ35 platform integrates OneCrypto:

### QemuQ35Pkg.dsc:
```dsc
[Defines]
  SHARED_SHARED_CRYPTO_PATH = MU_BASECORE/CryptoPkg/Binaries/edk2-onecrypto-driver-bin

[Components.X64]
  # OneCrypto Support - Shared Cryptographic Services
  $(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoMmBin.inf
  $(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoDxeLoader.inf
  $(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoLoaderMm.inf
```

### QemuQ35Pkg.fdf:
```fdf
[FV.DXEFV]
  # ... other components ...

  # OneCrypto DXE Loader
  INF $(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoDxeLoader.inf

  # OneCrypto MM Support (phase-independent binary + loader)
  # CRITICAL: These must be in the same FV as StandaloneMm
  INF $(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoMmBin.inf
  INF $(SHARED_SHARED_CRYPTO_PATH)/bin/shared/OneCryptoLoaderMm.inf
```

## Architecture Notes

1. **Phase-Independent Binary**: `OneCryptoMmBin.inf` contains the actual cryptographic implementation that is shared across phases to reduce firmware size and improve security by having a single implementation.

2. **Loaders**: The `OneCryptoDxeLoader` and `OneCryptoLoaderMm` drivers locate and initialize the phase-independent binary and expose cryptographic protocols/services to their respective phases.

3. **Placement Requirements**: The phase-independent binary MUST be in the same firmware volume as it will be accessed from. For MM/SMM, this typically means the same FV that contains your StandaloneMm core and drivers.

## Troubleshooting

**Problem**: "OneCrypto binary not found" error on first boot  
**Solution**: Ensure `OneCryptoMmBin.inf` is in the same firmware volume as your StandaloneMm environment

**Problem**: Missing cryptographic protocols in DXE  
**Solution**: Verify `OneCryptoDxeLoader.inf` is included in the DXE firmware volume and built in Components.X64

**Problem**: Missing cryptographic protocols in MM  
**Solution**: Verify both `OneCryptoMmBin.inf` and `OneCryptoLoaderMm.inf` are included in the MM firmware volume and built in Components.X64
