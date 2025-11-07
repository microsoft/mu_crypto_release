# mu_crypto_release Documentation

Centralized documentation hub for the mu_crypto_release repository.

## Overview

This repository provides cryptographic functionality for UEFI firmware through a protocol-based architecture. The implementation supports both traditional and modern "OneCrypto" shared library approaches.

## Architecture Documentation

### [OneCrypto Architecture](Architecture.md)
Comprehensive explanation of the OneCrypto system architecture and design:
- Relationship between drivers and OneCrypto binary
- Binary loading mechanism and PE/COFF format
- Protocol interface and dependency injection
- DXE and MM/SMM phase flow
- Benefits and design rationale

### [Platform Integration Guide](PlatformIntegration.md)
Step-by-step guide for integrating OneCrypto into platforms:
- Required components and firmware volume placement
- DSC and FDF integration examples
- QemuQ35 platform example
- Troubleshooting common issues

## Package Documentation

### OneCryptoPkg
**Location:** `OneCryptoPkg/`

Provides minimal crypto libraries for standalone MM drivers with a streamlined dependency model.

**Key Resources:**
- [Package README](../OneCryptoPkg/README.md) - Package structure and library mappings
- [Integration Guide](PlatformIntegration.md) - Platform integration

### CryptoBinPkg
**Location:** `CryptoBinPkg/`

Contains the OneCrypto loader drivers that dynamically load cryptographic binaries.

**Key Resources:**
- [Driver README](../CryptoBinPkg/Driver/readme.md) - Loader architecture and implementation
- [RNG Security Model](RngSecurityModel.md) - Random number generation requirements

### OpensslPkg
**Location:** `OpensslPkg/`

OpenSSL-based cryptographic implementations and the OneCrypto binary builds.

## Developer Tools

### [CreateCryptoProtocol.py](CreateCryptoProtocol.md)
**Location:** `OneCryptoPkg/OneCryptoBin/Scripts/CreateCryptoProtocol.py`  
**Documentation:** [CreateCryptoProtocol.md](CreateCryptoProtocol.md)

Python script that automatically generates UEFI protocol headers and library implementations from crypto function definitions.

**Use Cases:**
- Regenerate protocol when crypto functions are added/modified
- Generate library headers organized by function groups
- Create protocol-based library implementations

**Quick Start:**
```bash
python OneCryptoPkg/OneCryptoBin/Scripts/CreateCryptoProtocol.py \
    OpensslPkg/Include/Private/OneCryptoLibrary.h -p -l
```

**Full Documentation:** See [CreateCryptoProtocol.md](CreateCryptoProtocol.md) for complete usage guide.

## Component Documentation

### Drivers

| Component | Description | Documentation |
|-----------|-------------|---------------|
| **OneCryptoLoaderDxe** | DXE driver that loads OneCrypto binary and publishes protocol | [Driver README](../CryptoBinPkg/Driver/readme.md) |
| **OneCryptoLoaderMm** | MM driver that loads OneCrypto binary for MM environment | [Driver README](../CryptoBinPkg/Driver/readme.md) |

### Libraries

| Library | Description | Package |
|---------|-------------|---------|
| **MinimalBaseLib** | Minimal BaseLib implementation for reduced dependencies | OneCryptoPkg |
| **MinimalBaseMemoryLib** | Minimal BaseMemoryLib for memory operations | OneCryptoPkg |
| **MinimalBasePrintLib** | Minimal BasePrintLib for formatted output | OneCryptoPkg |
| **BaseCryptLibOnProtocolPpi** | Protocol-based crypto library implementation | OneCryptoPkg |

### Protocols

| Protocol | GUID | Description |
|----------|------|-------------|
| **OneCryptoDxeProtocol** | `gOneCryptoDxeProtocolGuid` | DXE crypto protocol interface |
| **OneCryptoMmProtocol** | `gOneCryptoPrivateProtocolGuid` | MM crypto protocol interface |

## Build Instructions

### Build Individual Packages

```bash
# Build CryptoBinPkg (OneCrypto loaders)
python SingleFlavorBuild.py CryptoBinPkg

# Build OneCryptoPkg (Minimal libraries)
python SingleFlavorBuild.py OneCryptoPkg

# Build OpensslPkg (OpenSSL crypto binary)
python SingleFlavorBuild.py OpensslPkg
```

### Build All Packages

```bash
python MultiFlavorBuild.py
```

## Integration Guides

### For Platform Developers

1. **[Platform Integration Guide](PlatformIntegration.md)**
   - How to integrate OneCrypto into your platform
   - Required FDF and DSC changes
   - Library class mappings

### For Crypto Developers

1. **[CreateCryptoProtocol Guide](CreateCryptoProtocol.md)**
   - How to add new crypto functions
   - Regenerating protocol and library files
   - Function annotation requirements

## Security Considerations

### [RNG Security Model](RngSecurityModel.md)

Important security information about random number generation:
- Lazy RNG initialization to avoid boot hangs
- Platform RNG requirements
- MM environment considerations

## Directory Structure

```
mu_crypto_release/
├── Docs/                           # Centralized documentation (this directory)
│   ├── README.md                   # Documentation hub (you are here)
│   ├── Architecture.md            # OneCrypto architecture and design
│   ├── CreateCryptoProtocol.md    # CreateCryptoProtocol.py tool guide
│   ├── PlatformIntegration.md     # Platform integration guide
│   └── RngSecurityModel.md        # RNG security considerations
├── CryptoBinPkg/                   # OneCrypto loader drivers
│   └── Driver/
│       └── readme.md              # Driver architecture
├── OneCryptoPkg/                   # Minimal crypto libraries
│   ├── README.md                  # Package overview
│   └── Library/                   # Minimal library implementations
├── OpensslPkg/                     # OpenSSL crypto implementations
│   ├── OneCryptoBin/              # OneCrypto binary builds
│   └── Library/                   # BaseCryptLib implementations
└── Common/                         # Submodule dependencies
    ├── MU/                        # Project Mu components
    └── MU_TIANO/                  # TianoCore components
```

## Quick Links

### Primary Documentation
- 🏛️ [OneCrypto Architecture](Architecture.md) - Understand the system design
- 📖 [Platform Integration](PlatformIntegration.md) - Start here for platform integration
- 🔧 [Driver Architecture](../CryptoBinPkg/Driver/readme.md) - Understand the loader drivers
- 🐍 [CreateCryptoProtocol Script](CreateCryptoProtocol.md) - Tool for developers

### Package Information
- 📦 [OneCryptoPkg README](../OneCryptoPkg/README.md)
- 📦 [CryptoBinPkg Driver README](../CryptoBinPkg/Driver/readme.md)

### Security & Compliance
- 🔐 [RNG Security Model](RngSecurityModel.md)

## Contributing

When adding new features or modifying existing functionality:

1. **Update Documentation** - Keep relevant README files current
2. **Run Tests** - Build and verify all affected packages
3. **Update Protocol** - If adding crypto functions, regenerate using [CreateCryptoProtocol.py](CreateCryptoProtocol.md)
4. **Security Review** - Consider security implications, especially for RNG changes

## Support

For issues or questions:
- Check existing documentation in the links above
- Review [troubleshooting sections](CreateCryptoProtocol.md#troubleshooting) in relevant guides
- Examine build logs for errors

## Version Information

This repository follows semantic versioning for the crypto protocol:
- **Major** - Breaking changes to protocol structure
- **Minor** - New functions added (backward compatible)
- **Revision** - Bug fixes and non-breaking changes

Current version is defined in `OpensslPkg/Include/Private/OneCryptoLibrary.h`:
```c
#define VERSION_MAJOR     1ULL
#define VERSION_MINOR     0ULL
#define VERSION_REVISION  0ULL
```

## License

Copyright (c) Microsoft Corporation.  
SPDX-License-Identifier: BSD-2-Clause-Patent
