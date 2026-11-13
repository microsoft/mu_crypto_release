# Project Mu Crypto Release

[![Continuous Integration](https://github.com/microsoft/mu_crypto_release/actions/workflows/continuous-integration.yml/badge.svg?branch=main)](https://github.com/microsoft/mu_crypto_release/actions/workflows/continuous-integration.yml)
[![Build OneCryptoPkg](https://github.com/microsoft/mu_crypto_release/actions/workflows/build-onecrypto.yml/badge.svg?branch=main)](https://github.com/microsoft/mu_crypto_release/actions/workflows/build-onecrypto.yml)
[![Host-Based Unit Tests](https://github.com/microsoft/mu_crypto_release/actions/workflows/host-based-test-runner.yml/badge.svg?branch=main)](https://github.com/microsoft/mu_crypto_release/actions/workflows/host-based-test-runner.yml)
[![CodeQL](https://github.com/microsoft/mu_crypto_release/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/microsoft/mu_crypto_release/actions/workflows/codeql.yml)
[![Coverage](https://github.com/microsoft/mu_crypto_release/actions/workflows/coverage.yml/badge.svg?branch=main)](https://github.com/microsoft/mu_crypto_release/actions/workflows/coverage.yml)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-4.1.0-blue)](https://github.com/openssl/openssl/releases/tag/openssl-4.1.0)
[![Mbed TLS](https://img.shields.io/badge/Mbed_TLS-3.6.5-blue)](https://github.com/Mbed-TLS/mbedtls/releases/tag/v3.6.5)

This repository hosts the cryptographic library packages for [Project Mu](https://microsoft.github.io/mu/).
It decomposes the monolithic [CryptoPkg](https://github.com/tianocore/edk2/tree/master/CryptoPkg) into
independent, backend-specific packages so that each crypto implementation can be built, tested, and
maintained separately.

## Repository Structure

| Package            | Description                                                                              |
|--------------------|------------------------------------------------------------------------------------------|
| **OneCryptoPkg**   | Unified cross-phase crypto driver that dispatches the crypto provider.     |
| **OpensslPkg**     | BaseCryptLib, OpensslLib, TlsLib, and supporting headers backed by OpenSSL.              |
| **MbedTlsPkg**     | BaseCryptLib, MbedTlsLib, and supporting headers backed by Mbed TLS.                     |

## Crypto-operation capability reporting

Use `GetCryptoOpCapability()` from `Library/BaseCryptLib.h` to query the
algorithms a provider supports for an operation. Pass one of the operation GUIDs
from `Guid/CryptoOpId.h`:

| Operation | Reported algorithms |
|---|---|
| `gCryptoOpCmsVerifyGuid` | Provider signature OIDs for PKCS#7/CMS verification |
| `gCryptoOpCmsContentDigestGuid` | Provider fixed-output content-digest OIDs |
| `gCryptoOpAuthenticodeVerifyGuid` | Provider signature OIDs for Authenticode verification |
| `gCryptoOpAuthenticodeHashGuid` | Available SHA-1/256/384/512 image-hash digest OIDs |

On success, iterate the returned `BASE_CRYPT_OP_CAPABILITY` array using
`CapabilityCount`. Each entry's `AlgorithmOid` is a NUL-terminated ASCII
dotted-decimal object identifier (OID); `AlgorithmOidSize` includes the NUL.
The array is unordered. Free it once with `FreePool()`; do not modify or
separately free its strings.

An empty supported set returns `EFI_SUCCESS` with a NULL array and zero count.
`EFI_NOT_FOUND` means the provider does not implement the requested operation.
`EFI_UNSUPPORTED` means capability reporting is unavailable. Errors clear both
outputs.

Reporting is implemented by the full OpenSSL BaseCryptLib and exposed through
OneCrypto protocol **1.1**. Reduced OpenSSL and MbedTLS instances do not support
reporting. Consumers using older OneCrypto binaries must handle `EFI_UNSUPPORTED`.

Reported algorithms do not establish certificate trust, authorize an algorithm,
or guarantee that a particular signature/digest combination will verify.
Querying capabilities does not enable algorithms or change verification policy.

## CI Setup

```bash
# One-time setup
git submodule update --init --recursive
pip install -r pip-requirements.txt

# Packages: (OpensslPkg or MbedTlsPkg)
stuart_setup    -c .pytool/CISettings.py -p <Pkg>
stuart_ci_setup -c .pytool/CISettings.py -p <Pkg> # Only required for CI
stuart_update   -c .pytool/CISettings.py -p <Pkg>
```

## CI Building

```bash
# CI Targets: (DEBUG, RELEASE, NO-TARGET)
stuart_ci_build -c .pytool/CISettings.py -p <Pkg> -t DEBUG TOOL_CHAIN_TAG=CLANGPDB
stuart_ci_build -c .pytool/CISettings.py -p <Pkg> -t RELEASE TOOL_CHAIN_TAG=CLANGPDB
```

## Host-Based Unit Tests

```bash
# Run host-based unit tests locally with GCC

# Packages: (OpensslPkg, MbedTlsPkg)
stuart_ci_build -c .pytool/CISettings.py -p <Pkg> -t NOOPT -d HostUnitTestCompilerPlugin=run TOOL_CHAIN_TAG=GCC
```

> **Note:** MbedTlsPkg host-based tests are currently disabled due to known test
> failures. See the TODO in `host-based-test-runner.yml` for details.

## OneCryptoPkg

> For more details, see [OneCryptoPkg/Docs/README.md](OneCryptoPkg/Docs/README.md).

OneCryptoPkg uses `OneCryptoPkg/DriverBuild.py` (via `stuart_build`) instead of the CI
settings file. By default, it builds **both** DEBUG and RELEASE targets for
`X64` and `AARCH64`.

### Setup

```bash

# Clone GetDependencies() repos (MU_BASECORE, MM_SUPV, mu_plus)
stuart_ci_setup -c OneCryptoPkg/DriverBuild.py

# Sync git submodules listed in .gitmodules (openssl, mbedtls)
stuart_setup  -c OneCryptoPkg/DriverBuild.py

# Fetch ext_deps (NuGet, web, etc.)
stuart_update -c OneCryptoPkg/DriverBuild.py
```

### Build

```bash
# Build all targets and architectures
stuart_build -c OneCryptoPkg/DriverBuild.py TOOL_CHAIN_TAG=CLANGPDB

# Build only X64 RELEASE
stuart_build -c OneCryptoPkg/DriverBuild.py -a X64 -t RELEASE TOOL_CHAIN_TAG=CLANGPDB

# Build only AARCH64 DEBUG
stuart_build -c OneCryptoPkg/DriverBuild.py -a AARCH64 -t DEBUG TOOL_CHAIN_TAG=CLANGPDB
```

### Build Variants

Two variants are available:

- **Accelerated** (default) — uses NASM assembly optimizations in OpenSSL.
- **Non-accelerated** — pure C, no assembly. Built with the `BLD_*_NON_ACCEL=TRUE` flag.

```bash
# Non-accelerated build
stuart_build -c OneCryptoPkg/DriverBuild.py BLD_*_NON_ACCEL=TRUE TOOL_CHAIN_TAG=CLANGPDB
```

### Packaging

After a successful build the OneCryptoBundler plugin automatically produces
`Build/OneCryptoPkg/OneCrypto-Drivers.zip`. To skip packaging, pass
`--skip-packaging`:

```bash
stuart_build -c OneCryptoPkg/DriverBuild.py --skip-packaging TOOL_CHAIN_TAG=CLANGPDB
```

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines.

## License

This project is licensed under the BSD-2-Clause-Patent license. See the
[License.txt](MU_BASECORE/License.txt) file for details.
