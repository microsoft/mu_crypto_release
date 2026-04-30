# Project Mu Crypto Release

[![Continuous Integration](https://github.com/Microsoft/mu_crypto_release/actions/workflows/continuous-integration.yml/badge.svg?branch=main)](https://github.com/microsoft/mu_crypto_release/actions/workflows/continuous-integration.yml)
[![Host-Based Unit Tests](https://github.com/microsoft/mu_crypto_release/actions/workflows/host-based-test-runner.yml/badge.svg?branch=main)](https://github.com/microsoft/mu_crypto_release/actions/workflows/host-based-test-runner.yml)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-3.5.5-blue)](https://github.com/openssl/openssl/releases/tag/openssl-3.5.5)
[![Mbed TLS](https://img.shields.io/badge/Mbed_TLS-3.6.5-blue)](https://github.com/Mbed-TLS/mbedtls/releases/tag/v3.6.5)

This repository hosts the cryptographic library packages for [Project Mu](https://microsoft.github.io/mu/).
It decomposes the monolithic [CryptoPkg](https://github.com/tianocore/edk2/tree/master/CryptoPkg) into
independent, backend-specific packages so that each crypto implementation can be built, tested, and
maintained separately.

## Repository Structure

| Package        | Description                                                                 |
|----------------|-----------------------------------------------------------------------------|
| **OpensslPkg** | BaseCryptLib, OpensslLib, TlsLib, and supporting headers backed by OpenSSL. |
| **MbedTlsPkg** | BaseCryptLib, MbedTlsLib, and supporting headers backed by Mbed TLS.        |

## Setup

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
# Run host-based unit tests locally with GCC5

# Packages: (OpensslPkg, MbedTlsPkg)
stuart_ci_build -c .pytool/CISettings.py -p <Pkg> -t NOOPT -d HostUnitTestCompilerPlugin=run TOOL_CHAIN_TAG=GCC5
```

> **Note:** MbedTlsPkg host-based tests are currently disabled due to known test
> failures. See the TODO in `host-based-test-runner.yml` for details.

<<<<<<< Updated upstream
||||||| Stash base
## OneCryptoPkg

> For more details, see [OneCryptoPkg/Docs/README.md](OneCryptoPkg/Docs/README.md).

OneCryptoPkg uses `PlatformBuild.py` (via `stuart_build`) instead of the CI
settings file. By default, it builds **both** DEBUG and RELEASE targets for
`X64` and `AARCH64`.

### Setup

```bash
stuart_setup  -c PlatformBuild.py
stuart_update -c PlatformBuild.py
```

### Build

```bash
# Build all targets and architectures
stuart_build -c PlatformBuild.py TOOL_CHAIN_TAG=CLANGPDB

# Build only X64 RELEASE
stuart_build -c PlatformBuild.py -a X64 -t RELEASE TOOL_CHAIN_TAG=CLANGPDB

# Build only AARCH64 DEBUG
stuart_build -c PlatformBuild.py -a AARCH64 -t DEBUG TOOL_CHAIN_TAG=CLANGPDB
```

### Build Variants

Two variants are available:

- **Accelerated** (default) — uses NASM assembly optimizations in OpenSSL.
- **Non-accelerated** — pure C, no assembly. Built with the `BLD_*_NON_ACCEL=TRUE` flag.

```bash
# Non-accelerated build
stuart_build -c PlatformBuild.py BLD_*_NON_ACCEL=TRUE TOOL_CHAIN_TAG=CLANGPDB
```

### Packaging

After a successful build the OneCryptoBundler plugin automatically produces
`Build/OneCryptoPkg/OneCrypto-Drivers.zip`. To skip packaging, pass
`--skip-packaging`:

```bash
stuart_build -c PlatformBuild.py --skip-packaging TOOL_CHAIN_TAG=CLANGPDB
```

=======
## OneCryptoPkg

> For more details, see [OneCryptoPkg/Docs/README.md](OneCryptoPkg/Docs/README.md).

OneCryptoPkg uses `PlatformBuild.py` (via `stuart_build`) instead of the CI
settings file. By default, it builds **both** DEBUG and RELEASE targets for
`X64` and `AARCH64`.

### Setup

```bash

# Clone GetDependencies() repos (MU_BASECORE, MM_SUPV, mu_plus)
stuart_ci_setup -c PlatformBuild.py

# Sync git submodules listed in .gitmodules (openssl, mbedtls)
stuart_setup  -c PlatformBuild.py

# Fetch ext_deps (NuGet, web, etc.)
stuart_update -c PlatformBuild.py
```

### Build

```bash
# Build all targets and architectures
stuart_build -c PlatformBuild.py TOOL_CHAIN_TAG=CLANGPDB

# Build only X64 RELEASE
stuart_build -c PlatformBuild.py -a X64 -t RELEASE TOOL_CHAIN_TAG=CLANGPDB

# Build only AARCH64 DEBUG
stuart_build -c PlatformBuild.py -a AARCH64 -t DEBUG TOOL_CHAIN_TAG=CLANGPDB
```

### Build Variants

Two variants are available:

- **Accelerated** (default) — uses NASM assembly optimizations in OpenSSL.
- **Non-accelerated** — pure C, no assembly. Built with the `BLD_*_NON_ACCEL=TRUE` flag.

```bash
# Non-accelerated build
stuart_build -c PlatformBuild.py BLD_*_NON_ACCEL=TRUE TOOL_CHAIN_TAG=CLANGPDB
```

### Packaging

After a successful build the OneCryptoBundler plugin automatically produces
`Build/OneCryptoPkg/OneCrypto-Drivers.zip`. To skip packaging, pass
`--skip-packaging`:

```bash
stuart_build -c PlatformBuild.py --skip-packaging TOOL_CHAIN_TAG=CLANGPDB
```

>>>>>>> Stashed changes
## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines.

## License

This project is licensed under the BSD-2-Clause-Patent license. See the
[License.txt](MU_BASECORE/License.txt) file for details.
