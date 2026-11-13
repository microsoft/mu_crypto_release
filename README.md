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

## OpenSSL Provider Configuration

The table summarizes existing and post-quantum provider/library capabilities,
not additional OneCrypto services or platform security policy. EC-dependent
entries require `OpensslLibFull` or `OpensslLibFullAccel`; they are omitted from
the no-EC library instances. Availability is not a recommendation to use legacy
algorithms or protocols.

| Feature | Enabled configuration |
|---------|-----------------------|
| Digests | MD5, SHA-1, SHA-224/256/384/512, SHA3-256/512, SHAKE-128/256, SM3 |
| Symmetric encryption | AES-128/192/256 in ECB, CBC, CTR, and GCM modes; AES-128/256-CBC-HMAC-SHA256 where supported by the implementation |
| Message authentication | HMAC |
| Key derivation | HKDF, PBKDF2, SSKDF, SSHKDF, TLS 1 PRF, TLS 1.3 KDF |
| Random generation | CTR-DRBG, HASH-DRBG |
| Classical signatures | RSA, ECDSA |
| Classical key exchange | DH, ECDH, X25519, X448 |
| RSA encryption | Enabled |
| CMS verification | Enabled through `Pkcs7Verify` and `AuthenticodeVerify` |
| ML-DSA | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| ML-KEM | ML-KEM-512, ML-KEM-768, ML-KEM-1024 |
| SLH-DSA | Disabled to reduce binary size |
| TlsLib version selection | TLS 1.0, 1.1, 1.2, and 1.3; negotiation is subject to security and cipher policy |
| TLS 1.3 cipher suites | TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 |
| Classical groups accepted by `TlsSetEcCurve` | P-256, P-384, P-521, X25519, X448 |
| Hybrid groups accepted by `TlsSetEcCurve` | X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 |

Explicit TLS cipher lists replace suites across both protocol families:
requesting only TLS 1.2 suites disables TLS 1.3 suites, and vice versa.
Unsupported suites are filtered without enabling an unrequested cipher family.

Generated headers, assembly, and INF source lists must be regenerated together
using `python OpensslPkg/Library/OpensslLib/configure.py` after changing the
OpenSSL revision or configuration.

## Repository Structure

| Package            | Description                                                                              |
|--------------------|------------------------------------------------------------------------------------------|
| **OneCryptoPkg**   | Unified cross-phase crypto driver that dispatches the crypto provider.     |
| **OpensslPkg**     | BaseCryptLib, OpensslLib, TlsLib, and supporting headers backed by OpenSSL.              |
| **MbedTlsPkg**     | BaseCryptLib, MbedTlsLib, and supporting headers backed by Mbed TLS.                     |

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
