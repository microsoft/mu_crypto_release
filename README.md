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

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines.

## License

This project is licensed under the BSD-2-Clause-Patent license. See the
[License.txt](MU_BASECORE/License.txt) file for details.
