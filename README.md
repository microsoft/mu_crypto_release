# Project Mu Crypto Release

[![MU_CRYPTO_RELEASE CI](https://github.com/Microsoft/mu_crypto_release/actions/workflows/continuous-integration.yml/badge.svg)](https://github.com/Microsoft/mu_crypto_release/actions/workflows/continuous-integration.yml)

This repository hosts the cryptographic library packages for
[Project Mu](https://microsoft.github.io/mu/). It decomposes the monolithic
`CryptoPkg` into independent, backend-specific packages so that each crypto
implementation can be built, tested, and maintained separately.

## Repository Structure

| Package | Description |
|---|---|
| **OpensslPkg** | BaseCryptLib, OpensslLib, TlsLib, and supporting headers backed by OpenSSL. |
| **MbedTlsPkg** | BaseCryptLib, MbedTlsLib, and supporting headers backed by Mbed TLS. |
| **MU_BASECORE** | Git submodule providing core EDK II packages (MdePkg, MdeModulePkg, CryptoPkg interfaces, etc.). |

## Building

Building uses [stuart](https://github.com/tianocore/edk2-pytool-extensions) and
has been tested on Windows with VS2022 / CLANGPDB and on Linux with CLANGPDB.

```bash
# One-time setup
git submodule update --init --recursive
pip install -r pip-requirements.txt

# Stuart workflow (replace <Pkg> with OpensslPkg or MbedTlsPkg)
stuart_setup    -c .pytool/CISettings.py -p <Pkg>
stuart_ci_setup -c .pytool/CISettings.py -p <Pkg>
stuart_update   -c .pytool/CISettings.py -p <Pkg>
stuart_ci_build -c .pytool/CISettings.py -p <Pkg> TOOL_CHAIN_TAG=CLANGPDB
```

## Continuous Integration

A GitHub Actions workflow (`.github/workflows/continuous-integration.yml`) builds
both **OpensslPkg** and **MbedTlsPkg** with CLANGPDB on every pull request and
push to `main`.

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines.

## License

This project is licensed under the BSD-2-Clause-Patent license. See the
[License.txt](MU_BASECORE/License.txt) file for details.
