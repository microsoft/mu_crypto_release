# OneCryptoPkg and OpensslPkg Documentation

This directory contains the Doxygen configuration for generating comprehensive API documentation for OneCryptoPkg and OpensslPkg crypto libraries.

## Prerequisites

- [Doxygen](https://www.doxygen.nl/) version 1.9.0 or later
- Optional: [Graphviz](https://graphviz.org/) for generating class diagrams and call graphs

## Building the Documentation

To generate the documentation, run the following command from the repository root:

```powershell
doxygen OneCryptoPkg/OneCryptoBin/OneCryptoPkgDoxygen.config
```

Or on Linux/macOS:

```bash
doxygen OneCryptoPkg/OneCryptoBin/OneCryptoPkgDoxygen.config
```

## Viewing the Documentation

After building, the documentation will be available in:
- **HTML**: `Build/CryptoDocs/html/index.html`
- **LaTeX**: `Build/CryptoDocs/latex/` (if LaTeX output is enabled)

To open the HTML documentation:

**Windows:**
```powershell
Invoke-Item Build/CryptoDocs/html/index.html
```

**Linux/macOS:**
```bash
xdg-open Build/CryptoDocs/html/index.html  # Linux
open Build/CryptoDocs/html/index.html      # macOS
```

## What's Documented

The documentation covers:

### OneCryptoPkg
- **Protocol Definitions**: OneCrypto protocol interface (`Include/Protocol/OneCryptoProtocol.h`)
- **Library Headers**: BaseCryptLib, OneCryptoLib, minimal library interfaces
- **Implementation**: OneCryptoBin protocol implementation
- **Minimal Libraries**: MinimalBaseLib, MinimalBaseMemoryLib, MinimalBasePrintLib
- **Consumer Library**: OneCryptoLib that wraps the protocol

### OpensslPkg
- **Protocol Headers**: Shared crypto protocol definitions
- **BaseCryptLib**: Core crypto library implementation
- **Include Files**: Library class headers and private implementation headers

### Architecture Documentation
- System architecture overview
- Platform integration guides
- Security model documentation
- Commit organization guides

## Configuration Details

The Doxygen configuration (`OneCryptoPkgDoxygen.config`) is set to:
- **Recursively scan** all subdirectories in the specified INPUT paths
- **Exclude** the OpenSSL submodule (`OpensslPkg/Library/OpensslLib/openssl`) to avoid documenting upstream OpenSSL code
- **Support multiple file types**: C/C++ source files (`.c`, `.h`), Markdown (`.md`), Python (`.py`)
- **Generate warnings** for undocumented members to help improve documentation quality

## Customization

To modify what gets documented, edit `OneCryptoPkgDoxygen.config`:
- **INPUT**: Add or remove directories to scan
- **EXCLUDE**: Add paths to exclude from documentation
- **FILE_PATTERNS**: Modify which file extensions are processed
- **OUTPUT_DIRECTORY**: Change where documentation is generated

## Notes

- The documentation build may produce warnings about undocumented struct members or function parameters. These are informational and don't prevent the documentation from being generated.
- The generated documentation includes cross-references between files, functions, and data structures for easy navigation.
- Full-text search is available in the generated HTML documentation.
