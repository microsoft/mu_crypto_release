#!/usr/bin/env python3
"""
Package OneCrypto Build Artifacts

Simple script to package OneCrypto binaries into a zip file with a defined structure.
Easy to modify the layout by changing the FILE_LAYOUT dictionary.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import os
import sys
import zipfile
import re
import hashlib
from pathlib import Path
from datetime import datetime

# =============================================================================
# Configuration
# =============================================================================

# Path to OneCrypto protocol header (relative to script location)
PROTOCOL_HEADER = "../../MU_BASECORE/CryptoPkg/Include/Protocol/OneCrypto.h"

# Base build directory
BUILD_BASE = "Build"

# Default build configuration
DEFAULT_ARCH = "X64"
DEFAULT_TARGET = "DEBUG"
DEFAULT_TOOLCHAIN = "VS2022"
DEFAULT_VERSION = "1.0.0"  # Default version for package naming

# File layout: destination_folder -> list of (source_path, destination_name)
# Source paths are relative to BUILD_BASE or repo root (for Integration files)
FILE_LAYOUT = {
    "OneCryptoBin": [
        (
            f"OneCryptoPkg/{DEFAULT_TARGET}_{DEFAULT_TOOLCHAIN}/{DEFAULT_ARCH}/OneCryptoPkg/OneCryptoBin/OneCryptoBinSupvMm/OUTPUT/OneCryptoBinSupvMm.efi",
            "OneCryptoBinSupvMm.efi"
        ),
        (
            f"OneCryptoPkg/{DEFAULT_TARGET}_{DEFAULT_TOOLCHAIN}/{DEFAULT_ARCH}/OneCryptoPkg/OneCryptoBin/OneCryptoBinSupvMm/OUTPUT/OneCryptoBinSupvMm.depex",
            "OneCryptoBinSupvMm.depex"
        ),
        (
            f"OneCryptoPkg/{DEFAULT_TARGET}_{DEFAULT_TOOLCHAIN}/{DEFAULT_ARCH}/OneCryptoPkg/OneCryptoBin/OneCryptoBinStandaloneMm/OUTPUT/OneCryptoBinStandaloneMm.efi",
            "OneCryptoBinStandaloneMm.efi"
        ),
        (
            f"OneCryptoPkg/{DEFAULT_TARGET}_{DEFAULT_TOOLCHAIN}/{DEFAULT_ARCH}/OneCryptoPkg/OneCryptoBin/OneCryptoBinStandaloneMm/OUTPUT/OneCryptoBinStandaloneMm.depex",
            "OneCryptoBinStandaloneMm.depex"
        ),
        # Integration INF files from source tree
        ("../OneCryptoPkg/OneCryptoBin/Integration/OneCryptoBinSupvMm.inf", "OneCryptoBinSupvMm.inf"),
        ("../OneCryptoPkg/OneCryptoBin/Integration/OneCryptoBinStandaloneMm.inf", "OneCryptoBinStandaloneMm.inf"),
    ],
    "OneCryptoLoaders": [
        (
            f"OneCryptoPkg/{DEFAULT_TARGET}_{DEFAULT_TOOLCHAIN}/{DEFAULT_ARCH}/OneCryptoPkg/OneCryptoLoaders/OneCryptoLoaderDxe/OUTPUT/OneCryptoLoaderDxe.efi",
            "OneCryptoLoaderDxe.efi"
        ),
        (
            f"OneCryptoPkg/{DEFAULT_TARGET}_{DEFAULT_TOOLCHAIN}/{DEFAULT_ARCH}/OneCryptoPkg/OneCryptoLoaders/OneCryptoLoaderDxe/OUTPUT/OneCryptoLoaderDxe.depex",
            "OneCryptoLoaderDxe.depex"
        ),
        (
            f"OneCryptoPkg/{DEFAULT_TARGET}_{DEFAULT_TOOLCHAIN}/{DEFAULT_ARCH}/OneCryptoPkg/OneCryptoLoaders/OneCryptoLoaderSupvMm/OUTPUT/OneCryptoLoaderSupvMm.efi",
            "OneCryptoLoaderSupvMm.efi"
        ),
        (
            f"OneCryptoPkg/{DEFAULT_TARGET}_{DEFAULT_TOOLCHAIN}/{DEFAULT_ARCH}/OneCryptoPkg/OneCryptoLoaders/OneCryptoLoaderSupvMm/OUTPUT/OneCryptoLoaderSupvMm.depex",
            "OneCryptoLoaderSupvMm.depex"
        ),
        (
            f"OneCryptoPkg/{DEFAULT_TARGET}_{DEFAULT_TOOLCHAIN}/{DEFAULT_ARCH}/OneCryptoPkg/OneCryptoLoaders/OneCryptoLoaderStandaloneMm/OUTPUT/OneCryptoLoaderStandaloneMm.efi",
            "OneCryptoLoaderStandaloneMm.efi"
        ),
        (
            f"OneCryptoPkg/{DEFAULT_TARGET}_{DEFAULT_TOOLCHAIN}/{DEFAULT_ARCH}/OneCryptoPkg/OneCryptoLoaders/OneCryptoLoaderStandaloneMm/OUTPUT/OneCryptoLoaderStandaloneMm.depex",
            "OneCryptoLoaderStandaloneMm.depex"
        ),
        # Integration INF files from source tree
        ("../OneCryptoPkg/OneCryptoLoaders/Integration/OneCryptoLoaderDxe.inf", "OneCryptoLoaderDxe.inf"),
        ("../OneCryptoPkg/OneCryptoLoaders/Integration/OneCryptoLoaderSupvMm.inf", "OneCryptoLoaderSupvMm.inf"),
        ("../OneCryptoPkg/OneCryptoLoaders/Integration/OneCryptoLoaderStandaloneMm.inf", "OneCryptoLoaderStandaloneMm.inf"),
    ],
}

# =============================================================================
# Functions
# =============================================================================

def get_onecrypto_version():
    """
    Extract the version from the OneCrypto protocol header.
    
    Returns:
        tuple: (major, minor) version numbers, or (1, 0) if not found
    """
    script_dir = Path(__file__).parent
    header_path = script_dir / PROTOCOL_HEADER
    
    if not header_path.exists():
        print(f"Warning: Protocol header not found at {header_path}")
        print("Using default version 1.0")
        return (1, 0)
    
    try:
        with open(header_path, 'r') as f:
            content = f.read()
        
        # Look for VERSION_MAJOR and VERSION_MINOR defines
        major_match = re.search(r'#define\s+VERSION_MAJOR\s+(\d+)ULL', content)
        minor_match = re.search(r'#define\s+VERSION_MINOR\s+(\d+)ULL', content)
        
        if major_match and minor_match:
            major = int(major_match.group(1))
            minor = int(minor_match.group(1))
            return (major, minor)
        else:
            print("Warning: Could not parse version from protocol header")
            print("Using default version 1.0")
            return (1, 0)
            
    except Exception as e:
        print(f"Warning: Error reading protocol header: {e}")
        print("Using default version 1.0")
        return (1, 0)

def create_package(output_name=None, version=None, arch=None, target=None, toolchain=None):
    """
    Create a zip package with the specified files.
    
    Args:
        output_name: Name of the output zip file (without .zip extension)
        version: Version string (e.g., "1.0.0" becomes "v1_0_0")
        arch: Architecture (e.g., X64, AARCH64)
        target: Build target (DEBUG or RELEASE)
        toolchain: Toolchain used (e.g., VS2022, GCC5)
    
    Returns:
        Path to the created zip file
    """
    # Use defaults if not specified
    arch = arch or DEFAULT_ARCH
    target = target or DEFAULT_TARGET
    toolchain = toolchain or DEFAULT_TOOLCHAIN
    
    # Get version from protocol header if not specified
    if not version:
        major, minor = get_onecrypto_version()
        version = f"{major}.{minor}.0"
    
    # Generate output filename
    if not output_name:
        # Convert version to underscore format (e.g., "1.0.0" -> "v1_0_0")
        version_str = "v" + version.replace(".", "_")
        output_name = f"Mu_CryptoBin_{version_str}"
    
    # Write output to Build directory
    output_zip = Path(BUILD_BASE) / f"{output_name}.zip"
    
    print(f"Creating package: {output_zip}")
    print(f"Architecture: {arch}, Target: {target}, Toolchain: {toolchain}")
    print("-" * 80)
    
    # Update file layout with current build configuration
    updated_layout = {}
    for folder, files in FILE_LAYOUT.items():
        updated_files = []
        for src_path, dest_name in files:
            # Replace placeholders in source path
            src_path = src_path.replace(DEFAULT_ARCH, arch)
            src_path = src_path.replace(DEFAULT_TARGET, target)
            src_path = src_path.replace(DEFAULT_TOOLCHAIN, toolchain)
            updated_files.append((src_path, dest_name))
        updated_layout[folder] = updated_files
    
    # Create the zip file
    missing_files = []
    added_files = []
    
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for folder, files in updated_layout.items():
            print(f"\nProcessing folder: {folder}/")
            
            for src_path, dest_name in files:
                # Integration files use paths relative to BUILD_BASE (which goes up to repo root)
                if src_path.startswith("../"):
                    full_src_path = Path(BUILD_BASE) / src_path
                else:
                    full_src_path = Path(BUILD_BASE) / src_path
                
                zip_path = f"{folder}/{dest_name}"
                
                if full_src_path.exists():
                    file_size = full_src_path.stat().st_size
                    print(f"  + {dest_name} ({file_size:,} bytes)")
                    zipf.write(full_src_path, zip_path)
                    added_files.append(zip_path)
                else:
                    print(f"  - {dest_name} (NOT FOUND: {full_src_path})")
                    missing_files.append(str(full_src_path))
    
    print("\n" + "=" * 80)
    print(f"Package Summary:")
    print(f"  Total files added: {len(added_files)}")
    print(f"  Missing files: {len(missing_files)}")
    
    if missing_files:
        print("\nMissing files:")
        for f in missing_files:
            print(f"  - {f}")
        print("\nWARNING: Some files were not found. Package may be incomplete.")
    
    if added_files:
        # Calculate SHA256 hash of the package
        sha256_hash = hashlib.sha256()
        with open(output_zip, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        print(f"\n✓ Package created successfully: {output_zip}")
        print(f"  Size: {output_zip.stat().st_size:,} bytes")
        print(f"  SHA256: {sha256_hash.hexdigest()}")
        return output_zip
    else:
        print("\n✗ No files were added to the package.")
        output_zip.unlink(missing_ok=True)
        return None

def list_layout():
    """Print the current file layout configuration."""
    print("Current Package Layout:")
    print("=" * 80)
    for folder, files in FILE_LAYOUT.items():
        print(f"\n{folder}/")
        for src_path, dest_name in files:
            print(f"  {dest_name}")
            print(f"    <- {BUILD_BASE}/{src_path}")

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Package OneCrypto build artifacts into a zip file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python package_onecrypto.py
  python package_onecrypto.py --output MyPackage
  python package_onecrypto.py --version 1.0.2
  python package_onecrypto.py --arch AARCH64 --toolchain GCC5
  python package_onecrypto.py --target RELEASE
  python package_onecrypto.py --list
        """
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output zip filename (without .zip extension)',
        default=None
    )
    parser.add_argument(
        '--version', '-v',
        help='Version string (e.g., "1.0.2"). Auto-detected from protocol header if not specified.',
        default=None
    )
    parser.add_argument(
        '--arch', '-a',
        help=f'Architecture (default: {DEFAULT_ARCH})',
        default=None
    )
    parser.add_argument(
        '--target', '-t',
        help=f'Build target (default: {DEFAULT_TARGET})',
        choices=['DEBUG', 'RELEASE'],
        default=None
    )
    parser.add_argument(
        '--toolchain', '-tc',
        help=f'Toolchain (default: {DEFAULT_TOOLCHAIN})',
        default=None
    )
    parser.add_argument(
        '--list', '-l',
        action='store_true',
        help='List the package layout and exit'
    )
    
    args = parser.parse_args()
    
    if args.list:
        list_layout()
        return 0
    
    result = create_package(
        output_name=args.output,
        version=args.version,
        arch=args.arch,
        target=args.target,
        toolchain=args.toolchain
    )
    
    return 0 if result else 1

if __name__ == "__main__":
    sys.exit(main())
