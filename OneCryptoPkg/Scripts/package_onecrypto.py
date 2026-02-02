#!/usr/bin/env python3
"""
Package OneCrypto Build Artifacts

Simple script to package OneCrypto binaries into a zip file with a defined structure.
Easy to modify the layout by changing the FILE_LAYOUT dictionary.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import logging
import os
import sys
import zipfile
import re
import hashlib
from pathlib import Path
from datetime import datetime

# Get logger - use root logger to integrate with Stuart's logging
logger = logging.getLogger(__name__)

def _configure_standalone_logging():
    """Configure logging for standalone script execution."""
    if not logger.handlers and not logging.root.handlers:
        logging.basicConfig(
            level=logging.INFO,
            format='%(message)s'
        )

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
DEFAULT_VERSION = "1.0"  # Default version for package naming

# Supported architectures
SUPPORTED_ARCHITECTURES = ["X64", "AARCH64"]


def get_file_layout(arch, target, toolchain):
    """
    Get the file layout for a specific architecture.

    Architecture-specific layouts:
    - AARCH64: OneCryptoBinDxe, OneCryptoBinDxeLoader, OneCryptoBinStandaloneMm, OneCryptoBinStandaloneMmLoader
    - X64: OneCryptoBinLoader, OneCryptoBinStandaloneMm, OneCryptoBinStandaloneMmLoader, OneCryptoBinSupvMm, OneCryptoBinSupvMmLoader

    Args:
        arch: Architecture (X64, AARCH64)
        target: Build target (DEBUG, RELEASE)
        toolchain: Toolchain (VS2022, GCC5, etc.)

    Returns:
        dict: File layout for the specified architecture
    """
    build_path = f"OneCryptoPkg/{target}_{toolchain}/{arch}/OneCryptoPkg"

    if arch == "AARCH64":
        return {
            "OneCryptoBin": [
                # OneCryptoBinDxe
                (f"{build_path}/OneCryptoBin/OneCryptoBinDxe/OUTPUT/OneCryptoBinDxe.efi", "OneCryptoBinDxe.efi"),
                (f"{build_path}/OneCryptoBin/OneCryptoBinDxe/OUTPUT/OneCryptoBinDxe.depex", "OneCryptoBinDxe.depex"),
                ("../OneCryptoPkg/OneCryptoBin/Integration/OneCryptoBinDxe.inf", "OneCryptoBinDxe.inf"),
                # OneCryptoBinStandaloneMm
                (f"{build_path}/OneCryptoBin/OneCryptoBinStandaloneMm/OUTPUT/OneCryptoBinStandaloneMm.efi", "OneCryptoBinStandaloneMm.efi"),
                (f"{build_path}/OneCryptoBin/OneCryptoBinStandaloneMm/OUTPUT/OneCryptoBinStandaloneMm.depex", "OneCryptoBinStandaloneMm.depex"),
                ("../OneCryptoPkg/OneCryptoBin/Integration/OneCryptoBinStandaloneMm.inf", "OneCryptoBinStandaloneMm.inf"),
            ],
            "OneCryptoLoaders": [
                # OneCryptoBinDxeLoader (OneCryptoLoaderDxe)
                (f"{build_path}/OneCryptoLoaders/OneCryptoLoaderDxeByProtocol/OUTPUT/OneCryptoLoaderDxe.efi", "OneCryptoLoaderDxe.efi"),
                (f"{build_path}/OneCryptoLoaders/OneCryptoLoaderDxeByProtocol/OUTPUT/OneCryptoLoaderDxe.depex", "OneCryptoLoaderDxe.depex"),
                ("../OneCryptoPkg/OneCryptoLoaders/Integration/OneCryptoLoaderDxe.inf", "OneCryptoLoaderDxe.inf"),
                # OneCryptoBinStandaloneMmLoader (OneCryptoLoaderStandaloneMm)
                (f"{build_path}/OneCryptoLoaders/OneCryptoLoaderStandaloneMm/OUTPUT/OneCryptoLoaderStandaloneMm.efi", "OneCryptoLoaderStandaloneMm.efi"),
                (f"{build_path}/OneCryptoLoaders/OneCryptoLoaderStandaloneMm/OUTPUT/OneCryptoLoaderStandaloneMm.depex", "OneCryptoLoaderStandaloneMm.depex"),
                ("../OneCryptoPkg/OneCryptoLoaders/Integration/OneCryptoLoaderStandaloneMm.inf", "OneCryptoLoaderStandaloneMm.inf"),
            ],
            "BuildInfo": [
                (f"OneCryptoPkg/{target}_{toolchain}/BUILD_REPORT.TXT", "BUILD_REPORT.TXT"),
            ],
        }
    else:  # X64 (default)
        return {
            "OneCryptoBin": [
                # OneCryptoBinStandaloneMm
                (f"{build_path}/OneCryptoBin/OneCryptoBinStandaloneMm/OUTPUT/OneCryptoBinStandaloneMm.efi", "OneCryptoBinStandaloneMm.efi"),
                (f"{build_path}/OneCryptoBin/OneCryptoBinStandaloneMm/OUTPUT/OneCryptoBinStandaloneMm.depex", "OneCryptoBinStandaloneMm.depex"),
                ("../OneCryptoPkg/OneCryptoBin/Integration/OneCryptoBinStandaloneMm.inf", "OneCryptoBinStandaloneMm.inf"),
                # OneCryptoBinSupvMm
                (f"{build_path}/OneCryptoBin/OneCryptoBinSupvMm/OUTPUT/OneCryptoBinSupvMm.efi", "OneCryptoBinSupvMm.efi"),
                (f"{build_path}/OneCryptoBin/OneCryptoBinSupvMm/OUTPUT/OneCryptoBinSupvMm.depex", "OneCryptoBinSupvMm.depex"),
                ("../OneCryptoPkg/OneCryptoBin/Integration/OneCryptoBinSupvMm.inf", "OneCryptoBinSupvMm.inf"),
            ],
            "OneCryptoLoaders": [
                # OneCryptoBinLoader (OneCryptoLoaderDxe)
                (f"{build_path}/OneCryptoLoaders/OneCryptoLoaderDxe/OUTPUT/OneCryptoLoaderDxe.efi", "OneCryptoLoaderDxe.efi"),
                (f"{build_path}/OneCryptoLoaders/OneCryptoLoaderDxe/OUTPUT/OneCryptoLoaderDxe.depex", "OneCryptoLoaderDxe.depex"),
                ("../OneCryptoPkg/OneCryptoLoaders/Integration/OneCryptoLoaderDxe.inf", "OneCryptoLoaderDxe.inf"),
                # OneCryptoBinStandaloneMmLoader (OneCryptoLoaderStandaloneMm)
                (f"{build_path}/OneCryptoLoaders/OneCryptoLoaderStandaloneMm/OUTPUT/OneCryptoLoaderStandaloneMm.efi", "OneCryptoLoaderStandaloneMm.efi"),
                (f"{build_path}/OneCryptoLoaders/OneCryptoLoaderStandaloneMm/OUTPUT/OneCryptoLoaderStandaloneMm.depex", "OneCryptoLoaderStandaloneMm.depex"),
                ("../OneCryptoPkg/OneCryptoLoaders/Integration/OneCryptoLoaderStandaloneMm.inf", "OneCryptoLoaderStandaloneMm.inf"),
                # OneCryptoBinSupvMmLoader (OneCryptoLoaderSupvMm)
                (f"{build_path}/OneCryptoLoaders/OneCryptoLoaderSupvMm/OUTPUT/OneCryptoLoaderSupvMm.efi", "OneCryptoLoaderSupvMm.efi"),
                (f"{build_path}/OneCryptoLoaders/OneCryptoLoaderSupvMm/OUTPUT/OneCryptoLoaderSupvMm.depex", "OneCryptoLoaderSupvMm.depex"),
                ("../OneCryptoPkg/OneCryptoLoaders/Integration/OneCryptoLoaderSupvMm.inf", "OneCryptoLoaderSupvMm.inf"),
            ],
            "BuildInfo": [
                (f"OneCryptoPkg/{target}_{toolchain}/BUILD_REPORT.TXT", "BUILD_REPORT.TXT"),
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
        logger.warning(f"Protocol header not found at {header_path}")
        logger.warning("Using default version 1.0")
        return (1, 0)

    try:
        with open(header_path, 'r') as f:
            content = f.read()

        # Look for ONE_CRYPTO_VERSION_MAJOR and ONE_CRYPTO_VERSION_MINOR defines
        major_match = re.search(r'#define\s+ONE_CRYPTO_VERSION_MAJOR\s+(\d+)ULL', content)
        minor_match = re.search(r'#define\s+ONE_CRYPTO_VERSION_MINOR\s+(\d+)ULL', content)

        if major_match and minor_match:
            major = int(major_match.group(1))
            minor = int(minor_match.group(1))
            return (major, minor)
        else:
            logger.warning("Could not parse version from protocol header")
            logger.warning("Using default version 1.0")
            return (1, 0)

    except Exception as e:
        logger.warning(f"Error reading protocol header: {e}")
        logger.warning("Using default version 1.0")
        return (1, 0)

def create_package(output_name=None, version=None, architectures=None, target=None, toolchain=None, arch=None):
    """
    Create a zip package with the specified files.

    Package structure: <target>/<arch>/<BuildInfo|OneCryptoBin|OneCryptoLoaders>/

    Args:
        output_name: Name of the output zip file (without .zip extension)
        version: Version string (e.g., "1.0.0" becomes "v1_0_0")
        architectures: List of architectures to include (X64, AARCH64), or None for all available
        target: Build target (DEBUG or RELEASE)
        toolchain: Toolchain used (e.g., VS2022, GCC5)
        arch: Single architecture (for backward compatibility, use 'architectures' for multiple)

    Returns:
        dict with package details on success, None on failure
    """
    # Use defaults if not specified
    target = target or DEFAULT_TARGET
    toolchain = toolchain or DEFAULT_TOOLCHAIN

    # Handle backward compatibility: 'arch' parameter for single architecture
    if arch is not None and architectures is None:
        architectures = [arch]

    # If no architectures specified, try to include all supported architectures that have builds
    if architectures is None:
        architectures = SUPPORTED_ARCHITECTURES
    elif isinstance(architectures, str):
        architectures = [architectures]

    # Validate architectures
    valid_archs = []
    for arch in architectures:
        if arch not in SUPPORTED_ARCHITECTURES:
            logger.warning(f"Unsupported architecture: {arch}, skipping")
        else:
            valid_archs.append(arch)

    if not valid_archs:
        logger.error("No valid architectures specified")
        logger.error(f"Supported architectures: {', '.join(SUPPORTED_ARCHITECTURES)}")
        return None

    # Get version from protocol header if not specified
    if not version:
        major, minor = get_onecrypto_version()
        version = f"{major}.{minor}"

    # Generate output filename
    if not output_name:
        # Convert version to underscore format (e.g., "1.0" -> "v1_0")
        version_string = "v" + version.replace(".", "_")
        output_name = f"OneCrypto_Drivers_{version_string}"

    # Write output to Build directory
    output_zip = Path(BUILD_BASE) / f"{output_name}.zip"

    logger.info(f"Creating package: {output_zip}")
    logger.info(f"Target: {target}, Toolchain: {toolchain}")
    logger.info(f"Architectures: {', '.join(valid_archs)}")
    logger.info("-" * 80)

    # Create the zip file
    missing_files = []
    added_files = []
    folder_sizes = {}  # Track sizes per folder (includes arch prefix)
    file_details = []  # Track individual file details
    archs_included = []  # Track which architectures actually had files

    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for arch in valid_archs:
            # Get architecture-specific file layout
            file_layout = get_file_layout(arch, target, toolchain)
            arch_has_files = False

            logger.info(f"\n[{target}/{arch}]")

            for folder, files in file_layout.items():
                # New structure: <target>/<arch>/<folder>/
                full_folder = f"{target}/{arch}/{folder}"
                logger.info(f"  Processing: {full_folder}/")
                folder_sizes[full_folder] = 0

                for src_path, dest_name in files:
                    # Integration files use paths relative to BUILD_BASE (which goes up to repo root)
                    if src_path.startswith("../"):
                        full_src_path = Path(BUILD_BASE) / src_path
                    else:
                        full_src_path = Path(BUILD_BASE) / src_path

                    zip_path = f"{full_folder}/{dest_name}"

                    if full_src_path.exists():
                        file_size = full_src_path.stat().st_size
                        folder_sizes[full_folder] += file_size
                        # Show size in KB for .efi files for easier reading
                        if dest_name.endswith('.efi'):
                            size_str = f"{file_size:,} bytes ({file_size / 1024:.1f} KB)"
                        else:
                            size_str = f"{file_size:,} bytes"
                        logger.info(f"    + {dest_name} ({size_str})")
                        zipf.write(full_src_path, zip_path)
                        added_files.append((zip_path, file_size))
                        file_details.append({
                            "arch": arch,
                            "folder": folder,
                            "name": dest_name,
                            "path": str(full_src_path),  # Source file path for analysis
                            "zip_path": zip_path,
                            "size": file_size
                        })
                        arch_has_files = True
                    else:
                        logger.warning(f"    - {dest_name} (NOT FOUND: {full_src_path})")
                        missing_files.append(str(full_src_path))

            if arch_has_files:
                archs_included.append(arch)

    logger.info("\n" + "=" * 80)
    logger.info("Package Summary:")
    logger.info("-" * 40)

    # Show per-architecture size breakdown
    total_size = 0
    arch_totals = {}
    for folder_path, size in folder_sizes.items():
        total_size += size
        # Extract arch from path (e.g., "DEBUG/X64/OneCryptoBin" -> "X64")
        parts = folder_path.split('/')
        if len(parts) >= 2:
            arch = parts[1]
            arch_totals[arch] = arch_totals.get(arch, 0) + size

    for arch in archs_included:
        arch_size = arch_totals.get(arch, 0)
        logger.info(f"  {target}/{arch}: {arch_size:,} bytes ({arch_size / 1024:.1f} KB)")

    logger.info("-" * 40)
    logger.info(f"  Architectures included: {', '.join(archs_included)}")
    logger.info(f"  Total uncompressed: {total_size:,} bytes ({total_size / 1024:.1f} KB)")
    logger.info(f"  Total files added: {len(added_files)}")
    logger.info(f"  Missing files: {len(missing_files)}")

    if missing_files:
        logger.warning("\nMissing files:")
        for f in missing_files:
            logger.warning(f"  - {f}")
        logger.warning("\nWARNING: Some files were not found. Package may be incomplete.")

    if added_files:
        # Calculate SHA256 hash of the package
        sha256_hash = hashlib.sha256()
        with open(output_zip, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        compressed_size = output_zip.stat().st_size
        logger.info(f"\n✓ Package created successfully: {output_zip}")
        logger.info(f"  Compressed size: {compressed_size:,} bytes ({compressed_size / 1024:.1f} KB)")
        logger.info(f"  SHA256: {sha256_hash.hexdigest()}")

        # Return result with details for callers
        return {
            "path": output_zip,
            "architectures": archs_included,
            "target": target,
            "folder_sizes": folder_sizes,
            "file_details": file_details,
            "total_uncompressed": total_size,
            "compressed_size": compressed_size,
            "sha256": sha256_hash.hexdigest(),
            "files_added": len(added_files),
            "files_missing": len(missing_files)
        }
    else:
        logger.error("\n✗ No files were added to the package.")
        output_zip.unlink(missing_ok=True)
        return None

def list_layout(arch=None, target=None):
    """Print the file layout configuration for architectures."""
    target = target or DEFAULT_TARGET
    archs_to_show = [arch] if arch else SUPPORTED_ARCHITECTURES

    for arch in archs_to_show:
        if arch not in SUPPORTED_ARCHITECTURES:
            logger.error(f"Unsupported architecture: {arch}")
            logger.error(f"Supported architectures: {', '.join(SUPPORTED_ARCHITECTURES)}")
            continue

        file_layout = get_file_layout(arch, target, DEFAULT_TOOLCHAIN)

        logger.info(f"\nPackage Layout for {target}/{arch}:")
        logger.info("=" * 80)
        for folder, files in file_layout.items():
            logger.info(f"\n{target}/{arch}/{folder}/")
            for src_path, dest_name in files:
                logger.info(f"  {dest_name}")
                logger.info(f"    <- {BUILD_BASE}/{src_path}")

def main():
    """Main entry point."""
    import argparse

    # Configure logging for standalone execution
    _configure_standalone_logging()

    parser = argparse.ArgumentParser(
        description="Package OneCrypto build artifacts into a zip file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python package_onecrypto.py                           # Package all architectures
  python package_onecrypto.py --arch X64                # Package only X64
  python package_onecrypto.py --arch X64 --arch AARCH64 # Package specific architectures
  python package_onecrypto.py --output MyPackage
  python package_onecrypto.py --version 1.0.2
  python package_onecrypto.py --target RELEASE
  python package_onecrypto.py --list                    # Show layout for all architectures
  python package_onecrypto.py --list --arch X64         # Show layout for X64 only

Package Structure:
  <target>/<arch>/BuildInfo/
  <target>/<arch>/OneCryptoBin/
  <target>/<arch>/OneCryptoLoaders/
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
        action='append',
        dest='architectures',
        choices=SUPPORTED_ARCHITECTURES,
        help='Architecture to include (can be specified multiple times). Default: all supported',
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
        # Show layout for specified arch or all architectures
        if args.architectures:
            for arch in args.architectures:
                list_layout(arch=arch, target=args.target)
        else:
            list_layout(target=args.target)
        return 0

    result = create_package(
        output_name=args.output,
        version=args.version,
        architectures=args.architectures,
        target=args.target,
        toolchain=args.toolchain,
    )

    return 0 if result else 1

if __name__ == "__main__":
    sys.exit(main())
