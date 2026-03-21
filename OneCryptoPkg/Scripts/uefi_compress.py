#!/usr/bin/env python3
"""
UEFI Compression Utility

Measures compressibility of EFI files using the UEFI LzmaCompress algorithm.
Cross-platform (Windows/Linux) and architecture-aware.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import logging
import os
import platform
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def get_lzma_compress_path(workspace_root: Optional[Path] = None) -> Optional[Path]:
    """
    Find the LzmaCompress executable for the current platform and architecture.

    Args:
        workspace_root: Root of the workspace. If None, tries to find it from this script's location.

    Returns:
        Path to LzmaCompress executable, or None if not found.
    """
    if workspace_root is None:
        # Try to find workspace root from this script's location
        # Script is at: <workspace>/OneCryptoPkg/Scripts/uefi_compress.py
        script_dir = Path(__file__).parent
        workspace_root = script_dir.parent.parent

    # Determine platform folder name
    system = platform.system()
    machine = platform.machine().lower()

    # Map platform.machine() to BaseTools folder names
    if system == "Windows":
        if machine in ("amd64", "x86_64", "x64"):
            platform_folder = "Windows-x86"
        elif machine in ("arm64", "aarch64"):
            platform_folder = "Windows-ARM-64"
        else:
            logger.warning(f"Unsupported Windows architecture: {machine}")
            return None
        exe_name = "LzmaCompress.exe"
    elif system == "Linux":
        if machine in ("x86_64", "amd64"):
            platform_folder = "Linux-x86"
        elif machine in ("aarch64", "arm64"):
            platform_folder = "Linux-ARM-64"
        else:
            logger.warning(f"Unsupported Linux architecture: {machine}")
            return None
        exe_name = "LzmaCompress"
    else:
        logger.warning(f"Unsupported operating system: {system}")
        return None

    # Build path to LzmaCompress
    compress_path = workspace_root / "MU_BASECORE" / "BaseTools" / "Bin" / "Mu-Basetools_extdep" / platform_folder / exe_name

    if compress_path.exists():
        return compress_path

    logger.warning(f"LzmaCompress not found at: {compress_path}")
    return None


def get_compressed_size(file_path: Path, workspace_root: Optional[Path] = None) -> Optional[Tuple[int, int, float]]:
    """
    Get the compressed size of a file using UEFI LzmaCompress.

    Args:
        file_path: Path to the file to compress.
        workspace_root: Root of the workspace.

    Returns:
        Tuple of (original_size, compressed_size, ratio) or None if compression failed.
    """
    compress_exe = get_lzma_compress_path(workspace_root)
    if compress_exe is None:
        return None

    if not file_path.exists():
        logger.warning(f"File not found: {file_path}")
        return None

    original_size = file_path.stat().st_size

    # Create temp file for compressed output
    with tempfile.NamedTemporaryFile(delete=False, suffix=".compressed") as tmp:
        tmp_path = Path(tmp.name)

    try:
        # Run LzmaCompress
        result = subprocess.run(
            [str(compress_exe), "-e", "-o", str(tmp_path), str(file_path)],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            logger.warning(f"LzmaCompress failed for {file_path}: {result.stderr}")
            return None

        compressed_size = tmp_path.stat().st_size
        ratio = compressed_size / original_size if original_size > 0 else 0

        return (original_size, compressed_size, ratio)

    finally:
        # Clean up temp file
        if tmp_path.exists():
            tmp_path.unlink()


def format_size(size_bytes: int) -> str:
    """Format size in bytes to human-readable string."""
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes:,} bytes ({size_bytes / (1024*1024):.2f} MB)"
    elif size_bytes >= 1024:
        return f"{size_bytes:,} bytes ({size_bytes / 1024:.1f} KB)"
    else:
        return f"{size_bytes:,} bytes"


def analyze_efi_compression(efi_files: list, workspace_root: Optional[Path] = None) -> dict:
    """
    Analyze compression for a list of EFI files.

    Args:
        efi_files: List of Path objects to EFI files.
        workspace_root: Root of the workspace.

    Returns:
        Dictionary with compression analysis results.
    """
    results = {
        "files": [],
        "total_original": 0,
        "total_compressed": 0,
        "tool_available": False
    }

    compress_exe = get_lzma_compress_path(workspace_root)
    if compress_exe is None:
        logger.warning("LzmaCompress not available - compression analysis skipped")
        return results

    results["tool_available"] = True
    results["tool_path"] = str(compress_exe)

    for efi_path in efi_files:
        if not efi_path.exists():
            continue

        compression_result = get_compressed_size(efi_path, workspace_root)
        if compression_result:
            original, compressed, ratio = compression_result
            results["files"].append({
                "name": efi_path.name,
                "path": str(efi_path),
                "original_size": original,
                "compressed_size": compressed,
                "ratio": ratio
            })
            results["total_original"] += original
            results["total_compressed"] += compressed

    if results["total_original"] > 0:
        results["overall_ratio"] = results["total_compressed"] / results["total_original"]
    else:
        results["overall_ratio"] = 0

    return results


def print_compression_report(results: dict):
    """Print a formatted compression report."""
    if not results["tool_available"]:
        logger.warning("Compression analysis not available (LzmaCompress not found)")
        return

    logger.info("\nUEFI Compression Analysis (LzmaCompress):")
    logger.info("-" * 70)
    logger.info(f"{'File':<40} {'Original':>12} {'Compressed':>12} {'Ratio':>8}")
    logger.info("-" * 70)

    for file_info in results["files"]:
        name = file_info["name"]
        if len(name) > 38:
            name = "..." + name[-35:]
        orig_kb = file_info["original_size"] / 1024
        comp_kb = file_info["compressed_size"] / 1024
        ratio_pct = file_info["ratio"] * 100
        logger.info(f"{name:<40} {orig_kb:>9.1f} KB {comp_kb:>9.1f} KB {ratio_pct:>7.1f}%")

    logger.info("-" * 70)
    total_orig_kb = results["total_original"] / 1024
    total_comp_kb = results["total_compressed"] / 1024
    overall_ratio = results["overall_ratio"] * 100
    logger.info(f"{'TOTAL':<40} {total_orig_kb:>9.1f} KB {total_comp_kb:>9.1f} KB {overall_ratio:>7.1f}%")
    logger.info("")


if __name__ == "__main__":
    import argparse

    # Configure logging for standalone execution
    logging.basicConfig(level=logging.INFO, format='%(message)s')

    parser = argparse.ArgumentParser(description="Analyze UEFI compression of EFI files")
    parser.add_argument("files", nargs="+", help="EFI files to analyze")
    parser.add_argument("--workspace", "-w", help="Workspace root directory")

    args = parser.parse_args()

    workspace = Path(args.workspace) if args.workspace else None
    efi_files = [Path(f) for f in args.files]

    results = analyze_efi_compression(efi_files, workspace)
    print_compression_report(results)
