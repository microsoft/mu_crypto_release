import hashlib
import logging
import os
import platform
import re
import subprocess
import tempfile
import zipfile
from edk2toolext.environment.plugintypes.uefi_helper_plugin import IUefiHelperPlugin
from pathlib import Path

class OneCryptoBundler(IUefiHelperPlugin):
    
    def RegisterHelpers(self, obj):
        fp = os.path.abspath(__file__)
        obj.Register("create_package", self.create_package, fp)
        obj.Register("get_onecrypto_version", get_onecrypto_version, fp)


    @staticmethod
    def create_package(
        workspace: str,
        output_zip: Path,
        architectures: list[str],
        toolchain: str,
        targets: list[str],
    ):
        """
        Create a zip package with the specified files.

        Package structure: <target>/<arch>/<BuildInfo|OneCryptoBin|OneCryptoLoaders>/

        Args:
            output_zip: Full path (including filename) for the output zip file (e.g., "C:/OneCrypto.zip")
            version: Version string (e.g., "1.0.0" becomes "v1_0_0")
            architectures: List of architectures to include (X64, AARCH64), or None for all available
            toolchain: Toolchain used (e.g., VS2022, GCC5)
            targets: List of build targets (DEBUG, RELEASE), or None for default

        Returns:
            dict with package details on success, None on failure
        """       
        logging.info(f"Creating package: {output_zip.resolve()}:")
        logging.info(f"  Targets: {', '.join(targets)}")
        logging.info(f"  Architectures: {', '.join(architectures)}")
        
        # Create the zip file. 'w' mode will overwrite if it already exists
        with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for target in targets:
                for arch in architectures:
                    zip_bundle(workspace, target, arch, toolchain, zipf)
            add_log_files(workspace, zipf)
            log_bundle_info(workspace, output_zip, targets, architectures, toolchain, zipf)


def zip_bundle(workspace, target, arch, toolchain, output_zip):
    """
    Inserts specific files into the zip bundle provided by output_zip.

    Args:
        workspace: Path to the workspace (repo root)
        target: Build target (DEBUG, RELEASE)
        arch: Architecture (X64, AARCH64)
        toolchain: Toolchain used (e.g., VS2022, GCC5)
        output_zip: Path to the output zip file
    """
    # Get architecture-specific file layout
    file_layout = get_file_layout(workspace, arch, target, toolchain)

    for folder, files in file_layout.items():
        # New structure: <target>/<arch>/<folder>/
        full_folder = f"{target}/{arch}/{folder}"
        logging.info(f"  Processing: {full_folder}/")

        for src_path, dest_name in files:
            zip_path = f"{full_folder}/{dest_name}"
            full_src_path = Path(src_path)

            if not full_src_path.exists():
                raise FileNotFoundError(full_src_path)
            file_size = full_src_path.stat().st_size
            # Show size in KB for .efi files for easier reading
            if dest_name.endswith('.efi'):
                size_str = f"{file_size:,} bytes ({file_size / 1024:.1f} KB)"
            else:
                size_str = f"{file_size:,} bytes"
            logging.info(f"    + {dest_name} ({size_str})")
            output_zip.write(full_src_path, zip_path)


def add_log_files(workspace, zipf):
    """
    Move the setup, update, and build logs into a top level "Logs" folder in the zip.

    Args:
        workspace: Path to the workspace (repo root)
        zipf: Open ZipFile object to write the metadata file into
    """
    build_dir = Path(workspace) / "Build"
    for log_file in build_dir.glob("*.txt"):
        zipf.write(log_file, f"Logs/{log_file.name}")
        logging.info(f"  + Logs/{log_file.name}")



def log_bundle_info(workspace, output_zip, targets, architectures, toolchain, zipf):
    """
    Log a packaging summary including EFI sizes, compression ratios, and SHA256.

    Args:
        workspace: Path to the workspace (repo root)
        output_zip: Path to the output zip file
        targets: List of build targets (DEBUG, RELEASE)
        architectures: List of architectures (X64, AARCH64)
        toolchain: Toolchain used (e.g., VS2022, GCC5)
        zipf: Open ZipFile object to read entry metadata from
    """
    logging.critical("=" * 80)
    logging.critical("OneCrypto Packaging Summary:")
    total_uncompressed = 0
    total_compressed = 0
    for target in targets:
        for arch in architectures:
            logging.critical("-" * 80)
            layout = get_file_layout(workspace, arch, target, toolchain)
            for folder in layout:
                if folder == "BuildInfo":
                    continue
                efi_entries = [
                    (src, name)
                    for src, name in layout[folder]
                    if name.endswith('.efi')
                ]
                if not efi_entries:
                    continue
                logging.critical(f"[{target}/{arch}] {folder} EFI Sizes")
                for src_path, name in efi_entries:
                    file_size = Path(src_path).stat().st_size
                    compressed = get_compressed_size(Path(src_path), Path(workspace))
                    total_uncompressed += file_size
                    if compressed is not None:
                        total_compressed += compressed
                        ratio = (1 - compressed / file_size) * 100 if file_size else 0
                        logging.critical(f"  {name}: {file_size:,} -> {compressed:,} ({ratio:.0f}%)")
                    else:
                        logging.critical(f"  {name}: {file_size:,} (LZMA compression unavailable)")
    logging.critical("-" * 80)
    ratio = (1 - total_compressed / total_uncompressed) * 100 if total_uncompressed else 0
    logging.critical(f"Total: {total_uncompressed:,} -> {total_compressed:,} ({ratio:.0f}% compression)")
    sha256 = hashlib.sha256(Path(output_zip).read_bytes()).hexdigest()
    logging.critical(f"SHA256: {sha256}")
    logging.critical(f"Package: {Path(output_zip).resolve()}")
    logging.critical("=" * 80)


def get_file_layout(workspace, arch, target, toolchain):
    """
    Get the file layout for a specific architecture.

    Architecture-specific layouts:
    - AARCH64: OneCryptoBinDxe, OneCryptoBinDxeLoader, OneCryptoBinStandaloneMm, OneCryptoBinStandaloneMmLoader
    - X64: OneCryptoBinLoader, OneCryptoBinStandaloneMm, OneCryptoBinStandaloneMmLoader, OneCryptoBinSupvMm, OneCryptoBinSupvMmLoader

    Args:
        arch: Architecture (X64, AARCH64)
        target: Build target (DEBUG, RELEASE)
        toolchain: Toolchain (CLANGPDB, VS2022, GCC5, etc.)

    Returns:
        dict: File layout for the specified architecture
    """
    ws = Path(workspace)
    build_output = ws / "Build" / "OneCryptoPkg" / f"{target}_{toolchain}"
    package_build_dir = str(build_output / arch / "OneCryptoPkg")
    is_debug = target == "DEBUG"

    def driver_files(driver_dir, driver_name, new_name):
        """Build the file list for a module, including .efi, .depex, and optionally .pdb if debug."""
        files = [
            (f"{driver_dir}/OUTPUT/{driver_name}.efi", f"{new_name}.efi"),
            (f"{driver_dir}/OUTPUT/{driver_name}.depex", f"{new_name}.depex"),
        ]
        if is_debug:
            files.append((f"{driver_dir}/OUTPUT/{driver_name}.pdb", f"{new_name}.pdb"))
        return files

    if arch == "AARCH64":
        return {
            "OneCryptoBin": [
                # OneCryptoBinDxe
                *driver_files(f"{package_build_dir}/OneCryptoBin/OneCryptoBinDxe", "OneCryptoBinDxe", "OneCryptoBinDxe"),
                (f"{workspace}/OneCryptoPkg/OneCryptoBin/Integration/OneCryptoBinDxe.inf", "OneCryptoBinDxe.inf"),
                # OneCryptoBinStandaloneMm
                *driver_files(f"{package_build_dir}/OneCryptoBin/OneCryptoBinStandaloneMm", "OneCryptoBinStandaloneMm", "OneCryptoBinStandaloneMm"),
                (f"{workspace}/OneCryptoPkg/OneCryptoBin/Integration/OneCryptoBinStandaloneMm.inf", "OneCryptoBinStandaloneMm.inf"),
            ],
            "OneCryptoLoaders": [
                # OneCryptoBinDxeLoader (OneCryptoLoaderDxe)
                *driver_files(f"{package_build_dir}/OneCryptoLoaders/OneCryptoLoaderDxeByProtocol", "OneCryptoLoaderDxe", "OneCryptoLoaderDxeByProtocol"),
                (f"{workspace}/OneCryptoPkg/OneCryptoLoaders/Integration/OneCryptoLoaderDxe.inf", "OneCryptoLoaderDxe.inf"),
                # OneCryptoBinStandaloneMmLoader (OneCryptoLoaderStandaloneMm)
                *driver_files(f"{package_build_dir}/OneCryptoLoaders/OneCryptoLoaderStandaloneMm", "OneCryptoLoaderStandaloneMm", "OneCryptoLoaderStandaloneMm"),
                (f"{workspace}/OneCryptoPkg/OneCryptoLoaders/Integration/OneCryptoLoaderStandaloneMm.inf", "OneCryptoLoaderStandaloneMm.inf"),
            ],
            "BuildInfo": [
                (f"{build_output}/BUILD_REPORT.TXT", "BUILD_REPORT.TXT"),
            ],
        }
    else:  # X64 (default)
        return {
            "OneCryptoBin": [
                # OneCryptoBinStandaloneMm
                (f"{package_build_dir}/OneCryptoBin/OneCryptoBinStandaloneMm/OUTPUT/OneCryptoBinStandaloneMm.efi", "OneCryptoBinStandaloneMm.efi"),
                (f"{package_build_dir}/OneCryptoBin/OneCryptoBinStandaloneMm/OUTPUT/OneCryptoBinStandaloneMm.depex", "OneCryptoBinStandaloneMm.depex"),
                (f"{workspace}/OneCryptoPkg/OneCryptoBin/Integration/OneCryptoBinStandaloneMm.inf", "OneCryptoBinStandaloneMm.inf"),
                # OneCryptoBinSupvMm
                (f"{package_build_dir}/OneCryptoBin/OneCryptoBinSupvMm/OUTPUT/OneCryptoBinSupvMm.efi", "OneCryptoBinSupvMm.efi"),
                (f"{package_build_dir}/OneCryptoBin/OneCryptoBinSupvMm/OUTPUT/OneCryptoBinSupvMm.depex", "OneCryptoBinSupvMm.depex"),
                (f"{workspace}/OneCryptoPkg/OneCryptoBin/Integration/OneCryptoBinSupvMm.inf", "OneCryptoBinSupvMm.inf"),
            ],
            "OneCryptoLoaders": [
                # OneCryptoBinLoader (OneCryptoLoaderDxe)
                (f"{package_build_dir}/OneCryptoLoaders/OneCryptoLoaderDxe/OUTPUT/OneCryptoLoaderDxe.efi", "OneCryptoLoaderDxe.efi"),
                (f"{package_build_dir}/OneCryptoLoaders/OneCryptoLoaderDxe/OUTPUT/OneCryptoLoaderDxe.depex", "OneCryptoLoaderDxe.depex"),
                (f"{workspace}/OneCryptoPkg/OneCryptoLoaders/Integration/OneCryptoLoaderDxe.inf", "OneCryptoLoaderDxe.inf"),
                # OneCryptoBinStandaloneMmLoader (OneCryptoLoaderStandaloneMm)
                (f"{package_build_dir}/OneCryptoLoaders/OneCryptoLoaderStandaloneMm/OUTPUT/OneCryptoLoaderStandaloneMm.efi", "OneCryptoLoaderStandaloneMm.efi"),
                (f"{package_build_dir}/OneCryptoLoaders/OneCryptoLoaderStandaloneMm/OUTPUT/OneCryptoLoaderStandaloneMm.depex", "OneCryptoLoaderStandaloneMm.depex"),
                (f"{workspace}/OneCryptoPkg/OneCryptoLoaders/Integration/OneCryptoLoaderStandaloneMm.inf", "OneCryptoLoaderStandaloneMm.inf"),
                # OneCryptoBinSupvMmLoader (OneCryptoLoaderSupvMm)
                (f"{package_build_dir}/OneCryptoLoaders/OneCryptoLoaderSupvMm/OUTPUT/OneCryptoLoaderSupvMm.efi", "OneCryptoLoaderSupvMm.efi"),
                (f"{package_build_dir}/OneCryptoLoaders/OneCryptoLoaderSupvMm/OUTPUT/OneCryptoLoaderSupvMm.depex", "OneCryptoLoaderSupvMm.depex"),
                (f"{workspace}/OneCryptoPkg/OneCryptoLoaders/Integration/OneCryptoLoaderSupvMm.inf", "OneCryptoLoaderSupvMm.inf"),
            ],
            "BuildInfo": [
                (f"{build_output}/BUILD_REPORT.TXT", "BUILD_REPORT.TXT"),
            ],
        }


def get_lzma_compress_path(workspace_root: Path) -> Path | None:
    """
    Find the LzmaCompress executable for the current platform and architecture.

    Args:
        workspace_root: Root of the workspace. If None, tries to find it from this script's location.

    Returns:
        Path to LzmaCompress executable, or None if not found.
    """
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


def get_compressed_size(file_path: Path, workspace_root: Path) -> int | None:
    """
    Get the compressed size of a file using UEFI LzmaCompress.

    Args:
        file_path: Path to the file to compress.
        workspace_root: Root of the workspace.

    Returns:
        Compressed size in bytes, or None if compression failed.
    """
    compress_exe = get_lzma_compress_path(workspace_root)
    if compress_exe is None:
        return None

    if not file_path.exists():
        logger.warning(f"File not found: {file_path}")
        return None

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

        return tmp_path.stat().st_size

    finally:
        # Clean up temp file
        if tmp_path.exists():
            tmp_path.unlink()


@staticmethod
def get_onecrypto_version(workspace: str):
    """
    Extract the version from the OneCrypto protocol header.

    Returns:
        tuple: (major, minor) version numbers, or (1, 0) if not found
    """
    script_dir = Path(__file__).parent
    header_path = Path(workspace) / "MU_BASECORE" / "CryptoPkg" / "Include" / "Protocol" / "OneCrypto.h"

    if not header_path.exists():
        logging.warning(f"Protocol header not found at {header_path}")
        logging.warning("Using default version 1.0")
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
            logging.warning("Could not parse version from protocol header")
            logging.warning("Using default version 1.0")
            return (1, 0)

    except Exception as e:
        logging.warning(f"Error reading protocol header: {e}")
        logging.warning("Using default version 1.0")
        return (1, 0)


if __name__ == "__main__":
    import argparse
    argparser = argparse.ArgumentParser(description="OneCrypto Packaging Script")
    argparser.add_argument("output", help="Output zip file path (e.g., OneCrypto.zip)")
    argparser.add_argument("-w", "--workspace", required=False, default=".", help="Path to the workspace (repo root)")
    argparser.add_argument("--toolchain", required=False, default="CLANGPDB", help="Toolchain used for the build (e.g., CLANGPDB, VS2022, GCC5)")
    argparser.add_argument("-a", "--architecture", required=False, action='append', help="Architecture(s) to include (X64, AARCH64). Can specify multiple times.")
    argparser.add_argument("-t", "--target", required=False, action='append', help="Build target(s) to include (DEBUG, RELEASE). Can specify multiple times.")

    args = argparser.parse_args()

    OneCryptoBundler.create_package(
        workspace=args.workspace,
        output_zip=Path(args.output),
        architectures=args.architecture if args.architecture else ["X64", "AARCH64"],
        toolchain=args.toolchain,
        targets=args.target if args.target else ["DEBUG", "RELEASE"],
    )
