import os
import logging
import struct
import uswid
import lzma

from edk2toollib.utility_functions import RunCmd
from edk2toolext.environment.plugintypes.uefi_helper_plugin import IUefiHelperPlugin
from pathlib import Path
from io import StringIO


# EFI_ACPI_SBOM_TABLE_ENTRY constants
SBOM_REVISION           = 0x04
SBOM_FLAG_NONE          = 0x00
SBOM_FORMAT_COSWID      = 0x00
SBOM_FORMAT_CYCLONEDX   = 0x01
SBOM_FORMAT_SPDX        = 0x02
SBOM_FORMAT_VENDOR      = 0xFF
SBOM_COMPRESSION_NONE   = 0x00
SBOM_COMPRESSION_ZLIB   = 0x01
SBOM_COMPRESSION_LZMA   = 0x02
SBOM_COMPRESSION_VENDOR = 0xFF


class SbomInserter(IUefiHelperPlugin):
    
    def RegisterHelpers(self, obj):
        fp = os.path.abspath(__file__)
        obj.Register("create_sbom", self.create_sbom, fp)

    
    @staticmethod    
    def create_sbom(ws: Path, efi_file: Path, sbom_data: dict):
        """Creates an SBOM for the given OneCryptoBin EFI File.
        
        The SBOM is generated in COSWID format, compressed with LZMA, and inserted into the EFI file in a `.sbom`
        section. Additionally, an SPDX XML sidecar is emitted next to the EFI file for tooling that consumes SPDX
        directly.
        
        Args:
            ws (Path): The workspace path.
            efi_file (Path): The path to the OneCryptoBin EFI file.
            sbom_data (dict): A dictionary containing the following keys:
                - "ARCHITECTURE": The architecture of the build (e.g., "X64", "AARCH64").
                - "TARGET": The build target (e.g., "DEBUG", "RELEASE").
                - "GUID": The GUID of the OneCrypto Binary EFI file.
                - "EFI_NAME": The name of the OneCrypto Binary EFI file.
                - "VERSION": The current One Crypto Version.
                - "TOOL_CHAIN_TAG": The toolchain tag used for the build (e.g., "CLANGPDB").
        """
        container = SbomInserter.build_sbom(ws, sbom_data)
        
        b = uswid.uSwidFormatSpdx().save(container)
        
        compressed = lzma.compress(b)

        sbom_table_entry = SbomInserter.build_sbom_table_entry(
            payload=compressed,
            fmt=SBOM_FORMAT_SPDX,
            compression=SBOM_COMPRESSION_LZMA,
        )

        SbomInserter.write_sbom_section(efi_file, sbom_table_entry)

        # Also emit an SPDX XML sidecar next to the EFI for tooling that
        # consumes SPDX directly.
        spdx_path = Path(efi_file).with_suffix(".spdx.xml")
        spdx_path.write_bytes(b)
    
    @staticmethod
    def build_sbom(ws: Path, sbom_data: dict) -> uswid.uSwidContainer:
        """Builds a SBOM container for OneCrypto and OpenSSL components.
        
        Args:
            ws (Path): The workspace path.
            sbom_data (dict): A dictionary containing the following keys:
                - "ARCHITECTURE": The architecture of the build (e.g., "X64", "AARCH64").
                - "TARGET": The build target (e.g., "DEBUG", "RELEASE").
                - "GUID": The GUID of the OneCrypto Binary EFI file.
                - "EFI_NAME": The name of the OneCrypto Binary EFI file.
                - "VERSION": The current One Crypto Version.
                - "TOOL_CHAIN_TAG": The toolchain tag used for the build (e.g., "CLANGPDB").
        """
        compiler_link = SbomInserter.build_compiler_link(sbom_data)
        
        openssl_component, openssl_link = SbomInserter.build_openssl_component(
            ws,
            sbom_data,
            compiler_link,
        )
        
        one_crypto_component, one_crypto_link = SbomInserter.build_one_crypto_component(
            ws,
            sbom_data,
            compiler_link,
        )
        
        openssl_component.add_link(one_crypto_link)
        one_crypto_component.add_link(openssl_link)
        
        container = uswid.uSwidContainer([one_crypto_component, openssl_component])
        container.depsolve()
        
        return container

    @staticmethod
    def build_openssl_component(ws: Path, lookup: dict, compiler: uswid.uSwidLink) -> tuple[uswid.uSwidComponent, uswid.uSwidLink]:
        """Builds a SBOM component for OpenSSL and a link attribute for self-referencing inside the SBOM.
        
        Args:
            lookup (dict): A dictionary containing the following keys:
                - "ARCHITECTURE": The architecture of the build (e.g., "X64", "AARCH64").
                - "TARGET": The build target (e.g., "DEBUG", "RELEASE").
            compiler (uswid.uSwidLink): A uSwidLink object representing the compiler used for the build.
        """
        # This UUID is only used to associate components together.
        TAG_ID = "e2aeed23-3824-45ad-9043-a5237e1131c2".lower()
        
        architecture = lookup["ARCHITECTURE"]
        target = lookup["TARGET"]
        
        openssl_version = SbomInserter.get_openssl_version(ws)
        colloquial_version = SbomInserter.get_openssl_sha(ws)

        openssl_entity = uswid.uSwidEntity(
            name = "The OpenSSL Project",
            regid = "openssl.org",
            roles = [
                uswid.uSwidEntityRole.DISTRIBUTOR, 
                uswid.uSwidEntityRole.MAINTAINER, 
                uswid.uSwidEntityRole.SOFTWARE_CREATOR
            ]
        )
        
        openssl_license = uswid.uSwidLink(
            rel=uswid.uSwidLinkRel.LICENSE,
            spdx_id="Apache-2.0",
        )
        
        openssl_library_link = uswid.uSwidLink(
            href=f"uswid:{TAG_ID}",
            rel=uswid.uSwidLinkRel.COMPONENT,
        )
        
        component = uswid.uSwidComponent(
            tag_id=TAG_ID,
            tag_version=1,
            software_name="OpenSSL",
            software_version=openssl_version
        )
        
        component.add_entity(openssl_entity)
        component.add_link(openssl_license)
        component.add_link(compiler)
        component.colloquial_version = colloquial_version
        component.product = "OpenSSL"
        component.type = uswid.uSwidComponentType.LIBRARY
        component.cpe = f"cpe:2.3:a:openssl:openssl:{openssl_version}:*:*:*:*:*:*:*"
        component.version_scheme = uswid.uSwidVersionScheme.SEMVER
        component.edition = f"{architecture}-{target}"
        
        return component, openssl_library_link

    @staticmethod
    def get_openssl_version(ws: Path) -> str:
        # Read the OpenSSL version from VERSION.dat in the OpenSSL submodule
        # and assemble a semver-style version string.
        version_dat = ws / "OpensslPkg" / "Library" / "OpensslLib" / "openssl" / "VERSION.dat"

        fields: dict[str, str] = {}
        for line in version_dat.read_text().splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip().strip('"')

        version = f"{fields['MAJOR']}.{fields['MINOR']}.{fields['PATCH']}"
        if fields.get("PRE_RELEASE_TAG"):
            version += f"-{fields['PRE_RELEASE_TAG']}"
        if fields.get("BUILD_METADATA"):
            version += f"+{fields['BUILD_METADATA']}"
        return version

    @staticmethod
    def get_openssl_sha(ws: Path) -> str:
        """Reads the OpenSSL commit SHA from the git submodule."""
        submodule = ws / "OpensslPkg" / "Library" / "OpensslLib" / "openssl"
        return SbomInserter.get_commit_sha(submodule)

    @staticmethod
    def build_one_crypto_component(ws: Path, lookup: dict, compiler: uswid.uSwidLink) -> tuple[uswid.uSwidComponent, uswid.uSwidLink]:
        """Builds a SBOM component for OneCrypto and a link attribute for self-referencing inside the SBOM.
        
        Args:
            lookup (dict): A dictionary containing the following keys:
                - "ARCHITECTURE": The architecture of the build (e.g., "X64", "AARCH64").
                - "TARGET": The build target (e.g., "DEBUG", "RELEASE").
                - "GUID": The GUID of the OneCrypto Binary EFI file.
                - "EFI_NAME": The name of the OneCrypto Binary EFI file.
                - "VERSION": The current One Crypto Version.
            compiler (uswid.uSwidLink): A uSwidLink object representing the compiler used for the build.
        """
        architecture = lookup["ARCHITECTURE"]
        target = lookup["TARGET"]
        tag_id = lookup["GUID"].lower()
        software_name = lookup["EFI_NAME"]
        software_version = lookup["VERSION"]
        colloquial_version = SbomInserter.get_commit_sha(ws)
        
        phase = ""
        if "Standalone" in software_name:
            phase = "STANDALONE_MM"
        elif "Supv" in software_name:
            phase = "SUPV_MM"
        elif "Dxe" in software_name:
            phase = "DXE"
        else:
            raise ValueError(f"Unknown OneCrypto phase in software name: {software_name}")

        edition = f"{phase}-{architecture}-{target}"

        microsoft_entity = uswid.uSwidEntity(
            name = "Microsoft Corporation",
            regid = "microsoft.com",
            roles = [
                uswid.uSwidEntityRole.SOFTWARE_CREATOR, 
                uswid.uSwidEntityRole.TAG_CREATOR, 
                uswid.uSwidEntityRole.DISTRIBUTOR, 
                uswid.uSwidEntityRole.MAINTAINER
            ]
        )
        
        microsoft_license = uswid.uSwidLink(
            rel=uswid.uSwidLinkRel.LICENSE,
            spdx_id="BSD-2-Clause-Patent",
        )
        
        onecrypto_component_link = uswid.uSwidLink(
            href=f"uswid:{tag_id}",
            rel=uswid.uSwidLinkRel.COMPONENT,
        )
        
        component = uswid.uSwidComponent(
            tag_id,
            tag_version=1,
            software_name=software_name,
            software_version=software_version,
        )
        
        component.add_entity(microsoft_entity)
        component.add_link(microsoft_license)
        component.add_link(compiler)
        component.colloquial_version = colloquial_version
        component.product = "OneCrypto"
        component.version_scheme = uswid.uSwidVersionScheme.SEMVER
        component.edition = edition
        
        return component, onecrypto_component_link

    @staticmethod
    def build_compiler_link(sbom_data: dict) -> uswid.uSwidLink:
        """Builds a SBOM link for the compiler used in the build.
        
        Args:
            sbom_data (dict): A dictionary containing the following keys:
                - "TOOL_CHAIN_TAG": The toolchain tag used for the build (e.g., "CLANGPDB").
        """
        toolchain_tag = sbom_data["TOOL_CHAIN_TAG"]
        
        href = ""
        if "VS" in toolchain_tag:
            href = "https://visualstudio.microsoft.com/"
        elif "CLANG" in toolchain_tag:
            href = "https://clang.llvm.org/"
        elif "GCC" in toolchain_tag:
            href = "https://gcc.gnu.org/"
        else:
            raise ValueError(f"Unknown toolchain tag: {toolchain_tag}")
        
        
        return uswid.uSwidLink(
            href=f"{href}",
            rel=uswid.uSwidLinkRel.COMPILER,
        )

    @staticmethod
    def get_commit_sha(ws: Path) -> str:
        """Read the OneCrypto commit SHA from git in the submodule."""
        out = StringIO()
        ret = RunCmd(
            "git",
            "rev-parse HEAD",
            workingdir=str(ws),
            outstream=out,
            raise_exception_on_nonzero=True,
        )
        if ret != 0:
            raise RuntimeError(f"git rev-parse HEAD failed in {submodule} (rc={ret})")
        return out.getvalue().strip()

    @staticmethod
    def build_sbom_table_entry(payload: bytes, fmt: int, compression: int, flags: int = 0x00) -> bytes:
        """Prepend the EFI_ACPI_SBOM_TABLE_ENTRY header to the payload bytes.

        Header layout (little-endian, packed):
            UINT8  Revision
            UINT16 HeaderLength
            UINT32 PayloadLength
            UINT8  Flags
            UINT8  Format
            UINT8  Compression
        """
        header_struct = struct.Struct("<BHIBBB")
        header = header_struct.pack(
            SBOM_REVISION,
            header_struct.size,
            len(payload),
            flags,
            fmt,
            compression,
        )
        return header + payload

    @staticmethod
    def write_sbom_section(efi_file: Path, sbom_bytes: bytes) -> None:
        """Insert (or replace) a `.sbom` PE section in `efi_file` using llvm-objcopy/objcopy.

        Mirrors uswid's _save_efi_objcopy approach: write the payload to a
        temporary file, then invoke objcopy to remove any existing `.sbom`
        section and add the new one with read-only data flags.
        """
        import shutil
        import subprocess
        import tempfile

        efi_file = Path(efi_file)
        if not efi_file.is_file():
            raise FileNotFoundError(f"EFI file not found: {efi_file}")

        objcopy = shutil.which("llvm-objcopy") or shutil.which("objcopy")
        if not objcopy:
            raise RuntimeError("Neither llvm-objcopy nor objcopy was found on PATH")

        with tempfile.NamedTemporaryFile(suffix=".sbom", delete=False) as tmp:
            tmp.write(sbom_bytes)
            tmp_path = tmp.name

        try:
            subprocess.check_output([
                objcopy,
                "--remove-section=.sbom",
                "--add-section",
                f".sbom={tmp_path}",
                "--set-section-flags",
                ".sbom=contents,alloc,load,readonly,data",
                str(efi_file),
            ])
        except e:
            logging.error(f"failed to insert .sbom section {e}")
        finally:
            os.unlink(tmp_path)

        logging.info("Inserted .sbom section (%d bytes) into %s", len(sbom_bytes), efi_file)
