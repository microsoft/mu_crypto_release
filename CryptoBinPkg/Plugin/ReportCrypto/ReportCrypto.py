## @file BundleCrypto.py
# Plugin to Bundle the CryptoBin build output
#
##

from edk2toolext.environment.plugintypes.uefi_build_plugin import IUefiBuildPlugin
from pathlib import Path
from datetime import datetime
from git import Repo
import lzma
from edk2toollib.uefi.edk2.parsers.dsc_parser import DscParser

binary_to_type = {}
arch_and_type_to_lib = {}
offset = 40

class ReportCrypto(IUefiBuildPlugin):
    """
    ReportCrypto is a plugin class that generates a report about the crypto binaries built during the build process.
    The report includes the next information:
    - Submodules information
    - Built binaries sizes
    - Linked OpenSSL library for each binary
    - OpenSSL library flags
    """
    def do_post_build(self, thebuilder):
        """
        Generates a report file in the build directory containing information about the build process, 
        submodules, built binaries, and linked OpenSSL configuration.
        """
        ### Initialize variables ###

        openssl_lib_path = Path(thebuilder.edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath("OpensslPkg", "Library", "OpensslLib"))
        CryptoBinPkg_Driver_path = Path(thebuilder.ws) / "CryptoBinPkg" / "Driver"
        repo = Repo(thebuilder.ws)

        build_path = Path(thebuilder.env.GetValue("BUILD_OUTPUT_BASE"))
        tool_chain = thebuilder.env.GetValue("TOOL_CHAIN_TAG")
        target = thebuilder.env.GetValue("TARGET")

        report_file_name = f"Report_{thebuilder.flavor}_{target}_{tool_chain}.txt"
        report_File = Path(thebuilder.ws) / "Build" / report_file_name
        report_File.touch()
        arch_list = thebuilder.env.GetValue("TARGET_ARCH")

        title = f"CRYPTO BINARIES REPORT - {thebuilder.flavor} FLAVOR - {target}\n\n"
        time = datetime.now().strftime('%Y-%m-%d %H:%M:%S\n')
        report = [title, "Build Time: " + time]

        report.append(f"Tool Chain: {tool_chain}\n")
        self.get_module_type_for_crypto_bin(CryptoBinPkg_Driver_path)
        report.append("=============================================\n")

        report.append("<------Submodules------>\n")

        for sub in repo.submodules:
            report.append("--------\n")
            report.append(f"Name: {sub.name}\n")
            report.append(f"Branch: {sub.branch_name}\n")
            report.append(f"Commit: {sub.hexsha}\n")

        report.append("=============================================\n")

        for arch in arch_list.split(" "):
            arch_build_path = build_path / arch
            report += ["--------------------------------\n", "ARCH: " + arch + "\n\n"]

            files = list(arch_build_path.glob("*.efi"))
            files.sort()

            report.append("<------Crypto binaries sizes report------>\n\n")
            for file in files:
                # get file size in k bytes
                file_size = file.stat().st_size / 1024

                # get compressed file size using LMZA
                with open(file, 'rb') as input_file:
                    input_data = input_file.read()
                    compressed_data = lzma.compress(input_data)
                    compressed_data_size = len(compressed_data) / 1024

                    if offset < len(file.name):
                        report.append(f"{file.name} - " + f"Uncompressed: {file_size:.2f} KB | LZMA Compressed: {compressed_data_size:.2f} KB\n")
                    report.append(f"{file.name} - " + (offset-len(file.name))* " " + f"Uncompressed: {file_size:.2f} KB | LZMA Compressed: {compressed_data_size:.2f} KB\n")
 
            report.append("\n<------Linked Openssl configuration------>\n\n")
            for file in files:
                # get module type for the binary
                module_type = binary_to_type.get(file.name, "UEFI_APPLICATION") # Default to UEFI_APPLICATION if not found (e.g. test binary)
                opensslib = self.get_linked_lib(arch, module_type, "OpensslLib", thebuilder)

                if offset < len(file.name):
                    report.append(f"{file.name} - " + f"OpensslLib: {opensslib}\n")
                report.append(f"{file.name} - " + (offset-len(file.name))* " " + f"OpensslLib: {opensslib}\n")

        report.append("=============================================\n")
        report.append("<------Openssl configuration report------>\n")

        openssl_inf_files = list(openssl_lib_path.glob("OpensslLib*.inf"))
        openssl_inf_files.sort()
        for file in openssl_inf_files:
            openssl_flags = self.get_openssl_flags(file)
            report.append("--------\n")
            report.append("File: " + file.name + "\n")
            report.extend(openssl_flags)

        report.append("=============================================\n")
        report_File.write_text("".join(report))

        return 0

    def get_openssl_flags(self, file):
        """
        Extracts OpenSSL library flags from the given .inf file.
        """
        flags = []
        with file.open() as f:
            for line in f:
                if "DEFINE OPENSSL_FLAGS" in line:
                    flags.append(line)
        return flags

    def get_module_type_for_crypto_bin(self, CryptoBinPkg_Driver_path):
        """
        Retrieves the module type (DXE_DRIVER, PEIM, etc.) for each crypto binary from the .inf files in the CryptoBinPkg Driver path.
        """
        inf_files = list(CryptoBinPkg_Driver_path.glob("*.inf"))
        for inf_file in inf_files:
            base_name = ""
            module_type = ""
            with inf_file.open() as f:
                for line in f:
                    if "BASE_NAME" in line:
                        base_name = line.split("=")[1].strip()
                    if "MODULE_TYPE" in line:
                        module_type = line.split("=")[1].strip()
                    if base_name != "" and module_type != "":
                        binary_to_type[f"{base_name}.efi"] = module_type # start binaries sizes report
                        break

    def get_linked_lib(self, arch, module_type, lib, thebuilder):
        """
        Determines the linked library configuration for the specified architecture and module type from the active dsc file.
        """
        ActiveDsc = thebuilder.edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath(thebuilder.env.GetValue("ACTIVE_PLATFORM"))
        dsc_parser = DscParser()
        dsc_parser.SetEdk2Path(thebuilder.edk2path)
        env_vars = thebuilder.env.GetAllBuildKeyValues()
        dsc_parser.SetInputVars(env_vars).ParseFile(ActiveDsc)
        print("ScopedLibraryDict: ", dsc_parser.ScopedLibraryDict)

        arch_scoped_config = f"{arch}.{module_type}.{lib}".lower() # most specific
        moduleType_scoped_config = f"common.{module_type}.{lib}".lower()
        common_scoped_config = f"common.{lib}".lower() # common for all module types

        if arch_scoped_config in dsc_parser.ScopedLibraryDict:
            print("here1")
            return dsc_parser.ScopedLibraryDict[arch_scoped_config][0]
        elif moduleType_scoped_config in dsc_parser.ScopedLibraryDict:
            print("here2")
            return dsc_parser.ScopedLibraryDict[moduleType_scoped_config][0]
        elif common_scoped_config in dsc_parser.ScopedLibraryDict:
            print("here3")
            return dsc_parser.ScopedLibraryDict[common_scoped_config][0]