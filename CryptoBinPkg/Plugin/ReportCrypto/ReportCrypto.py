## @file BundleCrypto.py
# Plugin to Bundle the CryptoBin build output
#
##
# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
from edk2toolext.environment.plugintypes.uefi_build_plugin import IUefiBuildPlugin
from pathlib import Path
from datetime import datetime
from git import Repo
import lzma

# Dictionaries
binary_to_type = {}
arch_and_type_to_lib = {}

# defines
offset = 40

class ReportCrypto(IUefiBuildPlugin):
    """
    ReportCrypto is a plugin class that generates a report about the crypto binaries built during the build process.
    The report includes the next information:
    - Submodules information
    - Built binaries sizes
    - Linked OpenSSL library for each binary
    - OpenSSL library flags
    Methods:
    --------
    do_post_build(thebuilder):
        Generates a report file in the build directory containing information about the build process, 
        submodules, built binaries, and linked OpenSSL configuration.
    get_openssl_flags(file):
        Extracts OpenSSL library flags from the given .inf file.
    get_module_type_for_crypto_bin():
        Retrieves the module type (DXE_DRIVER, PEIM, etc.) for each crypto binary from the .inf files in the CryptoBinPkg Driver path.
    get_linked_lib(arch, module_type, lib):
        Determines the linked library configuration for the specified architecture and module type from the CryptoBinPkg.dsc file.
    """

    def do_post_build(self, thebuilder):
        ### Initiazlize variables ###

        # get needed paths
        openssl_lib_path = Path(thebuilder.edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath("OpensslPkg")) / "Library" / "OpensslLib"
        CryptoBinPkg_Driver_path = Path(thebuilder.ws) / "CryptoBinPkg" / "Driver"
        cryptoBinPkg_dsc_path = Path(thebuilder.ws) / "CryptoBinPkg" / "CryptoBinPkg.dsc"
        repo = Repo(thebuilder.ws)

        # Path to Build output
        build_path = Path(thebuilder.env.GetValue("BUILD_OUTPUT_BASE"))
        tool_chain = thebuilder.env.GetValue("TOOL_CHAIN_TAG")
        target = thebuilder.env.GetValue("TARGET")
        # 
        # Create report file in the build directory
        report_file_name = f"Report_{thebuilder.flavor}_{target}_{tool_chain}.txt"
        report_File = Path(thebuilder.ws) / "Build" / report_file_name
        report_File.touch()
        arch_list = thebuilder.env.GetValue("TARGET_ARCH")

        # Time and Title
        title = f"CRYPTO BINARIES REPORT - {thebuilder.flavor} FLAVOR - {target}\n\n"
        time = datetime.now().strftime('%Y-%m-%d %H:%M:%S\n')
        report = [title, "Build Time: " + time]

        # get tool chain
        report.append(f"Tool Chain: {tool_chain}\n")

        # get each CryptoBin module type
        self.get_module_type_for_crypto_bin(CryptoBinPkg_Driver_path)

        report.append("=============================================\n")
        # get submodules information
        report.append("<------Submodules------>\n")

        for sub in repo.submodules:
            report.append("--------\n")
            report.append(f"Name: {sub.name}\n")
            report.append(f"Branch: {sub.branch_name}\n")
            report.append(f"Commit: {sub.hexsha}\n")

        report.append("=============================================\n")
        # For each architecture built
        for arch in arch_list.split(" "):
            arch_build_path = build_path / arch
            # write flavor and architecture name to report file
            report += ["--------------------------------\n", "ARCH: " + arch + "\n\n"]

            # get built binaries
            files = list(arch_build_path.glob("*.efi"))
            files.sort()

            # start binaries sizes report
            report.append("<------Crypto binaries sizes report------>\n\n")
            for file in files:
                # get file size in k bytes
                file_size = file.stat().st_size / 1024

                # get compressed file size using LMZA
                with open(file, 'rb') as input_file:
                    # Read the content of the input files
                    input_data = input_file.read()
                    # Compress the data using LZMA
                    compressed_data = lzma.compress(input_data)

                    # Get the number of k bytes of the compressed data
                    compressed_data_size = len(compressed_data) / 1024
                    # log to file (try to use offset to align the data)
                    if offset < len(file.name):
                        report.append(f"{file.name} - " + f"Uncompressed: {file_size:.2f} KB | LZMA Compressed: {compressed_data_size:.2f} KB\n")
                    report.append(f"{file.name} - " + (offset-len(file.name))* " " + f"Uncompressed: {file_size:.2f} KB | LZMA Compressed: {compressed_data_size:.2f} KB\n")

            # get linked openssl configuration
            report.append("\n")   
            report.append("<------Linked Openssl configuration------>\n\n")
            for file in files:
                # get module type for the binary
                module_type = binary_to_type.get(file.name, "UEFI_APPLICATION") # Default to UEFI_APPLICATION if not found (e.g. test binary)
                opensslib = self.get_linked_lib(arch, module_type, "OpensslLib", cryptoBinPkg_dsc_path)
                # log to file (try to use offset to align the data)
                if offset < len(file.name):
                    report.append(f"{file.name} - " + f"OpensslLib: {opensslib}\n")
                report.append(f"{file.name} - " + (offset-len(file.name))* " " + f"OpensslLib: {opensslib}\n")


        # start openssl configuration report
        report.append("=============================================\n")
        report.append("<------Openssl configuration report------>\n")

        # get openssl library files 
        openssl_inf_files = list(openssl_lib_path.glob("OpensslLib*.inf"))
        openssl_inf_files.sort()
        for file in openssl_inf_files:
            # write openssl library files to report file
            openssl_flags = self.get_openssl_flags(file)
            report.append("--------\n")
            report.append("File: " + file.name + "\n")
            report.extend(openssl_flags)

        report.append("=============================================\n")

        # write report to the report file
        report_File.write_text("".join(report))

        return 0

    def get_openssl_flags(self, file):

        # get openssl library flags
        flags = []
        with file.open() as f:
            for line in f:
                if "DEFINE OPENSSL_FLAGS" in line:
                    flags.append(line)
        return flags

    def get_module_type_for_crypto_bin(self, CryptoBinPkg_Driver_path):

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

    def get_linked_lib(self, arch, module_type, lib, cryptoBinPkg_dsc_path):

        with cryptoBinPkg_dsc_path.open() as f:
            current_key = None
            # there are 3 possible lib configuarions for the crypto binaries: "[LibraryClasses] (default)", "LibraryClasses.common.{module_type}" and "[LibraryClasses.arch.module_type] (most specific)"
            default = ""
            common_type = ""
            arch_type = ""
            for line in f:
                if "[LibraryClasses]" in line:
                    current_key = "Default"
                elif "[LibraryClasses" in line:
                    current_key = line
                if f"{lib}|" in line:
                    specific_lib = line.split("|")[1].strip()
                    if current_key == "Default":
                        default = specific_lib            
                    else:
                        if f"{arch}.{module_type}" in current_key:
                            arch_type = specific_lib
                        elif f"common.{module_type}" in current_key:
                            common_type = specific_lib

            if arch_type != "":
                return arch_type
            elif common_type != "":
                return common_type
            else:
                return default
