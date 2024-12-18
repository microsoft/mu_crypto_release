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

class ReportCrypto(IUefiBuildPlugin):

    def do_post_build(self, thebuilder):
        
        # get branch name

        # Path to Build output
        build_path = Path(thebuilder.env.GetValue("BUILD_OUTPUT_BASE"))
        tool_chain = thebuilder.env.GetValue("TOOL_CHAIN_TAG")
        target = thebuilder.env.GetValue("TARGET")
        # Create report file in the build directory
        report_file_name = f"Report_{thebuilder.flavor}_{target}_{tool_chain}.txt"
        report_File = Path(thebuilder.ws) / "Build" / report_file_name
        report_File.touch()
        arch_list = thebuilder.env.GetValue("TARGET_ARCH")

        # Time and Title
        title = f"CRYPTO BINARIES REPORT - {thebuilder.flavor} FLAVOR - {target}\n\n"
        time = datetime.now().strftime('%Y-%m-%d %H:%M:%S\n')
        report = [title, "Build Time: " + time]

        # get current branch
        repo = Repo(thebuilder.ws)
        branch = repo.active_branch
        commit = repo.active_branch.commit
        report.append(f"Branch: {branch.name} | Commit: {commit}\n")
        
        # get tool chain
        report.append(f"Tool Chain: {tool_chain}\n")

        # start binaries sizes report
        report.append("=============================================\n")
        report.append("<------Crypto binaries sizes report------>\n\n")

        # For each architecture built
        for arch in arch_list.split(" "):
            arch_build_path = build_path / arch
            # write flavor and architecture name to report file
            report += ["--------------------------------\n", "ARCH: " + arch + "\n\n"]
            # get built binaries
            files = list(arch_build_path.glob("*.efi"))
            files.sort()
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
                    # log to file (assuming file name won't be longer than 30 characters to keep the report clean)
                    report.append(f"{file.name} - " + (30-len(file.name))* " " + f"Uncompressed: {file_size:.2f} KB | LZMA Compressed: {compressed_data_size:.2f} KB\n")
          
        # start openssl configuration report
        report.append("=============================================\n")
        report.append("<------Openssl configuration report------>\n")
     
        # get openssl library files 
        openssl_lib = Path(thebuilder.edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath("OpensslPkg")) / "Library" / "OpensslLib"
        openssl_inf_files = list(openssl_lib.glob("OpensslLib*.inf"))
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