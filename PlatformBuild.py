# @file PlatformBuild.py
# Script to Build OneCryptoPkg
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import io
import logging

from edk2toolext.environment.uefi_build import UefiBuilder
from edk2toolext.invocables.edk2_platform_build import BuildSettingsManager
from edk2toolext.invocables.edk2_setup import SetupSettingsManager, RequiredSubmodule
from edk2toolext.invocables.edk2_update import UpdateSettingsManager
from edk2toollib.utility_functions import RunCmd


# ####################################################################################### #
#                                Common Configuration                                     #
# ####################################################################################### #
class CommonPlatform():
    ''' Common settings for this platform.  Define static data here and use
        for the different parts of stuart
    '''
    PackagesSupported = ("OneCryptoPkg",)
    ArchSupported = ("X64", "AARCH64")
    TargetsSupported = ("DEBUG", "RELEASE")
    Scopes = ('OneCrypto', 'edk2-build')
    WorkspaceRoot = os.path.dirname(os.path.abspath(__file__))

    @staticmethod
    def GetAllSubmodules():
        rs = []

        # To avoid maintenance of this file for every new submodule
        # lets just parse the .gitmodules and add each if not already in list.
        result = io.StringIO()
        ret = RunCmd("git", "config --file .gitmodules --get-regexp path",
                     workingdir=CommonPlatform.WorkspaceRoot, outstream=result)
        # Cmd output is expected to look like:
        # submodule.MU_BASECORE.path MU_BASECORE
        if ret == 0:
            for line in result.getvalue().splitlines():
                _, _, path = line.partition(" ")
                if path is not None:
                    if path not in [x.path for x in rs]:
                        # add it with recursive since we don't know
                        rs.append(RequiredSubmodule(path, True))
        return rs

    @staticmethod
    def GetAllSubmodulePaths():
        return (sm.path for sm in CommonPlatform.GetAllSubmodules())

    @staticmethod
    def AddCommandLineOptions(parserObj):
        ''' Add command line options to the argparser '''
        valid_archs = ",".join(CommonPlatform.ArchSupported)

        def validate_arch(arch_arg: str):
            archs = tuple(arch.strip() for arch in arch_arg.split(","))
            for arch in archs:
                if arch not in CommonPlatform.ArchSupported:
                    raise ValueError("must be in set: {%s}" % valid_archs)
            return archs
        parserObj.add_argument("-a", "--arch", dest="arch", type=validate_arch,
                               default=valid_archs,
                               help="target architecture(s) for the build {%s}" % valid_archs)


# ####################################################################################### #
#                         Configuration for Update & Setup                                #
# ####################################################################################### #
class SettingsManager(UpdateSettingsManager, SetupSettingsManager):

    def GetPackagesSupported(self):
        ''' return iterable of edk2 packages supported by this build.
        These should be edk2 workspace relative paths '''
        return CommonPlatform.PackagesSupported

    def GetArchitecturesSupported(self):
        ''' return iterable of edk2 architectures supported by this build '''
        return CommonPlatform.ArchSupported

    def GetTargetsSupported(self):
        ''' return iterable of edk2 target tags supported by this build '''
        return CommonPlatform.TargetsSupported

    def GetRequiredSubmodules(self):
        ''' return iterable containing RequiredSubmodule objects.
        If no RequiredSubmodules return an empty iterable
        '''
        return CommonPlatform.GetAllSubmodules()

    def SetArchitectures(self, list_of_requested_architectures):
        ''' Confirm the requests architecture list is valid and configure SettingsManager
        to run only the requested architectures.

        Raise Exception if a list_of_requested_architectures is not supported
        '''
        unsupported = set(list_of_requested_architectures) - \
            set(self.GetArchitecturesSupported())
        if len(unsupported) > 0:
            errorString = (
                "Unsupported Architecture Requested: " + " ".join(unsupported))
            logging.critical(errorString)
            raise Exception(errorString)
        self.ActualArchitectures = list_of_requested_architectures

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        return CommonPlatform.WorkspaceRoot

    def GetActiveScopes(self):
        ''' return tuple containing scopes that should be active for this process '''
        return CommonPlatform.Scopes

    def GetName(self):
        return "OneCryptoPkg"

    def GetPackagesPath(self):
        ''' Return a list of paths that should be mapped as edk2 PackagesPath '''
        return CommonPlatform.GetAllSubmodulePaths()


# ####################################################################################### #
#                         Actual Configuration for Platform Build                         #
# ####################################################################################### #
class PlatformBuilder(UefiBuilder, BuildSettingsManager):
    def __init__(self):
        UefiBuilder.__init__(self)

    def AddCommandLineOptions(self, parserObj):
        ''' Add command line options to the argparser '''
        CommonPlatform.AddCommandLineOptions(parserObj)

        parserObj.add_argument("-t", "--target", dest="target", type=str,
                               default=CommonPlatform.TargetsSupported[0],
                               choices=CommonPlatform.TargetsSupported,
                               help="the target to build (DEBUG or RELEASE)")

    def RetrieveCommandLineOptions(self, args):
        self.target = args.target
        self.arch = args.arch

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        return CommonPlatform.WorkspaceRoot

    def GetPackagesPath(self):
        ''' Return a list of workspace relative paths that should be mapped as edk2 PackagesPath '''
        return CommonPlatform.GetAllSubmodulePaths()

    def GetActiveScopes(self):
        ''' return tuple containing scopes that should be active for this process '''
        return CommonPlatform.Scopes

    def GetName(self):
        ''' Get the name of the repo, platform, or product being built '''
        ''' Used for naming the log file, among others '''
        return "OneCryptoPkg_%s" % self.target

    def GetLoggingLevel(self, loggerType):
        ''' Get the logging level for a given type
        base == lowest logging level supported
        con  == Screen logging
        txt  == plain text file logging
        md   == markdown file logging
        '''
        return super().GetLoggingLevel(loggerType)

    def SetPlatformEnv(self):
        logging.debug("PlatformBuilder SetPlatformEnv")
        self.env.SetValue("PRODUCT_NAME", "OneCrypto", "Platform Hardcoded")
        self.env.SetValue("ACTIVE_PLATFORM", "OneCryptoPkg/OneCryptoPkg.dsc", "Platform Hardcoded")
        self.env.SetValue("OUTPUT_DIRECTORY", "Build/OneCryptoPkg", "Platform Hardcoded")
        self.env.SetValue("TARGET_ARCH", " ".join(self.arch), "CLI args")
        self.env.SetValue("TARGET", self.target, "CLI args")

        # Default turn on build reporting.
        self.env.SetValue("BUILDREPORTING", "TRUE", "Enabling build report")
        self.env.SetValue("BUILDREPORT_TYPES",
                          "PCD DEPEX FLASH BUILD_FLAGS LIBRARY FIXED_ADDRESS HASH",
                          "Setting build report types")

        return 0

    def PlatformPreBuild(self):
        return 0

    def PlatformPostBuild(self):
        # Package the build artifacts after successful build
        logging.critical("=" * 80)
        logging.critical("Running post-build packaging...")

        # Import the packaging script
        import sys
        script_dir = os.path.join(CommonPlatform.WorkspaceRoot, "OneCryptoPkg", "Scripts")
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)

        from package_onecrypto import create_package
        from uefi_compress import analyze_efi_compression
        from pathlib import Path

        # Get the toolchain from environment
        toolchain = self.env.GetValue("TOOL_CHAIN_TAG", "VS2022")
        workspace_root = Path(CommonPlatform.WorkspaceRoot)

        # Package all architectures that were built into a single package
        logging.critical(f"Packaging OneCrypto for {', '.join(self.arch)} {self.target}...")
        result = create_package(
            architectures=self.arch,
            target=self.target,
            toolchain=toolchain
        )
        if result is None:
            logging.error(f"Packaging failed for {self.target}")
        else:
            # Display per-architecture details
            for arch in result.get("architectures", []):
                logging.critical("-" * 60)
                logging.critical(f"[{self.target}/{arch}] OneCryptoBin EFI Sizes (size-critical components):")

                # Collect OneCryptoBin EFI files for this architecture
                onecrypto_bin_files = []
                for file_info in result.get("file_details", []):
                    if file_info.get("arch") == arch and file_info["folder"] == "OneCryptoBin" and file_info["name"].endswith(".efi"):
                        size_kb = file_info["size"] / 1024
                        logging.critical(f"  {file_info['name']}: {file_info['size']:,} bytes ({size_kb:.1f} KB)")
                        onecrypto_bin_files.append(Path(file_info["path"]))

                # UEFI Compression analysis for OneCryptoBin
                if onecrypto_bin_files:
                    compression_results = analyze_efi_compression(onecrypto_bin_files, workspace_root)
                    if compression_results["tool_available"]:
                        logging.critical(f"[{self.target}/{arch}] OneCryptoBin UEFI Compressed Sizes:")
                        for file_info in compression_results["files"]:
                            comp_kb = file_info["compressed_size"] / 1024
                            ratio_pct = file_info["ratio"] * 100
                            logging.critical(f"  {file_info['name']}: {file_info['compressed_size']:,} bytes ({comp_kb:.1f} KB) [{ratio_pct:.1f}%]")

                logging.critical(f"[{self.target}/{arch}] OneCryptoLoaders EFI Sizes:")
                for file_info in result.get("file_details", []):
                    if file_info.get("arch") == arch and file_info["folder"] == "OneCryptoLoaders" and file_info["name"].endswith(".efi"):
                        size_kb = file_info["size"] / 1024
                        logging.critical(f"  {file_info['name']}: {file_info['size']:,} bytes ({size_kb:.1f} KB)")

            logging.critical("-" * 60)
            logging.critical(f"Total uncompressed: {result['total_uncompressed']:,} bytes ({result['total_uncompressed'] / 1024:.1f} KB)")
            logging.critical(f"Compressed (zip): {result['compressed_size']:,} bytes ({result['compressed_size'] / 1024:.1f} KB)")
            logging.critical(f"SHA256: {result['sha256']}")
            logging.critical(f"Package created: {result['path']}")

        logging.critical("=" * 80)
        return 0


if __name__ == "__main__":
    import argparse
    import sys
    from edk2toolext.invocables.edk2_update import Edk2Update
    from edk2toolext.invocables.edk2_setup import Edk2PlatformSetup
    from edk2toolext.invocables.edk2_platform_build import Edk2PlatformBuild

    print("Invoking Stuart")
    print(r"     ) _     _")
    print(r"    ( (^)-~-(^)")
    print(r"__,-.\_( 0 0 )__,-.___")
    print(r"  'W'   \   /   'W'")
    print(r"         >o<")

    SCRIPT_PATH = os.path.relpath(__file__)
    parser = argparse.ArgumentParser(add_help=False)
    parse_group = parser.add_mutually_exclusive_group()
    parse_group.add_argument("--update", "--UPDATE",
                             action='store_true', help="Invokes stuart_update")
    parse_group.add_argument("--setup", "--SETUP",
                             action='store_true', help="Invokes stuart_setup")
    args, remaining = parser.parse_known_args()
    new_args = ["stuart", "-c", SCRIPT_PATH]
    new_args = new_args + remaining
    sys.argv = new_args

    if args.setup:
        print("Running stuart_setup -c " + SCRIPT_PATH)
        Edk2PlatformSetup().Invoke()
    elif args.update:
        print("Running stuart_update -c " + SCRIPT_PATH)
        Edk2Update().Invoke()
    else:
        print("Running stuart_build -c " + SCRIPT_PATH)
        Edk2PlatformBuild().Invoke()
