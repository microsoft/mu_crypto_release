# @file SingleFlavorBuild.py
# Script to Build a Single Flavor and Target of CryptoBin
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import logging

from edk2toolext.environment.uefi_build import UefiBuilder
from edk2toolext.invocables.edk2_platform_build import BuildSettingsManager

from CommonBuildSettings import CommonPlatform, CommonSettingsManager, crypto_platforms, validate_platform_option


# ####################################################################################### #
#                         Configuration for Update & Setup                                #
# ####################################################################################### #
class SingleSettingsManager(CommonSettingsManager):
    # Just use the common configuration.
    pass


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
                               help="the target to build for the Crypto binary distribution")

        parserObj.add_argument("-b", "--bundle", dest="bundle", action="store_true",
                               default=False,
                               help="Bundles the build output into the directory structure for the Crypto binary distribution.")

        subparsers = parserObj.add_subparsers(dest="active_platform", help="Sub-commands for active platform", required=True)

        # Add a subparser for each active platform
        for platform_name, platform_info in crypto_platforms.items():
            subparser = subparsers.add_parser(platform_name, help=f"Options for {platform_name}")
            if "custom_settings" in platform_info:
                for setting in platform_info["custom_settings"]:
                    setting_info = platform_info["custom_settings"][setting]
                    if setting == "flavor":
                        subparser.add_argument(f"--{setting}", type=setting_info["type"], choices=setting_info["supported_flavors"], required=True, help=setting_info["help"])
                    else:
                        raise ValueError(f"Unknown custom setting: {setting}")

        # TODO for some reason the subparsers are not being added to the help output


    def RetrieveCommandLineOptions(self, args):
        self.flavor = args.flavor
        self.target = args.target
        self.arch = args.arch
        self.bundle = args.bundle
        self.active_platform = crypto_platforms[args.active_platform]["ACTIVE_PLATFORM"]
        self.product_name = crypto_platforms[args.active_platform]["PRODUCT_NAME"]

    def GetWorkspaceRoot(self):
        ''' get WorkspacePath '''
        return CommonPlatform.WorkspaceRoot

    def GetPackagesPath(self):
        ''' Return a list of workspace relative paths that should be mapped as edk2 PackagesPath '''
        return CommonPlatform.GetAllSubmodulePaths()

    def GetActiveScopes(self):
        ''' return tuple containing scopes that should be active for this process '''
        if self.bundle:
            return CommonPlatform.Scopes + ("crypto-bundle",)
        return CommonPlatform.Scopes

    def GetBaseName(self):
        return "CryptoBin_%s" % self.flavor

    def GetName(self):
        ''' Get the name of the repo, platform, or product being built '''
        ''' Used for naming the log file, among others '''
        return "%s_%s" % (self.GetBaseName(), self.target)

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
        self.env.SetValue("PRODUCT_NAME", self.product_name, "Platform Hardcoded")
        self.env.SetValue("ACTIVE_PLATFORM", self.active_platform, "Platform Hardcoded")
        self.env.SetValue("BLD_%s_OUTPUT_SUB_DIRECTORY" % self.target, self.GetBaseName(), "Platform Hardcoded")
        self.env.SetValue("OUTPUT_DIRECTORY", "Build/%s" % self.GetBaseName(), "Platform Hardcoded")
        self.env.SetValue("TARGET_ARCH", " ".join(self.arch), "CLI args")
        self.env.SetValue("TARGET", self.target, "CLI args")
        self.env.SetValue("BLD_*_CRYPTO_SERVICES", self.flavor, "CLI args")
        self.env.SetValue("BLD_*_SHARED_CRYPTO_PATH", "CryptoBinPkg", "Platform Hardcoded")

        # Default turn on build reporting.
        self.env.SetValue("BUILDREPORTING", "TRUE", "Enabling build report")
        self.env.SetValue("BUILDREPORT_TYPES",
                          "PCD DEPEX FLASH BUILD_FLAGS LIBRARY FIXED_ADDRESS HASH",
                          "Setting build report types")

        return 0

    def PlatformPreBuild(self):
        return 0

    def PlatformPostBuild(self):
        return 0


if __name__ == "__main__":
    import argparse
    import sys
    from edk2toolext.invocables.edk2_update import Edk2Update
    from edk2toolext.invocables.edk2_setup import Edk2PlatformSetup
    from edk2toolext.invocables.edk2_platform_build import Edk2PlatformBuild
    print("Invoking Stuart")
    print("     ) _     _")
    print("    ( (^)-~-(^)")
    print("__,-.\_( 0 0 )__,-.___")         # noqa
    print("  'W'   \   /   'W'")            # noqa
    print("         >o<")
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
