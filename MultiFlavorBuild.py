# @file SingleFlavorBuild.py
# Script to Build a Single Flavor and Target of CryptoBin
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import logging

from edk2toolext import edk2_logging
from edk2toolext.environment import shell_environment
from edk2toolext.environment.uefi_build import UefiBuilder
from edk2toolext.invocables.edk2_platform_build import BuildSettingsManager
from edk2toollib.utility_functions import RunPythonScript

from CommonBuildSettings import CommonPlatform, CommonSettingsManager, crypto_platforms, validate_platform_option


# ####################################################################################### #
#                         Configuration for Update & Setup                                #
# ####################################################################################### #
class MultiSettingsManager(CommonSettingsManager):
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

        parserObj.add_argument("--stop-on-fail", dest="stop", action="store_true",
                               default=False,
                               help="halt all builds on the first build failure")

        def validate_list(list_arg: str, valid_list: list):
            valid_items = ",".join(valid_list)
            items = tuple(item.strip() for item in list_arg.split(","))
            for item in items:
                if item not in valid_list:
                    raise ValueError("must be in set: {%s}" % valid_items)
            return items

        def validate_targets(target_arg: str):
            return validate_list(target_arg, CommonPlatform.TargetsSupported)

        def validate_flavors(flavor_arg: str):
            return validate_list(flavor_arg, CommonPlatform.AvailableFlavors)


        parserObj.add_argument("-t", "--target", dest="target", type=validate_targets,
                               default=CommonPlatform.TargetsSupported,
                               help="build target(s) for the build {%s}" % ",".join(CommonPlatform.TargetsSupported))
        
        parserObj.add_argument("-f", "--flavor", dest="flavor", type=validate_flavors,
                               default=CommonPlatform.AvailableFlavors,
                               help="flavor(s) for the build {%s}" % ",".join(CommonPlatform.AvailableFlavors))
        parserObj.add_argument("-b", "--bundle", dest="bundle", action="store_true",
                               default=False,
                               help="Bundles the build output into the directory structure for the Crypto binary distribution.")
        parserObj.add_argument("--active-platform",
                               dest="active_platform",
                               choices=crypto_platforms.keys(),
                               default="CryptoBinPkg",
                               type=validate_platform_option,
                               help="the active platform to build for the Crypto binary distribution")

    def RetrieveCommandLineOptions(self, args):
        self.arch = args.arch
        self.target = args.target
        self.flavor = args.flavor
        self.stop = args.stop
        self.bundle = args.bundle
        self.active_platform = args.active_platform

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
        return "MultiCryptoBin"

    def GetLoggingLevel(self, loggerType):
        ''' Get the logging level for a given type
        base == lowest logging level supported
        con  == Screen logging
        txt  == plain text file logging
        md   == markdown file logging
        '''
        return super().GetLoggingLevel(loggerType)

    def Go(self, WorkSpace, PackagesPath, PInHelper, PInManager):
        toolchain = shell_environment.GetBuildVars().GetValue("TOOL_CHAIN_TAG")
        if toolchain is None:
            toolchain = "VS2022"
        overall_success = True
        for flavor in self.flavor:
            for target in self.target:
                arches = []
                use_gcc = False
                for arch in self.arch:
                    if arch != "AARCH64":
                        arches.append(arch)
                    else:
                        use_gcc = True
                if len(arches) > 0:
                    params = [flavor]
                    params += [f"TOOL_CHAIN_TAG={toolchain}"]
                    params += ["-t", target]
                    params += ["-a", ",".join(arches)]
                    if self.bundle:
                        params += ["-b"]

                    current_build = f"{flavor} {target}"
                    logging.log(edk2_logging.SECTION, f"Building {current_build}")

                    ret = RunPythonScript("SingleFlavorBuild.py", " ".join(params), workingdir=self.GetWorkspaceRoot())

                    if ret == 0:
                        logging.log(edk2_logging.PROGRESS, f"{current_build} Success")
                    else:
                        logging.error(f"{current_build} FAILED")
                        overall_success = False
                        if self.stop:
                            break
                if use_gcc:
                    params = [flavor]
                    params += [f"TOOL_CHAIN_TAG=GCC5"]
                    params += ["-t", target]
                    params += ["-a", "AARCH64"]
                    if self.bundle:
                        params += ["-b"]

                    current_build = f"{flavor} {target}"
                    logging.log(edk2_logging.SECTION, f"Building {current_build}")

                    ret = RunPythonScript("SingleFlavorBuild.py", " ".join(params), workingdir=self.GetWorkspaceRoot())

                    if ret == 0:
                        logging.log(edk2_logging.PROGRESS, f"{current_build} Success")
                    else:
                        logging.error(f"{current_build} FAILED")
                        overall_success = False
                        if self.stop:
                            break
            else:
                continue    # Allow the break to exit both loops.
            break           # Allow the break to exit both loops.

        return 0 if overall_success else -1


if __name__ == "__main__":
    import argparse
    import sys
    from edk2toolext.invocables.edk2_update import Edk2Update
    from edk2toolext.invocables.edk2_setup import Edk2PlatformSetup
    from edk2toolext.invocables.edk2_platform_build import Edk2PlatformBuild
    print("Invoking Stuart")
    print(r"     ) _     _")
    print(r"    ( (^)-~-(^)")
    print(r"__,-.\_( 0 0 )__,-.___")         # noqa
    print(r"  'W'   \   /   'W'")            # noqa
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
