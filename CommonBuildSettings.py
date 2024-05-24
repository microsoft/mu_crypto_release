# @file CommonBuildSettings.py
# Settings and configurations that are common to both
# SingleFlavorBuild.py and MultiFlavorBuild.py
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import io
import os
import logging

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
    BaseName = "CryptoBin"
    PackagesSupported = ("CryptoBinPkg",)
    ArchSupported = ("IA32", "X64", "AARCH64")
    TargetsSupported = ("DEBUG", "RELEASE")
    Scopes = ('cryptobin', 'edk2-build')
    # TODO: Maybe load this from the supported flavors in MU_BASECORE\CryptoPkg\Driver\Packaging modules?
    AvailableFlavors = ('ALL', 'TINY_SHA', 'MINIMAL_SHA_SM3', 'SMALL_SHA_RSA', 'STANDARD')
    WorkspaceRoot = os.path.dirname(os.path.abspath(__file__))

    def GetAllSubmodules():
        rs = []

        # To avoid maintenance of this file for every new submodule
        # lets just parse the .gitmodules and add each if not already in list.
        # The GetRequiredSubmodules is designed to allow a build to optimize
        # the desired submodules but it isn't necessary for this repository.
        result = io.StringIO()
        ret = RunCmd("git", "config --file .gitmodules --get-regexp path",
                     workingdir=CommonPlatform.WorkspaceRoot, outstream=result)
        # Cmd output is expected to look like:
        # submodule.CryptoPkg/Library/OpensslLib/openssl.path CryptoPkg/Library/OpensslLib/openssl
        # submodule.SoftFloat.path ArmPkg/Library/ArmSoftFloatLib/berkeley-softfloat-3
        if ret == 0:
            for line in result.getvalue().splitlines():
                _, _, path = line.partition(" ")
                if path is not None:
                    if path not in [x.path for x in rs]:
                        # add it with recursive since we don't know
                        rs.append(RequiredSubmodule(path, True))
        return rs

    def GetAllSubmodulePaths():
        return (sm.path for sm in __class__.GetAllSubmodules())

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
class CommonSettingsManager(UpdateSettingsManager, SetupSettingsManager):

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
        return CommonPlatform.BaseName

    def GetPackagesPath(self):
        ''' Return a list of paths that should be mapped as edk2 PackagesPath '''
        return CommonPlatform.GetAllSubmodulePaths()
