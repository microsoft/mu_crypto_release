## @file
#  Cryptographic Library Package for UEFI Security Implementation.
#  PEIM, DXE Driver, and SMM Driver with all crypto services enabled.
#
#  Copyright (c) 2009 - 2021, Intel Corporation. All rights reserved.<BR>
#  Copyright (c) 2020, Hewlett Packard Enterprise Development LP. All rights reserved.<BR>
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

################################################################################
#
# Defines Section - statements that will be processed to create a Makefile.
#
################################################################################
[Defines]
  PLATFORM_NAME                  = OpensslPkg
  PLATFORM_GUID                  = 3f2504e0-4f89-11d3-9a0c-0305e82c3301
  PLATFORM_VERSION               = 0.98
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/OpensslPkg
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
  SKUID_IDENTIFIER               = DEFAULT

################################################################################
#
# Library Class section - list of all Library Classes needed by this Platform.
#
################################################################################

!include MdePkg/MdeLibs.dsc.inc


[PcdsPatchableInModule]
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x17

[PcdsFixedAtBuild]
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80080246
  #gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x800002CF # use when debugging depex loading issues
  gEfiMdePkgTokenSpaceGuid.PcdFixedDebugPrintErrorLevel|gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel

[LibraryClasses]
  #
  # BE VERY CAREFUL PUTTING ANYTHING HERE
  # We need to be very specific with our dependencies
  #

[LibraryClasses.common.MM_STANDALONE]
  UefiBootServicesTableLib    |MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  BaseLib                     |OneCryptoPkg/Library/MinimalBaseLib/MinimalBaseLib.inf # Minimal BaseLib to satisfy dependencies
  BaseMemoryLib               |OneCryptoPkg/Library/MinimalBaseMemoryLib/MinimalBaseMemoryLib.inf
  BasePrintLib                |OneCryptoPkg/Library/MinimalBasePrintLib/MinimalBasePrintLib.inf
  MmServicesTableLib          |MmSupervisorPkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
  StandaloneMmDriverEntryPoint|OneCryptoPkg/Library/BaseStandaloneMmDriverEntryPoint/BaseStandaloneMmDriverEntryPoint.inf
  PcdLib                      |MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf # Required for UEFI applications - NULL implementation
  DebugLib                    |MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf # Required for UEFI applications - NULL implementation
  
  # TODO - what to do in an agnostic way
  # NULL                        |MdePkg/Library/StackCheckLib/StackCheckLibStaticInit.inf
  IntrinsicLib                |OpensslPkg/Library/IntrinsicLib/IntrinsicLib.inf
  FltUsedLib                  |MdePkg/Library/FltUsedLib/FltUsedLib.inf
  OpensslLib                  |OpensslPkg/Library/OpensslLib/OpenssLibShared.inf




###################################################################################################
#
# Components Section - list of the modules and components that will be processed by compilation
#                      tools and the EDK II tools to generate PE32/PE32+/Coff image files.
#
# Note: The EDK II DSC file is not used to specify how compiled binary images get placed
#       into firmware volume images. This section is just a list of modules to compile from
#       source into UEFI-compliant binaries.
#       It is the FDF file that contains information on combining binary files into firmware
#       volume images, whose concept is beyond UEFI and is described in PI specification.
#       Binary modules do not need to be listed in this section, as they should be
#       specified in the FDF file. For example: Shell binary (Shell_Full.efi), FAT binary (Fat.efi),
#       Logo (Logo.bmp), and etc.
#       There may also be modules listed in this section that are not required in the FDF file,
#       When a module listed here is excluded from FDF file, then UEFI-compliant binary will be
#       generated for it, but the binary will not be put into any firmware volume.
#
###################################################################################################
[Components]
  OpensslPkg/SharedCryptoBin/SharedCryptoMmBin.inf

[BuildOptions]
  *_*_*_CC_FLAGS = -D DISABLE_NEW_DEPRECATED_INTERFACES
  # Disable security features to avoid linker issues with minimal dependencies
  MSFT:*_*_*_CC_FLAGS = /GS-
  MSFT:*_*_*_DLINK_FLAGS = /IGNORE:4217
!if $(CRYPTO_SERVICES) IN "PACKAGE ALL"
  MSFT:*_*_*_CC_FLAGS = /D ENABLE_MD5_DEPRECATED_INTERFACES
  INTEL:*_*_*_CC_FLAGS = /D ENABLE_MD5_DEPRECATED_INTERFACES
  GCC:*_*_*_CC_FLAGS = -D ENABLE_MD5_DEPRECATED_INTERFACES
  RVCT:*_*_*_CC_FLAGS = -DENABLE_MD5_DEPRECATED_INTERFACES
!endif


[BuildOptions.common.EDKII.DXE_RUNTIME_DRIVER, BuildOptions.common.EDKII.DXE_SMM_DRIVER, BuildOptions.common.EDKII.SMM_CORE, BuildOptions.common.EDKII.DXE_DRIVER]
  MSFT:*_*_IA32_DLINK_FLAGS = /ALIGN:4096 # enable 4k alignment for MAT and other protections.
  MSFT:*_*_X64_DLINK_FLAGS = /ALIGN:4096 # enable 4k alignment for MAT and other protections.
