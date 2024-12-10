## @file
#  Cryptographic Library Package for UEFI Security Implementation.
#  PEIM, DXE Driver, and SMM Driver with all crypto services enabled.
#
#  Copyright (c) Microsoft Corporation. All rights reserved.
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
  PLATFORM_NAME                  = CryptoBinPkg
  PLATFORM_GUID                  = 5595080B-F41F-454B-A058-1A0C07D23F7B
  PLATFORM_VERSION               = 0.98
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/$(OUTPUT_SUB_DIRECTORY)   # Will be updated by platform build script.
  SUPPORTED_ARCHITECTURES        = IA32|X64|ARM|AARCH64
  BUILD_TARGETS                  = DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT

!include CryptoBinPkg/Driver/Bin/Crypto.inc.dsc

!include UnitTestFrameworkPkg/UnitTestFrameworkPkgTarget.dsc.inc

# Note: MdeLibs.dsc.inc cannot be included right now due to X64 PEI build issues.

################################################################################
#
# Library Class section - list of all Library Classes needed by this Platform.
#
################################################################################
[LibraryClasses]
  ArmLib|ArmPkg/Library/ArmLib/ArmBaseLib.inf
  ArmTrngLib|MdePkg/Library/BaseArmTrngLibNull/BaseArmTrngLibNull.inf
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  CpuLib|MdePkg/Library/BaseCpuLib/BaseCpuLib.inf
  DebugLib|MdeModulePkg/Library/PeiDxeDebugLibReportStatusCode/PeiDxeDebugLibReportStatusCode.inf
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  FltUsedLib|MdePkg/Library/FltUsedLib/FltUsedLib.inf
  HashApiLib|CryptoPkg/Library/BaseHashApiLib/BaseHashApiLib.inf
  HmacSha1Lib|OpensslPkg/Library/HmacSha1Lib/HmacSha1Lib.inf
  IntrinsicLib|OpensslPkg/Library/IntrinsicLib/IntrinsicLib.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  MmServicesTableLib|MdePkg/Library/MmServicesTableLib/MmServicesTableLib.inf
  OemHookStatusCodeLib|MdeModulePkg/Library/OemHookStatusCodeLibNull/OemHookStatusCodeLibNull.inf
  OpensslLib|OpensslPkg/Library/OpensslLib/OpensslLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
  RngLib|MdePkg/Library/BaseRngLib/BaseRngLib.inf
  SafeIntLib|MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
  SmmCpuRendezvousLib|MdePkg/Library/SmmCpuRendezvousLibNull/SmmCpuRendezvousLibNull.inf
  StackCheckFailureHookLib|MdePkg/Library/StackCheckFailureHookLibNull/StackCheckFailureHookLibNull.inf
  SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  TimerLib|MdePkg/Library/BaseTimerLibNullTemplate/BaseTimerLibNullTemplate.inf
  TlsLib|CryptoPkg/Library/TlsLibNull/TlsLibNull.inf
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  UnitTestBootLib|UnitTestFrameworkPkg/Library/UnitTestBootLibNull/UnitTestBootLibNull.inf
  UnitTestLib|UnitTestFrameworkPkg/Library/UnitTestLib/UnitTestLib.inf
  UnitTestPersistenceLib|UnitTestFrameworkPkg/Library/UnitTestPersistenceLibNull/UnitTestPersistenceLibNull.inf
  UnitTestResultReportLib|UnitTestFrameworkPkg/Library/UnitTestResultReportLib/UnitTestResultReportLibDebugLib.inf
  NULL|MdePkg/Library/FltUsedLib/FltUsedLib.inf


#
# For stack protection
#
[LibraryClasses.common.PEI_CORE]
  NULL|MdePkg/Library/StackCheckLibNull/StackCheckLibNull.inf

[LibraryClasses.common.PEIM, LibraryClasses.common.MM_CORE_STANDALONE, LibraryClasses.common.MM_STANDALONE]
  NULL|MdePkg/Library/StackCheckLib/StackCheckLibStaticInit.inf

[LibraryClasses.common.DXE_CORE, LibraryClasses.common.SMM_CORE, LibraryClasses.common.DXE_SMM_DRIVER, LibraryClasses.common.DXE_DRIVER, LibraryClasses.common.DXE_RUNTIME_DRIVER, LibraryClasses.common.DXE_SAL_DRIVER, LibraryClasses.common.UEFI_DRIVER, LibraryClasses.common.UEFI_APPLICATION]
  NULL|MdePkg/Library/StackCheckLib/StackCheckLibStaticInit.inf

[LibraryClasses.common.DXE_DRIVER, LibraryClasses.common.DXE_RUNTIME_DRIVER, LibraryClasses.common.UEFI_APPLICATION]
  RngLib|MdePkg/Library/DxeRngLib/DxeRngLib.inf

!if $(TOOL_CHAIN_TAG) == VS2019 or $(TOOL_CHAIN_TAG) == VS2022
[LibraryClasses.IA32]
  NULL|MdePkg/Library/VsIntrinsicLib/VsIntrinsicLib.inf
  ReportStatusCodeLib|MdePkg/Library/BaseReportStatusCodeLibNull/BaseReportStatusCodeLibNull.inf
[LibraryClasses.X64.DXE_CORE, LibraryClasses.X64.UEFI_DRIVER, LibraryClasses.X64.DXE_DRIVER, LibraryClasses.X64.UEFI_APPLICATION]
  # this is currently X64 only because MSVC doesn't support BaseMemoryLibOptDxe for AARCH64
  BaseMemoryLib|MdePkg/Library/BaseMemoryLibOptDxe/BaseMemoryLibOptDxe.inf
!endif

[LibraryClasses.common.PEIM]
  HobLib|MdePkg/Library/PeiHobLib/PeiHobLib.inf
  MemoryAllocationLib|MdePkg/Library/PeiMemoryAllocationLib/PeiMemoryAllocationLib.inf
  PeimEntryPoint|MdePkg/Library/PeimEntryPoint/PeimEntryPoint.inf
  PeiServicesLib|MdePkg/Library/PeiServicesLib/PeiServicesLib.inf
  PeiServicesTablePointerLib|MdePkg/Library/PeiServicesTablePointerLib/PeiServicesTablePointerLib.inf

[LibraryClasses.common.DXE_SMM_DRIVER]
  BaseMemoryLib|MdePkg/Library/BaseMemoryLibRepStr/BaseMemoryLibRepStr.inf
  MemoryAllocationLib|MdePkg/Library/SmmMemoryAllocationLib/SmmMemoryAllocationLib.inf
  SmmServicesTableLib|MdePkg/Library/SmmServicesTableLib/SmmServicesTableLib.inf

[LibraryClasses.ARM]
  ArmSoftFloatLib|ArmPkg/Library/ArmSoftFloatLib/ArmSoftFloatLib.inf

[LibraryClasses.common.PEIM]
  BaseCryptLib|OpensslPkg/Library/BaseCryptLib/PeiCryptLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/PeiReportStatusCodeLib/PeiReportStatusCodeLib.inf
  TlsLib|CryptoPkg/Library/TlsLibNull/TlsLibNull.inf

[LibraryClasses.IA32.PEIM, LibraryClasses.X64.PEIM]
  PeiServicesTablePointerLib|MdePkg/Library/PeiServicesTablePointerLibIdt/PeiServicesTablePointerLibIdt.inf

[LibraryClasses.ARM.PEIM, LibraryClasses.AARCH64.PEIM]
  PeiServicesTablePointerLib|ArmPkg/Library/PeiServicesTablePointerLib/PeiServicesTablePointerLib.inf

[LibraryClasses.common.DXE_DRIVER, LibraryClasses.common.UEFI_APPLICATION]
  BaseCryptLib|OpensslPkg/Library/BaseCryptLib/BaseCryptLib.inf
  DebugLib|MdePkg/Library/UefiDebugLibDebugPortProtocol/UefiDebugLibDebugPortProtocol.inf
  OpensslLib|OpensslPkg/Library/OpensslLib/OpensslLibFull.inf
  ReportStatusCodeLib|MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf
  TlsLib|OpensslPkg/Library/TlsLib/TlsLib.inf

[LibraryClasses.common.DXE_RUNTIME_DRIVER]
  BaseCryptLib|OpensslPkg/Library/BaseCryptLib/RuntimeCryptLib.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/RuntimeDxeReportStatusCodeLib/RuntimeDxeReportStatusCodeLib.inf
  TlsLib|OpensslPkg/Library/TlsLib/TlsLib.inf
  UefiRuntimeLib|MdePkg/Library/UefiRuntimeLib/UefiRuntimeLib.inf

[LibraryClasses.common.DXE_SMM_DRIVER]
  BaseCryptLib|OpensslPkg/Library/BaseCryptLib/SmmCryptLib.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  ReportStatusCodeLib|MdeModulePkg/Library/SmmReportStatusCodeLib/SmmReportStatusCodeLib.inf
  TlsLib|CryptoPkg/Library/TlsLibNull/TlsLibNull.inf

[LibraryClasses.common.MM_STANDALONE]
  BaseCryptLib|OpensslPkg/Library/BaseCryptLib/SmmCryptLib.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  MemoryAllocationLib|StandaloneMmPkg/Library/StandaloneMmMemoryAllocationLib/StandaloneMmMemoryAllocationLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/SmmReportStatusCodeLib/StandaloneMmReportStatusCodeLib.inf
  TlsLib|CryptoPkg/Library/TlsLibNull/TlsLibNull.inf

[LibraryClasses.common.PEIM]
  RngLib|MdePkg/Library/PeiRngLib/PeiRngLib.inf

[LibraryClasses.AARCH64.MM_STANDALONE]
  MmServicesTableLib|MdePkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
  RngLib|MdePkg/Library/BaseRngLibTimerLib/BaseRngLibTimerLib.inf
  StandaloneMmDriverEntryPoint|MdePkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf

[LibraryClasses.ARM.MM_STANDALONE, LibraryClasses.AARCH64.MM_STANDALONE]
  MmServicesTableLib|MdePkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
  StandaloneMmDriverEntryPoint|MdePkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf

################################################################################
#
# Pcd Section - list of all EDK II PCD Entries defined by this Platform
#
################################################################################
[PcdsFixedAtBuild]
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x0f
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80000000
  gEfiMdePkgTokenSpaceGuid.PcdReportStatusCodePropertyMask|0x06

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
[Components.X64]
  CryptoPkg/Test/UnitTest/Library/BaseCryptLib/BaseCryptLibUnitTestApp.inf {
    <LibraryClasses>
      BaseCryptLib|OpensslPkg/Library/BaseCryptLib/BaseCryptLib.inf
      UnitTestResultReportLib |XmlSupportPkg/Library/UnitTestResultReportJUnitFormatLib/UnitTestResultReportLib.inf
      XmlTreeLib                        |XmlSupportPkg/Library/XmlTreeLib/XmlTreeLib.inf
      ShellLib         |ShellPkg/Library/UefiShellLib/UefiShellLib.inf
      FileHandleLib     |MdePkg/Library/UefiFileHandleLib/UefiFileHandleLib.inf
      UefiLib         |MdePkg/Library/UefiLib/UefiLib.inf
      HiiLib          |MdeModulePkg/Library/UefiHiiLib/UefiHiiLib.inf
      SortLib              |MdeModulePkg/Library/UefiSortLib/UefiSortLib.inf
      UefiHiiServicesLib          |MdeModulePkg/Library/UefiHiiServicesLib/UefiHiiServicesLib.inf
    <PcdsFixedAtBuild>
      !include CryptoPkg/Test/Crypto.pcd.ALL.inc.dsc
  }
[Components.IA32, Components.X64]
  CryptoBinPkg/Driver/CryptoSmm.inf {
    <Defines>
      FILE_GUID = $(SMM_CRYPTO_DRIVER_FILE_GUID)
  }

[Components.IA32, Components.X64, Components.AARCH64]
  CryptoBinPkg/Driver/CryptoPei.inf {
    <Defines>
      FILE_GUID = $(PEI_CRYPTO_DRIVER_FILE_GUID)
  }

  CryptoBinPkg/Driver/CryptoDxe.inf {
    <Defines>
      FILE_GUID = $(DXE_CRYPTO_DRIVER_FILE_GUID)
  }

  CryptoBinPkg/Driver/CryptoRuntimeDxe.inf {
    <Defines>
      FILE_GUID = $(RUNTIMEDXE_CRYPTO_DRIVER_FILE_GUID)
  }

[Components.X64]
  # Note: MmSupervisorPkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf has instructions
  #       that are not supported in 32-bit. Only 64-bit is practically needed, so only build for 64-bit here.
  CryptoBinPkg/Driver/CryptoMmSupervisorStandaloneMm.inf {
    <Defines>
      FILE_GUID = $(STANDALONEMM_MMSUPERVISOR_CRYPTO_DRIVER_FILE_GUID)
    <LibraryClasses>
      MmServicesTableLib|MmSupervisorPkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
      StandaloneMmDriverEntryPoint|MmSupervisorPkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
    <PcdsFixedAtBuild>
      # MM environment only set up the exception handler for the upper 32 entries.
      # The platform should set this to a non-conflicting exception number, otherwise
      # it will be treated as one of the normal types of CPU faults.
      gEfiMdePkgTokenSpaceGuid.PcdStackCookieExceptionVector|0x0F
  }

[Components.AARCH64, Components.X64]
  # Note: Only 64-bit is practically needed, so only build for 64-bit here.
  CryptoBinPkg/Driver/CryptoStandaloneMm.inf {
    <Defines>
      FILE_GUID = $(STANDALONEMM_CRYPTO_DRIVER_FILE_GUID)
    <LibraryClasses>
      MmServicesTableLib|MdePkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
      StandaloneMmDriverEntryPoint|MdePkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
    <PcdsFixedAtBuild>
      # MM environment only set up the exception handler for the upper 32 entries.
      # The platform should set this to a non-conflicting exception number, otherwise
      # it will be treated as one of the normal types of CPU faults.
      gEfiMdePkgTokenSpaceGuid.PcdStackCookieExceptionVector|0x0F
  }

[BuildOptions]
  *_*_*_CC_FLAGS = -D DISABLE_NEW_DEPRECATED_INTERFACES
!if $(CRYPTO_SERVICES) IN "PACKAGE ALL"
  MSFT:*_*_*_CC_FLAGS = /D ENABLE_MD5_DEPRECATED_INTERFACES
  INTEL:*_*_*_CC_FLAGS = /D ENABLE_MD5_DEPRECATED_INTERFACES
  GCC:*_*_*_CC_FLAGS = -D ENABLE_MD5_DEPRECATED_INTERFACES
  RVCT:*_*_*_CC_FLAGS = -DENABLE_MD5_DEPRECATED_INTERFACES
!endif
MSFT:RELEASE_*_*_CC_FLAGS = /Zi
MSFT:RELEASE_*_*_DLINK_FLAGS = /DEBUG /OPT:REF /OPT:ICF=10 /ALT /PDBALTPATH:$(MODULE_NAME)
MSFT:RELEASE_*_*_ASM_FLAGS = /Zi
MSFT:RELEASE_*_*_NASM_FLAGS = -g

[BuildOptions.X64.EDKII.PEIM, BuildOptions.AARCH64.EDKII.PEIM]
  MSFT:*_*_*_DLINK_FLAGS = /FILEALIGN:0x1000 # meet requirement for PEIM section and file alignment to match.

[BuildOptions.common.EDKII.DXE_RUNTIME_DRIVER, BuildOptions.common.EDKII.DXE_SMM_DRIVER, BuildOptions.common.EDKII.SMM_CORE, BuildOptions.common.EDKII.DXE_DRIVER, BuildOptions.common.EDKII.MM_STANDALONE]
  MSFT:*_*_IA32_DLINK_FLAGS = /ALIGN:4096 # enable 4k alignment for MAT and other protections.
  MSFT:*_*_X64_DLINK_FLAGS = /ALIGN:4096 # enable 4k alignment for MAT and other protections.

[BuildOptions.AARCH64.EDKII.PEIM, BuildOptions.AARCH64.EDKII.DXE_DRIVER, BuildOptions.AARCH64.EDKII.MM_STANDALONE]
  GCC:*_*_*_DLINK_FLAGS = -z common-page-size=0x1000

[BuildOptions.AARCH64.EDKII.MM_STANDALONE]
  GCC:*_*_*_CC_FLAGS = -mstrict-align -march=armv8-a
