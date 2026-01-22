## @file
# OneCryptoPkg DSC file
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

[Defines]
  PLATFORM_NAME                  = OneCryptoPkg
  PLATFORM_GUID                  = 36470E85-36F2-4BA0-8CC8-937C7D9FF888
  PLATFORM_VERSION               = 1.0
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/OneCryptoPkg
  SUPPORTED_ARCHITECTURES        = X64|AARCH64
  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
  SKUID_IDENTIFIER               = DEFAULT


[PcdsPatchableInModule.X64]
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x17

[PcdsFixedAtBuild.X64]
  # Ensure DEBUG prints are enabled (excluding VERBOSE: 0x8040004F & ~0x00400000 = 0x8000004F)
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x8000004F
  gEfiMdePkgTokenSpaceGuid.PcdFixedDebugPrintErrorLevel|0x8000004F

  # OneCryptoPkg Debug Configuration
  # DEBUG builds: Enable Debug Print (BIT1) and Debug Code (BIT2) = 0x06
  # RELEASE builds: Disable all debug features = 0x00
  # Note: Debug Clear Memory (BIT3) is intentionally disabled for all builds
!if $(TARGET) == DEBUG
  gOneCryptoPkgTokenSpaceGuid.PcdDebugPropertyMask|0x06
  gOneCryptoPkgTokenSpaceGuid.PcdFixedDebugPrintErrorLevel|0xFFFFFFFF
!else
  gOneCryptoPkgTokenSpaceGuid.PcdDebugPropertyMask|0x00
  gOneCryptoPkgTokenSpaceGuid.PcdFixedDebugPrintErrorLevel|0x80000000
!endif

[Components.X64]

  #############################################################################
  ## OneCryptoBin START
  #############################################################################

  ## OneCryptBin meant for SupvMm
  #
  # This binary provides the crypto for a SupvMm based platform.
  ##
  OneCryptoPkg/OneCryptoBin/OneCryptoBinSupvMm.inf {
    <LibraryClasses>
      BaseLib                        | MdePkg/Library/BaseLib/BaseLib.inf
      BaseMemoryLib                  | MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
      PrintLib                       | MdePkg/Library/BasePrintLib/BasePrintLib.inf
      PcdLib                         | MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
      RegisterFilterLib              | MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
      SafeIntLib                     | MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
      StackCheckLib                  | MdePkg/Library/StackCheckLib/StackCheckLib.inf
      StackCheckFailureHookLib       | MdePkg/Library/StackCheckFailureHookLibNull/StackCheckFailureHookLibNull.inf
      BaseCryptLib                   | OpensslPkg/Library/BaseCryptLib/BaseCryptLib.inf
      TlsLib                         | OpensslPkg/Library/TlsLib/TlsLib.inf
      IntrinsicLib                   | OpensslPkg/Library/IntrinsicLib/IntrinsicLib.inf
      OneCryptoCrtLib                | OneCryptoPkg/Library/OneCryptoCrtLib/OneCryptoCrtLib.inf
      StandaloneMmDriverEntryPoint   | OneCryptoPkg/Library/SupvStandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
      #############################################################################
      ## Crypto Provider
      #############################################################################
      FltUsedLib                     | MdePkg/Library/FltUsedLib/FltUsedLib.inf
      RealTimeClockLib               | OneCryptoPkg/Library/RealTimeClockLibOnOneCrypto/RealTimeClockLibOnOneCrypto.inf
      DebugLib                       | OneCryptoPkg/Library/DebugLibOnOneCrypto/DebugLibOnOneCrypto.inf
      MemoryAllocationLib            | OneCryptoPkg/Library/MemoryAllocationLibOnOneCrypto/MemoryAllocationLibOnOneCrypto.inf
      RngLib                         | OneCryptoPkg/Library/RngLibOnOneCrypto/RngLibOnOneCrypto.inf
      OpensslLib                     | OpensslPkg/Library/OpensslLib/OpensslLibFullAccel.inf
  }

  ## OneCryptBin meant for StandaloneMm
  #
  # This binary provides the crypto for a StandaloneMm based platform.
  ##
  OneCryptoPkg/OneCryptoBin/OneCryptoBinStandaloneMm.inf {
    <LibraryClasses>
      BaseLib                        | MdePkg/Library/BaseLib/BaseLib.inf
      BaseMemoryLib                  | MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
      PrintLib                       | MdePkg/Library/BasePrintLib/BasePrintLib.inf
      PcdLib                         | MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
      RegisterFilterLib              | MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
      SafeIntLib                     | MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
      StackCheckLib                  | MdePkg/Library/StackCheckLib/StackCheckLib.inf
      StackCheckFailureHookLib       | MdePkg/Library/StackCheckFailureHookLibNull/StackCheckFailureHookLibNull.inf
      BaseCryptLib                   | OpensslPkg/Library/BaseCryptLib/BaseCryptLib.inf
      TlsLib                         | OpensslPkg/Library/TlsLib/TlsLib.inf
      IntrinsicLib                   | OpensslPkg/Library/IntrinsicLib/IntrinsicLib.inf
      OneCryptoCrtLib                | OneCryptoPkg/Library/OneCryptoCrtLib/OneCryptoCrtLib.inf
      StandaloneMmDriverEntryPoint   | OneCryptoPkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
      #############################################################################
      ## Crypto Provider
      #############################################################################
      FltUsedLib                     | MdePkg/Library/FltUsedLib/FltUsedLib.inf
      RealTimeClockLib               | OneCryptoPkg/Library/RealTimeClockLibOnOneCrypto/RealTimeClockLibOnOneCrypto.inf
      DebugLib                       | OneCryptoPkg/Library/DebugLibOnOneCrypto/DebugLibOnOneCrypto.inf
      MemoryAllocationLib            | OneCryptoPkg/Library/MemoryAllocationLibOnOneCrypto/MemoryAllocationLibOnOneCrypto.inf
      RngLib                         | OneCryptoPkg/Library/RngLibOnOneCrypto/RngLibOnOneCrypto.inf
      OpensslLib                     | OpensslPkg/Library/OpensslLib/OpensslLibFullAccel.inf
  }

  #############################################################################
  ## OneCryptoBin END
  #############################################################################

  #############################################################################
  ## OneCryptoLoader START
  #############################################################################

  OneCryptoPkg/OneCryptoLoaders/OneCryptoLoaderDxe.inf {
    <LibraryClasses>
      BaseLib                     | MdePkg/Library/BaseLib/BaseLib.inf
      BaseMemoryLib               | MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
      PcdLib                      | MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
      PrintLib                    | MdePkg/Library/BasePrintLib/BasePrintLib.inf
      UefiLib                     | MdePkg/Library/UefiLib/UefiLib.inf
      UefiRuntimeServicesTableLib | MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
      DevicePathLib               | MdePkg/Library/UefiDevicePathLibDevicePathProtocol/UefiDevicePathLibDevicePathProtocol.inf
      RngLib                      | MdePkg/Library/BaseRngLibNull/BaseRngLibNull.inf # Drivers should use the protocol, GetRandomNumber64 will not work.
      PeCoffLib                   | MdePkg/Library/BasePeCoffLib/BasePeCoffLib.inf
      PeCoffExtendedLib           | OneCryptoPkg/Library/PeCoffExtendedLib/PeCoffExtendedLib.inf
      PeCoffGetEntryPointLib      | MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
      CacheMaintenanceLib         | MdePkg/Library/BaseCacheMaintenanceLib/BaseCacheMaintenanceLib.inf
      NULL                        | MdePkg/Library/StackCheckLib/StackCheckLib.inf
      RegisterFilterLib           | MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
      PeCoffExtraActionLib        | MdePkg/Library/BasePeCoffExtraActionLibNull/BasePeCoffExtraActionLibNull.inf
      HobLib                      | MdePkg/Library/DxeHobLib/DxeHobLib.inf
      StackCheckFailureHookLib    | MdePkg/Library/StackCheckFailureHookLibNull/StackCheckFailureHookLibNull.inf
      StackCheckLib               | MdePkg/Library/StackCheckLib/StackCheckLib.inf
      SafeIntLib                  | MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
      UefiDriverEntryPoint        | MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
      UefiBootServicesTableLib    | MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
      MemoryAllocationLib         | MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
      DxeServicesLib              | MdePkg/Library/DxeServicesLib/DxeServicesLib.inf
      DxeServicesTableLib         | MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf                                   ## NOT NEEDED
      DebugLib                    | AdvLoggerPkg/Library/BaseDebugLibAdvancedLogger/BaseDebugLibAdvancedLogger.inf
      DebugPrintErrorLevelLib     | MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
      AdvancedLoggerLib           | AdvLoggerPkg/Library/AdvancedLoggerLib/Dxe/AdvancedLoggerLib.inf
      AssertLib                   | AdvLoggerPkg/Library/AssertLib/AssertLib.inf
  }

  OneCryptoPkg/OneCryptoLoaders/OneCryptoLoaderSupvMm.inf {
    <LibraryClasses>
      BaseLib                      | MdePkg/Library/BaseLib/BaseLib.inf
      BaseMemoryLib                | MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
      DebugLib                     | MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
      PcdLib                       | MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
      RngLib                       | MdePkg/Library/BaseRngLibNull/BaseRngLibNull.inf # Drivers should use the protocol, GetRandomNumber64 will not work.
      RegisterFilterLib            | MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
      PeCoffExtraActionLib         | MdePkg/Library/BasePeCoffExtraActionLibNull/BasePeCoffExtraActionLibNull.inf
      HobLib                       | MdePkg/Library/DxeHobLib/DxeHobLib.inf
      StackCheckFailureHookLib     | MdePkg/Library/StackCheckFailureHookLibNull/StackCheckFailureHookLibNull.inf
      StackCheckLib                | MdePkg/Library/StackCheckLib/StackCheckLib.inf
      SafeIntLib                   | MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
      PeCoffLib                    | MdePkg/Library/BasePeCoffLib/BasePeCoffLib.inf
      PeCoffExtendedLib            | OneCryptoPkg/Library/PeCoffExtendedLib/PeCoffExtendedLib.inf
      PeCoffGetEntryPointLib       | MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
      CacheMaintenanceLib          | MdePkg/Library/BaseCacheMaintenanceLib/BaseCacheMaintenanceLib.inf
      NULL                         | MdePkg/Library/StackCheckLib/StackCheckLib.inf
      StandaloneMmDriverEntryPoint | MmSupervisorPkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
      MmServicesTableLib           | MmSupervisorPkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
      MemoryAllocationLib          | StandaloneMmPkg/Library/StandaloneMmMemoryAllocationLib/StandaloneMmMemoryAllocationLib.inf
      HobLib                       | StandaloneMmPkg/Library/StandaloneMmHobLib/StandaloneMmHobLib.inf
      FvLib                        | StandaloneMmPkg/Library/FvLib/FvLib.inf
  }

  OneCryptoPkg/OneCryptoLoaders/OneCryptoLoaderStandaloneMm.inf {
    <LibraryClasses>
      BaseLib                      | MdePkg/Library/BaseLib/BaseLib.inf
      BaseMemoryLib                | MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
      DebugLib                     | MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
      PcdLib                       | MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
      RngLib                       | MdePkg/Library/BaseRngLibNull/BaseRngLibNull.inf # Drivers should use the protocol, GetRandomNumber64 will not work.
      RegisterFilterLib            | MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
      PeCoffExtraActionLib         | MdePkg/Library/BasePeCoffExtraActionLibNull/BasePeCoffExtraActionLibNull.inf
      HobLib                       | MdePkg/Library/DxeHobLib/DxeHobLib.inf
      StackCheckFailureHookLib     | MdePkg/Library/StackCheckFailureHookLibNull/StackCheckFailureHookLibNull.inf
      StackCheckLib                | MdePkg/Library/StackCheckLib/StackCheckLib.inf
      SafeIntLib                   | MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
      PeCoffLib                    | MdePkg/Library/BasePeCoffLib/BasePeCoffLib.inf
      PeCoffExtendedLib            | OneCryptoPkg/Library/PeCoffExtendedLib/PeCoffExtendedLib.inf
      PeCoffGetEntryPointLib       | MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
      CacheMaintenanceLib          | MdePkg/Library/BaseCacheMaintenanceLib/BaseCacheMaintenanceLib.inf
      NULL                         | MdePkg/Library/StackCheckLib/StackCheckLib.inf
      StandaloneMmDriverEntryPoint | MdePkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
      MmServicesTableLib           | MdePkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
      MemoryAllocationLib          | StandaloneMmPkg/Library/StandaloneMmMemoryAllocationLib/StandaloneMmMemoryAllocationLib.inf
      HobLib                       | StandaloneMmPkg/Library/StandaloneMmHobLib/StandaloneMmHobLib.inf
      FvLib                        | StandaloneMmPkg/Library/FvLib/FvLib.inf
  }

  #############################################################################
  ## OneCryptoLoader END
  #############################################################################

[Components.AARCH64]
  # AARCH64 components will be added in a follow-up PR

[BuildOptions]
  *_*_*_CC_FLAGS = -D DISABLE_NEW_DEPRECATED_INTERFACES -D ENABLE_MD5_DEPRECATED_INTERFACES
  MSFT:*_*_*_DLINK_FLAGS = /IGNORE:4217