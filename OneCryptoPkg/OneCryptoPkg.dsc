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
  SUPPORTED_ARCHITECTURES        = IA32|X64|AARCH64
  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
  SKUID_IDENTIFIER               = DEFAULT

!ifndef NON_ACCEL
  DEFINE NON_ACCEL       = FALSE
!endif

!ifndef ONECRYPTO_AARCH64_MM_DEBUG
  # Opt-in AARCH64 StandaloneMM debug printing over the FF-A console (e.g.
  # Hafnium). Off by default so the package stays SPM-agnostic; the FF-A
  # console debug lib and PcdFfaLibConduitSmc are the only non-portable bits.
  DEFINE ONECRYPTO_AARCH64_MM_DEBUG = FALSE
!endif


[PcdsPatchableInModule.X64]
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x17

[PcdsFeatureFlag.X64]
  # Enable NASM assembly source style for accelerated OpenSSL crypto
  gEfiCryptoPkgTokenSpaceGuid.PcdOpensslLibAssemblySourceStyleNasm|TRUE

[PcdsPatchableInModule.AARCH64]
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x17

[PcdsFeatureFlag.AARCH64]
  #
  # Use the PE target assembly source files when building with the CLANGPDB
  # toolchain.
  # GCC and CLANGDWARF use the default PCD value of ELF target assembly source files.
  #
  !if "$(TOOL_CHAIN_TAG)" == "CLANGPDB"
  gEfiCryptoPkgTokenSpaceGuid.PcdOpensslLibAssemblySourceStylePe|TRUE
  !endif

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

[PcdsFixedAtBuild.AARCH64]
  # Ensure DEBUG prints are enabled (excluding VERBOSE: 0x8040004F & ~0x00400000 = 0x8000004F)
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x8000004F
  gEfiMdePkgTokenSpaceGuid.PcdFixedDebugPrintErrorLevel|0x8000004F
  # FF-A conduit (SVC vs SMC) is SPM-specific and only matters when the FF-A
  # console debug lib is linked (ONECRYPTO_AARCH64_MM_DEBUG). Hafnium uses SVC.
!if $(ONECRYPTO_AARCH64_MM_DEBUG) == TRUE
  gEfiMdeModulePkgTokenSpaceGuid.PcdFfaLibConduitSmc|FALSE
!endif

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

[LibraryClasses.AARCH64]
  CompilerIntrinsicsLib|MdePkg/Library/CompilerIntrinsicsLib/CompilerIntrinsicsLib.inf

[Components]
  MbedTlsPkg/Driver/MbedTlsCryptoPei.inf {
    <LibraryClasses>
      BaseLib                        | MdePkg/Library/BaseLib/BaseLib.inf
      BaseMemoryLib                  | MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
      DebugLib                       | MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
      PcdLib                         | MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
      PeimEntryPoint                 | MdePkg/Library/PeimEntryPoint/PeimEntryPoint.inf
      PeiServicesLib                 | MdePkg/Library/PeiServicesLib/PeiServicesLib.inf
      PeiServicesTablePointerLib     | MdePkg/Library/PeiServicesTablePointerLib/PeiServicesTablePointerLib.inf
      MemoryAllocationLib            | MdePkg/Library/PeiMemoryAllocationLib/PeiMemoryAllocationLib.inf
      RegisterFilterLib              | MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
      StackCheckLib                  | MdePkg/Library/StackCheckLibNull/StackCheckLibNull.inf
      CompilerIntrinsicsLib          | MdePkg/Library/CompilerIntrinsicsLib/CompilerIntrinsicsLib.inf
      HobLib                         | MdePkg/Library/PeiHobLib\PeiHobLib.inf
  }

[Components.X64]

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
      IntrinsicLib                   | CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
      OneCryptoCrtLib                | OneCryptoPkg/Library/OneCryptoCrtLib/OneCryptoCrtLib.inf
      StandaloneMmDriverEntryPoint   | OneCryptoPkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
      #############################################################################
      ## Crypto Provider
      #############################################################################
      FltUsedLib                     | MsCorePkg/Library/FltUsedLib/FltUsedLib.inf
      RealTimeClockLib               | OneCryptoPkg/Library/RealTimeClockLibOnOneCrypto/RealTimeClockLibOnOneCrypto.inf
      DebugLib                       | OneCryptoPkg/Library/DebugLibOnOneCrypto/DebugLibOnOneCrypto.inf
      MemoryAllocationLib            | OneCryptoPkg/Library/MemoryAllocationLibOnOneCrypto/MemoryAllocationLibOnOneCrypto.inf
      RngLib                         | OneCryptoPkg/Library/RngLibOnOneCrypto/RngLibOnOneCrypto.inf
      TimerLib                       | OneCryptoPkg/Library/TimerLibOnOneCrypto/TimerLibOnOneCrypto.inf
    !if $(NON_ACCEL) == TRUE
      OpensslLib                     | OpensslPkg/Library/OpensslLib/OpensslLibFull.inf
    !else
      OpensslLib                     | OpensslPkg/Library/OpensslLib/OpensslLibFullAccel.inf
    !endif
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
      StandaloneMmDriverEntryPoint | MdePkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
      MmServicesTableLib           | MdePkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
      MemoryAllocationLib          | StandaloneMmPkg/Library/StandaloneMmMemoryAllocationLib/StandaloneMmMemoryAllocationLib.inf
      HobLib                       | StandaloneMmPkg/Library/StandaloneMmHobLib/StandaloneMmHobLib.inf
      FvLib                        | MdePkg/Library/FvLib/FvLib.inf
  }

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
      IntrinsicLib                   | CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
      OneCryptoCrtLib                | OneCryptoPkg/Library/OneCryptoCrtLib/OneCryptoCrtLib.inf
      StandaloneMmDriverEntryPoint   | OneCryptoPkg/Library/SupvStandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
      #############################################################################
      ## Crypto Provider
      #############################################################################
      FltUsedLib                     | MsCorePkg/Library/FltUsedLib/FltUsedLib.inf
      RealTimeClockLib               | OneCryptoPkg/Library/RealTimeClockLibOnOneCrypto/RealTimeClockLibOnOneCrypto.inf
      DebugLib                       | OneCryptoPkg/Library/DebugLibOnOneCrypto/DebugLibOnOneCrypto.inf
      MemoryAllocationLib            | OneCryptoPkg/Library/MemoryAllocationLibOnOneCrypto/MemoryAllocationLibOnOneCrypto.inf
      RngLib                         | OneCryptoPkg/Library/RngLibOnOneCrypto/RngLibOnOneCrypto.inf
      TimerLib                       | OneCryptoPkg/Library/TimerLibOnOneCrypto/TimerLibOnOneCrypto.inf
    !if $(NON_ACCEL) == TRUE
      OpensslLib                     | OpensslPkg/Library/OpensslLib/OpensslLibFull.inf
    !else
      OpensslLib                     | OpensslPkg/Library/OpensslLib/OpensslLibFullAccel.inf
    !endif
  }

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
      BaseLib                      | MmSupervisorPkg/Library/BaseLibSysCall/BaseLib.inf
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
      SysCallLib                   | MmSupervisorPkg/Library/SysCallLib/SysCallLib.inf
      StandaloneMmDriverEntryPoint | MmSupervisorPkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
      MmServicesTableLib           | MmSupervisorPkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
      MemoryAllocationLib          | StandaloneMmPkg/Library/StandaloneMmMemoryAllocationLib/StandaloneMmMemoryAllocationLib.inf
      HobLib                       | StandaloneMmPkg/Library/StandaloneMmHobLib/StandaloneMmHobLib.inf
      FvLib                        | MdePkg/Library/FvLib/FvLib.inf
  }

[Components.AARCH64]

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
      IntrinsicLib                   | CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
      OneCryptoCrtLib                | OneCryptoPkg/Library/OneCryptoCrtLib/OneCryptoCrtLib.inf
      StandaloneMmDriverEntryPoint   | OneCryptoPkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
      #############################################################################
      ## Crypto Provider
      #############################################################################
      FltUsedLib                     | MsCorePkg/Library/FltUsedLib/FltUsedLib.inf
      RealTimeClockLib               | OneCryptoPkg/Library/RealTimeClockLibOnOneCrypto/RealTimeClockLibOnOneCrypto.inf
      DebugLib                       | OneCryptoPkg/Library/DebugLibOnOneCrypto/DebugLibOnOneCrypto.inf
      MemoryAllocationLib            | OneCryptoPkg/Library/MemoryAllocationLibOnOneCrypto/MemoryAllocationLibOnOneCrypto.inf
      RngLib                         | OneCryptoPkg/Library/RngLibOnOneCrypto/RngLibOnOneCrypto.inf
      TimerLib                       | OneCryptoPkg/Library/TimerLibOnOneCrypto/TimerLibOnOneCrypto.inf
    !if $(NON_ACCEL) == TRUE
      OpensslLib                     | OpensslPkg/Library/OpensslLib/OpensslLibFull.inf
    !else
      OpensslLib                     | OpensslPkg/Library/OpensslLib/OpensslLibFullAccel.inf
    !endif
      NULL                           | MdePkg/Library/CompilerIntrinsicsLib/CompilerIntrinsicsLib.inf
  }

  OneCryptoPkg/OneCryptoLoaders/OneCryptoLoaderStandaloneMm.inf {
    <LibraryClasses>
      BaseLib                      | MdePkg/Library/BaseLib/BaseLib.inf
      BaseMemoryLib                | MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
    !if $(ONECRYPTO_AARCH64_MM_DEBUG) == TRUE
      # FF-A console debug printing for AARCH64 MM (e.g. Hafnium). Only
      # consumer of the FF-A conduit libs + PcdFfaLibConduitSmc; opt-in.
      PrintLib                     | MdePkg/Library/BasePrintLib/BasePrintLib.inf
      DebugLib                     | MdeModulePkg/Library/ArmFfaConsoleDebugLib/ArmFfaConsoleDebugStandaloneMmLib.inf
      DebugPrintErrorLevelLib      | MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
      ArmSmcLib                    | MdePkg/Library/ArmSmcLib/ArmSmcLib.inf
      ArmSvcLib                    | MdePkg/Library/ArmSvcLib/ArmSvcLib.inf
    !else
      DebugLib                     | MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
      DebugPrintErrorLevelLib      | MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
      SerialPortLib                | MdePkg/Library/BaseSerialPortLibNull/BaseSerialPortLibNull.inf
    !endif
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
      StandaloneMmDriverEntryPoint | MdePkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
      MmServicesTableLib           | MdePkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
      MemoryAllocationLib          | StandaloneMmPkg/Library/StandaloneMmMemoryAllocationLib/StandaloneMmMemoryAllocationLib.inf
      HobLib                       | StandaloneMmPkg/Library/StandaloneMmHobLib/StandaloneMmHobLib.inf
      FvLib                        | MdePkg/Library/FvLib/FvLib.inf
  }

  OneCryptoPkg/OneCryptoLoaders/OneCryptoImageProviderStandaloneMm.inf {
    <LibraryClasses>
      BaseLib                      | MdePkg/Library/BaseLib/BaseLib.inf
      BaseMemoryLib                | MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
    !if $(ONECRYPTO_AARCH64_MM_DEBUG) == TRUE
      # FF-A console debug printing for AARCH64 MM (e.g. Hafnium). Only
      # consumer of the FF-A conduit libs + PcdFfaLibConduitSmc; opt-in.
      PrintLib                     | MdePkg/Library/BasePrintLib/BasePrintLib.inf
      DebugLib                     | MdeModulePkg/Library/ArmFfaConsoleDebugLib/ArmFfaConsoleDebugStandaloneMmLib.inf
      DebugPrintErrorLevelLib      | MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
      ArmSmcLib                    | MdePkg/Library/ArmSmcLib/ArmSmcLib.inf
      ArmSvcLib                    | MdePkg/Library/ArmSvcLib/ArmSvcLib.inf
    !else
      DebugLib                     | MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
      DebugPrintErrorLevelLib      | MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
      SerialPortLib                | MdePkg/Library/BaseSerialPortLibNull/BaseSerialPortLibNull.inf
    !endif
      PcdLib                       | MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
      RegisterFilterLib            | MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
      StackCheckFailureHookLib     | MdePkg/Library/StackCheckFailureHookLibNull/StackCheckFailureHookLibNull.inf
      StackCheckLib                | MdePkg/Library/StackCheckLib/StackCheckLib.inf
      SafeIntLib                   | MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
      MemoryAllocationLib          | StandaloneMmPkg/Library/StandaloneMmMemoryAllocationLib/StandaloneMmMemoryAllocationLib.inf
      StandaloneMmDriverEntryPoint | MdePkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf
      MmServicesTableLib           | MdePkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
      StandaloneMmMemLib           | StandaloneMmPkg/Library/StandaloneMmMemLib/StandaloneMmMemLib.inf
      HobLib                       | StandaloneMmPkg/Library/StandaloneMmHobLib/StandaloneMmHobLib.inf
      FvLib                        | MdePkg/Library/FvLib/FvLib.inf
      ExtractGuidedSectionLib      | StandaloneMmPkg/Library/StandaloneMmExtractGuidedSectionLib/StandaloneMmExtractGuidedSectionLib.inf
  }

  #############################################################################
  ## AARCH64 OneCryptoBin START
  ##
  ## AARCH64 requires 4 binaries instead of the normal 3 for X64:
  ##   1. OneCryptoBinDxe            - DXE binary that installs private protocol
  ##   2. OneCryptoLoaderDxeProtocol - DXE loader (consumes private protocol)
  ##   3. OneCryptoBinStandaloneMm   - MM binary for secure world
  ##   4. OneCryptoLoaderStandaloneMm - MM loader
  ##
  ## This is because the DXE loader cannot locate the StMM binary due to
  ## secure world layout differences on AARCH64.
  #############################################################################

  ## OneCryptoBinDxe for AARCH64
  #
  # This binary provides the crypto for DXE phase on AARCH64 platforms.
  # It installs gOneCryptoPrivateProtocolGuid for the protocol-based loader.
  ##
  OneCryptoPkg/OneCryptoBin/OneCryptoBinDxe.inf {
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
      IntrinsicLib                   | CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
      OneCryptoCrtLib                | OneCryptoPkg/Library/OneCryptoCrtLib/OneCryptoCrtLib.inf
      UefiDriverEntryPoint           | MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
      UefiBootServicesTableLib       | MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
      #############################################################################
      ## Crypto Provider
      #############################################################################
      FltUsedLib                     | MsCorePkg/Library/FltUsedLib/FltUsedLib.inf
      RealTimeClockLib               | OneCryptoPkg/Library/RealTimeClockLibOnOneCrypto/RealTimeClockLibOnOneCrypto.inf
      DebugLib                       | OneCryptoPkg/Library/DebugLibOnOneCrypto/DebugLibOnOneCrypto.inf
      MemoryAllocationLib            | OneCryptoPkg/Library/MemoryAllocationLibOnOneCrypto/MemoryAllocationLibOnOneCrypto.inf
      RngLib                         | OneCryptoPkg/Library/RngLibOnOneCrypto/RngLibOnOneCrypto.inf
      TimerLib                       | OneCryptoPkg/Library/TimerLibOnOneCrypto/TimerLibOnOneCrypto.inf
    !if $(NON_ACCEL) == TRUE
      OpensslLib                     | OpensslPkg/Library/OpensslLib/OpensslLibFull.inf
    !else
      OpensslLib                     | OpensslPkg/Library/OpensslLib/OpensslLibFullAccel.inf
    !endif
      NULL                           | MdePkg/Library/CompilerIntrinsicsLib/CompilerIntrinsicsLib.inf
  }

  ## OneCryptoLoaderDxeByProtocol for AARCH64
  #
  # This loader consumes gOneCryptoPrivateProtocolGuid installed by OneCryptoBinDxe
  # and produces gOneCryptoProtocolGuid for consumers.
  ##
  OneCryptoPkg/OneCryptoLoaders/OneCryptoLoaderDxeByProtocol.inf {
    <LibraryClasses>
      BaseLib                     | MdePkg/Library/BaseLib/BaseLib.inf
      BaseMemoryLib               | MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
      PcdLib                      | MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
      PrintLib                    | MdePkg/Library/BasePrintLib/BasePrintLib.inf
      UefiLib                     | MdePkg/Library/UefiLib/UefiLib.inf
      UefiRuntimeServicesTableLib | MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
      DevicePathLib               | MdePkg/Library/UefiDevicePathLibDevicePathProtocol/UefiDevicePathLibDevicePathProtocol.inf
      RngLib                      | MdePkg/Library/BaseRngLibNull/BaseRngLibNull.inf # Drivers should use the protocol, GetRandomNumber64 will not work.
      RegisterFilterLib           | MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
      HobLib                      | MdePkg/Library/DxeHobLib/DxeHobLib.inf
      StackCheckFailureHookLib    | MdePkg/Library/StackCheckFailureHookLibNull/StackCheckFailureHookLibNull.inf
      StackCheckLib               | MdePkg/Library/StackCheckLib/StackCheckLib.inf
      UefiDriverEntryPoint        | MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
      UefiBootServicesTableLib    | MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
      MemoryAllocationLib         | MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
      DebugLib                    | AdvLoggerPkg/Library/BaseDebugLibAdvancedLogger/BaseDebugLibAdvancedLogger.inf
      DebugPrintErrorLevelLib     | MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
      AdvancedLoggerLib           | AdvLoggerPkg/Library/AdvancedLoggerLib/Dxe/AdvancedLoggerLib.inf
      AssertLib                   | AdvLoggerPkg/Library/AssertLib/AssertLib.inf
  }

  ## OneCryptoLoaderDxeFromMm for AARCH64
  #
  # This loader fetches OneCrypto PE bytes from StandaloneMM over
  # gEfiMmCommunication2ProtocolGuid, then LoadImage()s and publishes
  # gOneCryptoProtocolGuid for DXE consumers.
  ##
  OneCryptoPkg/OneCryptoLoaders/OneCryptoLoaderDxeFromMm.inf {
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
      PeCoffExtraActionLib        | MdePkg/Library/BasePeCoffExtraActionLibNull/BasePeCoffExtraActionLibNull.inf
      PeCoffExtendedLib           | OneCryptoPkg/Library/PeCoffExtendedLib/PeCoffExtendedLib.inf
      PeCoffGetEntryPointLib      | MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
      DxeServicesLib              | MdePkg/Library/DxeServicesLib/DxeServicesLib.inf
      FvLib                       | MdePkg/Library/FvLib/FvLib.inf
      ExtractGuidedSectionLib     | MdePkg/Library/DxeExtractGuidedSectionLib/DxeExtractGuidedSectionLib.inf
      NULL                        | MdeModulePkg/Library/LzmaCustomDecompressLib/LzmaCustomDecompressLib.inf
      RegisterFilterLib           | MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
      HobLib                      | MdePkg/Library/DxeHobLib/DxeHobLib.inf
      StackCheckFailureHookLib    | MdePkg/Library/StackCheckFailureHookLibNull/StackCheckFailureHookLibNull.inf
      StackCheckLib               | MdePkg/Library/StackCheckLib/StackCheckLib.inf
      SafeIntLib                  | MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
      UefiDriverEntryPoint        | MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
      UefiBootServicesTableLib    | MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
      MemoryAllocationLib         | MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
      DebugLib                    | AdvLoggerPkg/Library/BaseDebugLibAdvancedLogger/BaseDebugLibAdvancedLogger.inf
      DebugPrintErrorLevelLib     | MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
      AdvancedLoggerLib           | AdvLoggerPkg/Library/AdvancedLoggerLib/Dxe/AdvancedLoggerLib.inf
      AssertLib                   | AdvLoggerPkg/Library/AssertLib/AssertLib.inf
  }

  #############################################################################
  ## AARCH64 OneCryptoBin END
  #############################################################################

[BuildOptions]
  *_*_*_CC_FLAGS = -D DISABLE_NEW_DEPRECATED_INTERFACES -D ENABLE_MD5_DEPRECATED_INTERFACES
  MSFT:*_*_*_DLINK_FLAGS = /IGNORE:4217
  RELEASE_*_*_CC_FLAGS = -D MDEPKG_NDEBUG

[BuildOptions.AARCH64]
  GCC:*_*_*_CC_FLAGS = -mbranch-protection=standard
