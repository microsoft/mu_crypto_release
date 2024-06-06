# Crypto Driver

VERSION: 2.0

This is a pre-built version of BaseCryptLib and TlsLib built into binaries that make the services available to other
modules via dynamic interfaces such as PPIs and protocols.

This currently supports Openssl implementation of BaseCryptLib but this will be expanded in the future.

## Benefits

But first, why would you care about this?

It has a few benefits, namely:

- Smaller Binary sizes
- Easier to service/upgrade
- Transparency on what version of crypto you're using
- Reduced build times (if using pre-compiled version)
- Ability to more rigorously track crypto such as with SBOM

There are different flavors of Crypto available, with different functions supported. For example, don't need to use
HMAC in your PEI phase? Then, select a service level or flavor that doesn't include HMAC in your platform inclusion
of shared crypto.

## Considerations when migrating to using a crypto binary

Transitioning to using these binaries for platforms that previously relied on BaseCryptLib have a few decisions during
the process.

1. Platform required crypto
    You need to select what flavor of crypto works for your platform for each phase.  Cross reference the pcd.FLAVOR
    files and your platforms requires to find which one works best.  If none of them work for you the ALL flavor
    enables all cryptographic functions.

2. What ARCH to use and what they're compiled with
    Currently all the different ARCHs use VS2022 for compilation with AARCH64 being the notable exception.  This may
    have platform remifications so be mindful of that.
    NOTE: AARCH64 will be compiled with VS2022 eventually and GCC5 binaries will no longer be produced.

   If you require a crypto algorithm not available in any flavor, including `ALL`, file a feature request issue in
   this repo describing the algorithm required and a use case for that algorithm in platform firmware.

2. **Your Platform** Architecture

    For each phase, ensure you have selected the correct architecture. Failure to do so will potentially result in
    build errors and incorrect behaior during boot.

3. Dependencies Built into Shared Crypto

    Ultimately, the shared crypto binaries have dependencies that must be fulfilled by the shared crypto project
    when the binaries are built. It is important to be aware of those selections and how they may impact usage of
    the binary.

    **Feedback** on dependency selections is welcome.

    There are a couple of specific services (library selections) that you need to be aware of when it comes to crypto
    interaction.

    - **Debug Output** - The binary for each boot phase is linked against a `DebugLib` instance.
      - Currently the `Null` instance of `DebugLib` is used for most phases which means that those binaries do not emit
        debug output.
      - The `PEIM` binaries are currently linked against the [`PeiDxeDebugLibReportStatusCode`](https://github.com/microsoft/mu_basecore/tree/HEAD/MdeModulePkg/Library/PeiDxeDebugLibReportStatusCode)
      library instance which sends debug output to the report status code infrastructure.

      - The `DXE_DRIVER` binaries are currently linked against the [`UefiDebugLibDebugPortProtocol`](https://github.com/microsoft/mu_basecore/tree/HEAD/MdePkg/Library/UefiDebugLibDebugPortProtocol)
      library instance which sends messages to an instance of the
      [`EFI_DEBUGPORT_PROTOCOL`](https://github.com/microsoft/mu_basecore/blob/HEAD/MdePkg/Include/Protocol/DebugPort.h).

      - Always check `CryptoBinPkg.dsc` to verify the `DebugLib` instance linked against the crypto module type you
        depend on to verify the instance actively used.

    - **Random Number Generation (RNG)** - Crypto operations can depend on random number generation. Therefore, the
      crypto code compiled into the shared crypto binary must be linked against a method to generate random numbers.

      Currently, the following selections are made per shared crypto binary type:

      - `CryptoPei` - `PeiRngLib` which uses the Crypto PPI to provide random numbers. This means a platform module
        must produce the PPI (`gEfiRngPpiGuid`).
      - `CryptoDxe` - `DxeRngLib` which uses the Crypto protocol to provide random numbers. This means a platform
        module must produce the protocol (`gEfiRngProtocolGuid`).
      - `CryptoRuntimeDxe` - `DxeRngLib` which uses the Crypto protocol to provide randmon numbers. This means a
        platform module must produce the protocol (`gEfiRngProtocolGuid`).
      - `CryptoStandaloneMm (AARCH64)` - `BaseRngLibTimerLib` is linked to the crypto binary.
      - `CrytpStandaloneMm (X64)` - `BaseRngLib` is linked to the binary which will use the rndr instruction.
      - `CryptoSmm` - `BaseRngLib` is linked to the binary which will use the rndr instruction.

      Look for the `RngLib` instance in `CryptoBinPkg.dsc` to see the current random generation library being used.

    - **PE/COFF Binary Properties** - Each crypto binary within shared crypto is a PE32 binary with a .efi extension.
      To allow image loaders to apply page attributes to a loaded image, section alignment is set to 4KB. In some cases,
      file alignment is set to 4k as well. This is currently the case for `PEIM` binaries to support 4k section
      alignment in Execute-in-Place (XIP) environments.

### Integrating the Pre-compiled binaries

1. Include an external dependency file for the shared crypto binary release. An external is shown below.

   ```json
   {
     "scope": "global",
     "type": "nuget",
     "name": "edk2-basecrypto-driver-bin",
     "source": "https://pkgs.dev.azure.com/projectmu/mu/_packaging/Mu-Public/nuget/v3/index.json",
     "version": "2023.2.9",
     "flags": ["set_build_var"],
     "var_name": "BLD_*_SHARED_CRYPTO_PATH"
   }
   ```

   **IMPORTANT**: The `var_name` should be as specified above so the files distributed with the binaries that use that
   variable value to resolve the file paths to the binaries can resolve properly.

2. Define the service level that you want for each phase of UEFI in the defines section of your DSC.

    ```ini
    [Defines]
        DEFINE PEI_CRYPTO_SERVICES          = TINY_SHA
        DEFINE DXE_CRYPTO_SERVICES          = STANDARD
        DEFINE RUNTIMEDXE_CRYPTO_SERVICES   = NONE
        DEFINE SMM_CRYPTO_SERVICES          = STANDARD
        DEFINE STANDALONEMM_CRYPTO_SERVICES = NONE
        DEFINE PEI_CRYPTO_ARCH              = IA32
        DEFINE DXE_CRYPTO_ARCH              = X64
        DEFINE RUNTIMEDXE_CRYPTO_ARCH       = NONE
        DEFINE SMM_CRYPTO_ARCH              = X64
        DEFINE STANDALONEMM_CRYPTO_ARCH     = NONE
    ```

    The above example is for a standard intel platform, and the service levels or flavors available.

    All these DEFINE statements are required but if you set them to NONE you do not need to include the crypto arch
    for that module type.

3. Add the DSC include

    ```ini
    !include $(SHARED_CRYPTO_PATH)/Driver/Bin/CryptoDriver.inc.dsc
    ```

    This sets the definitions for BaseCryptLib as well as includes the correct flavor level of the component you
    wish to use.

4. Add the FDF includes to your platform FDF

    Currently, it isn't possible in an FDF to redefine a FV section and have them be combined.
    There are two includes: BOOTBLOCK and DXE.
    The first includes the PEI phase and is meant to be stuck in your BOOTBLOCK FV.
    The second contains the DXE and SMM modules and is meant to be stuck in your FVDXE.

    ```ini
    [FV.FVBOOTBLOCK]
      ...
    !include $(SHARED_CRYPTO_PATH)/Driver/Bin/CryptoDriver.PEI.inc.fdf
    ...

    ```ini
    [FV.FVDXE]
      ...
      !include $(SHARED_CRYPTO_PATH)/Driver/Bin/CryptoDriver.DXE.inc.fdf
      !include $(SHARED_CRYPTO_PATH)/Driver/Bin/CryptoDriver.RUNTIMEDXE.inc.fdf
      !include $(SHARED_CRYPTO_PATH)/Driver/Bin/CryptoDriver.SMM.inc.fdf
      !include $(SHARED_CRYPTO_PATH)/Driver/Bin/CryptoDriver.STANDALONEMM.inc.fdf
    ```

    NOTE: Again. you don't need to include every one of these fdf files if you won't use them.
