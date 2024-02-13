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

3. Library consideration
    There are a couple of specific libraries that you need to be aware of when it comes to crypto interaction
    - DebugLib is set in the binary itself and is not effected by the platform.  Currently the MM crypto is
      using a null debug lib
    - RngLib does effect the crypto binaries.  Which RngLib you use will have effects on crypto.  For example for
      AARCH64 platforms ArmTrngLib and BaseRngLib effect eachother which causes issues.  Dependencies like that can
      lead to complications while integrating the crypto binaries.

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
