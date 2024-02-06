# Crypto Driver

VERSION: 2.0

This is a potentially prepacked version of the BaseCryptLib and TlsLib, delivered via protocol.

This currently supports Openssl implementation of BaseCryptLib but this will be expanded in the future.

## Benefits

But first, why would you care about this?

It has a few benefits, namely:

- Smaller Binary sizes
- Easier to service/upgrade
- Transparency on what version of crypto you're using
- Reduced build times (if using pre-compiled version)

There are different flavors of Crypto available, with different functions supported.
Don't need to use HMAC in your PEI phase?
Select a service level or flavor that doesn't include HMAC in your platform.

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

1. Define the service level that you want for each phase of UEFI in the defines section of your DSC.

    ``` dsc
    [Defines]
        DEFINE PEI_CRYPTO_SERVICES = TINY_SHA
        DEFINE DXE_CRYPTO_SERVICES = STANDARD
        DEFINE SMM_CRYPTO_SERVICES = STANDARD
        DEFINE STANDALONEMM_CRYPTO_SERVICES = NONE
        DEFINE PEI_CRYPTO_ARCH = IA32
        DEFINE DXE_CRYPTO_ARCH = X64
    ```

    The above example is for a standard intel platform, and the service levels or flavors available.
    All these DEFINE statements are required but if you set them to NONE you do not need to include the crypto arch
    for that module type.

2. Add the DSC include

    ``` dsc
    !include edk2-basecrypto-driver-bin_extdep/Driver/Bin/CryptoDriver.inc.dsc
    ```

    This sets the definitions for BaseCryptLib as well as includes the correct flavor level of the component you
    wish to use.

3. Add the FDF includes to your platform FDF

    Currently, it isn't possible in an FDF to redefine a FV section and have them be combined.
    There are two includes: BOOTBLOCK and DXE.
    The first includes the PEI phase and is meant to be stuck in your BOOTBLOCK FV.
    The second contains the DXE and SMM modules and is meant to be stuck in your FVDXE.

    ``` fdf
    [FV.FVBOOTBLOCK]
      ...
    !include edk2-basecrypto-driver-bin_extdep/Driver/Bin/CryptoDriver.PEI.inc.fdf
    ...

    [FV.FVDXE]
      ...
      !include edk2-basecrypto-driver-bin_extdep/Driver/Bin/CryptoDriver.DXE.inc.fdf
      !include edk2-basecrypto-driver-bin_extdep/Driver/Bin/CryptoDriver.SMM.inc.fdf
      !include edk2-basecrypto-driver-bin_extdep/Driver/Bin/CryptoDriver.STANDALONEMM.inc.fdf
    ```

    NOTE: Again. you don't need to include every one of these fdf files if you won't use them.

### The DIY way

If you want to take advantage of the BaseCryptOnProtocol but don't want to use a pre-compiled method, you can compile
it within your platform itself.  This requires taking the mu_crypto_release repo as a submodule.

Shown here is for an Intel platform, adjust the architectures as needed.

``` dsc

[LibraryClasses.IA32]
  BaseCryptLib|OpensslPkg/Library/BaseCryptLibOnProtocolPpi/PeiCryptLib.inf
  TlsLib|OpensslPkg/Library/BaseCryptLibOnProtocolPpi/PeiCryptLib.inf

[LibraryClasses.X64]
  BaseCryptLib|OpensslPkg/Library/BaseCryptLibOnProtocolPpi/DxeCryptLib.inf
  TlsLib|OpensslPkg/Library/BaseCryptLibOnProtocolPpi/DxeCryptLib.inf

[LibraryClasses.X64.DXE_SMM_DRIVER]
  BaseCryptLib|OpensslPkg/Library/BaseCryptLibOnProtocolPpi/SmmCryptLib.inf
  TlsLib|OpensslPkg/Library/BaseCryptLibOnProtocolPpi/SmmCryptLib.inf

[LibraryClasses.X64.MM_STANDALONE, LibraryClasses.X64.MM_CORE_STANDALONE]
  BaseCryptLib|OpensslPkg/Library/BaseCryptLibOnProtocolPpi/StandaloneMmCryptLib.inf
  TlsLib|OpensslPkg/Library/BaseCryptLibOnProtocolPpi/StandaloneMmCryptLib.inf

[Components.IA32]
  OpensslPkg/Driver/CryptoPei.inf {
      <LibraryClasses>
        BaseCryptLib|OpensslPkg/Library/BaseCryptLib/PeiCryptLib.inf
        TlsLib|CryptoPkg/Library/TlsLibNull/TlsLibNull.inf
      <PcdsFixedAtBuild>
        .. All the flavor PCDs here ..
  }

[Components.X64]
  OpensslPkg/Driver/CryptoDxe.inf {
      <LibraryClasses>
        BaseCryptLib|OpensslPkg/Library/BaseCryptLib/BaseCryptLib.inf
        TlsLib|OpensslPkg/Library/TlsLib/TlsLib.inf
      <PcdsFixedAtBuild>
        .. All the flavor PCDs here ..
  }
  OpensslPkg/Driver/CryptoSmm.inf {
      <LibraryClasses>
        BaseCryptLib|OpensslPkg/Library/BaseCryptLib/SmmCryptLib.inf
        TlsLib|CryptoPkg/Library/TlsLibNull/TlsLibNull.inf
      <PcdsFixedAtBuild>
        .. All the flavor PCDs here ..
  }
  OpensslPkg/Driver/CryptoStandaloneMm.inf {
      <LibraryClasses>
        BaseCryptLib|OpensslPkg/Library/BaseCryptLib/SmmCryptLib.inf
        TlsLib|CryptoPkg/Library/TlsLibNull/TlsLibNull.inf
      <PcdsFixedAtBuild>
        .. All the flavor PCDs here ..
  }
```

The PCDs are long and default to all false.
The flavors are stored as .inc.dsc files at `OpensslPkg\Driver\Packaging`.
An example would be `OpensslPkg\Driver\Packaging\Crypto.pcd.TINY_SHA.inc.dsc` which is a flavor that just has Sha1,
Sha256, and Sha386.

You'll need to include these components in your FDF as well.

``` fdf
[FV.FVBOOTBLOCK]
  INF OpensslPkg/Driver/CryptoPei.inf
[FV.FVDXE]
  INF OpensslPkg/Driver/CryptoSmm.inf
  INF OpensslPkg/Driver/CryptoStandaloneMm.inf
  INF OpensslPkg/Driver/CryptoDxe.inf
```
