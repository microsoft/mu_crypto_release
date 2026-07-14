# Frequently Asked Questions

## Can I back OneCryptoPkg with something other than Openssl?

Yes - As long as the crypto provider implements BaseCryptLib and its
dependencies are met by the `*OnOneCrypto` Libs then its as simple as
updating the DSC.

## Where can I see OneCryptoPkg integrated into a platform?

QemuQ35Pkg and QemuArmVirtPkg on
[mu_tiano_platforms](https://github.com/microsoft/mu_tiano_platforms) use the
OneCrypto binary drivers. See pull request
[Platforms: Wire up OneCrypto binary drivers](https://github.com/microsoft/mu_tiano_platforms/pull/1278).

## OneCryptoBinSupvMm is MODULE_TYPE MM_STANDALONE — how does it run in DXE?

On X64, the DXE Loader (`OneCryptoLoaderDxe`) calls `LoadImage()` on the
`MM_STANDALONE` binary so the UEFI loader applies the correct memory protections
and mappings, then parses the PE/COFF exports to find and invoke `CryptoEntry`.

AARCH64 cannot read the secure-world FV from DXE, so it either ships a dedicated
`DXE_DRIVER` Bin (dual-copy) or fetches the image from MM over
`EFI_MM_COMMUNICATION2_PROTOCOL` (single-copy). See
[Architecture.md](Architecture.md) for the full breakdown.

## Why are there both SetupEntry and NoSetupEntry in the Crypto Bin?

When a Bin module is loaded by the environment it was built for (e.g.
`OneCryptoBinDxe` dispatched by the DXE dispatcher, or `OneCryptoBinStandaloneMm`
dispatched by the MM environment), the UEFI loader natively calls all library
constructors. In this case the Loader invokes `NoSetupEntry` — no additional
setup is needed.

When a Loader loads a Bin from a **different phase** (e.g. `OneCryptoLoaderDxe`
on X64 loading the `MM_STANDALONE` binary via `LoadImage()`), the library
constructors are not automatically run because the binary's module type does
not match the executing environment. The Loader must call `SetupEntry` instead,
which manually initializes the library constructors before providing the crypto
protocol.

## Why are there multiple DXE Loaders (OneCryptoLoaderDxe, OneCryptoLoaderDxeByProtocol, OneCryptoLoaderDxeFromMm)?

They serve different architectures with fundamentally different loading
strategies:

- **`OneCryptoLoaderDxe`** (X64): locates the `MM_STANDALONE` Bin via
  `GetSectionFromAnyFv()`, `LoadImage()`s it, and resolves `CryptoEntry` from the
  PE/COFF exports. Cross-phase, so it uses `SetupEntry` to run constructors.

- **`OneCryptoLoaderDxeByProtocol`** (AARCH64): the Bin is a native `DXE_DRIVER`
  (`OneCryptoBinDxe`) already dispatched by DXE, so the loader just calls
  `LocateProtocol()` on `gOneCryptoPrivateProtocolGuid`. No `LoadImage()` or
  PE/COFF parsing, and `NoSetupEntry` since constructors already ran.

- **`OneCryptoLoaderDxeFromMm`** (AARCH64 single-copy): DXE cannot read the
  secure-world FV, so it requests the image bytes from
  `OneCryptoImageProviderStandaloneMm` over `EFI_MM_COMMUNICATION2_PROTOCOL`, then
  `LoadImage()`s the result and resolves `CryptoEntry`.

See [Architecture.md](Architecture.md) for the full X64 vs AARCH64 breakdown.
