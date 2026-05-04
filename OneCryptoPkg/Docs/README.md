# OneCryptoPkg

OneCryptoPkg provides pre-built UEFI crypto drivers backed by OpenSSL (via
BaseCryptLib). Instead of each platform statically linking its own copy of
OpenSSL, OneCryptoPkg builds the crypto stack once and distributes it as
standalone EFI binaries. Platform firmware loads these binaries at boot and
accesses crypto services through a protocol interface (`gOneCryptoProtocolGuid`).

## Package Layout

| Directory            | Contents                                                  |
|----------------------|-----------------------------------------------------------|
| `OneCryptoBin/`      | Crypto binary drivers (DXE, StandaloneMm, SupvMm)         |
| `OneCryptoLoaders/`  | Loader drivers that discover, initialize, and publish Bins |
| `Library/`           | `*OnOneCrypto` shim libraries and `OneCryptoCrtLib`        |
| `Include/`           | Public protocol headers and GUIDs                          |
| `Plugin/`            | `OneCryptoBundler` — post-build packaging plugin           |
| `Docs/`              | Architecture and FAQ documentation                         |

## How It Works

OneCryptoPkg uses a **Bin + Loader** pattern. A Bin module statically links
BaseCryptLib, TlsLib, and OpenSSL. A Loader module discovers the Bin, injects
platform dependencies (memory allocation, debug output, RNG, timers) via
`OneCryptoCrtLib`, and installs the public `gOneCryptoProtocolGuid`.

Platform services are injected at runtime through `*OnOneCrypto` shim libraries
that delegate to `OneCryptoCrtLib`. This avoids hard-linking the crypto binary
to any specific platform's DebugLib, MemoryAllocationLib, etc.

See [Architecture.md](Architecture.md) for the full Bin + Loader flow, X64 vs
AARCH64 differences, and a dependency injection diagram.

## Platform Integration

To consume OneCryptoPkg in a platform:

1. **Include the Integration INFs** in your FDF to add the Bin and Loader
   drivers to the firmware volume. Pre-built INFs are in
   `OneCryptoBin/Integration/` and `OneCryptoLoaders/Integration/`.

2. **Map BaseCryptLib** to
   [`BaseCryptLibOnOneCrypto`](https://github.com/microsoft/mu_basecore/tree/release/202511/CryptoPkg/Library/BaseCryptLibOnOneCrypto)
   in your DSC for the DXE and MM phases. This redirects all BaseCryptLib
   calls through the OneCrypto protocol.

3. **Wire up the DSC/FDF** following the example in
   [mu_tiano_platforms](https://github.com/microsoft/mu_tiano_platforms) —
   see PR [#1278](https://github.com/microsoft/mu_tiano_platforms/pull/1278).

## Further Reading

- [Architecture.md](Architecture.md) — Bin + Loader pattern, X64 vs AARCH64,
  dependency injection
- [FAQs.md](FAQs.md) — Common questions about OneCryptoPkg
