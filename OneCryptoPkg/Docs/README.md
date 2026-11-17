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
   [`BaseCryptLibOnOneCrypto`](https://github.com/microsoft/mu_basecore/tree/release/202608/CryptoPkg/Library/BaseCryptLibOnOneCrypto)
   in your DSC for the DXE and MM phases. This redirects all BaseCryptLib
   calls through the OneCrypto protocol.

3. **Wire up the DSC/FDF** following the example in
   [mu_tiano_platforms](https://github.com/microsoft/mu_tiano_platforms) —
   see PR [#1278](https://github.com/microsoft/mu_tiano_platforms/pull/1278).

## Protocol 1.1 provider services

The protocol retains the complete 1.0 prefix and the already-published
`GetCryptoOpCapability` slot. The service tail is appended in this order:
`GetTrustAnchorX509FromAuthData`, `FreeTrustAnchorX509Cache`,
`AuthenticodeVerifyEx`, `GetAuthenticodeHashAlgorithm`, `HashAllByGuid`,
`CmsVerify`, `CmsGetSignerInfoNum`, `X509IsPublicKeySupported`.
All new services require **major 1, minor >= 1**.

**Rebuild and deploy matching providers and consumers together.** The expanded
1.1 structure has no size field. An earlier, shorter provider that already
advertises 1.1 cannot safely be detected by probing its new function pointers.
The minor-version check is not sufficient to make that old binary compatible.
Neither staging's 2.0 layout nor the removed `GetAuthenticodeHash` and
`X509GetTbsCertHash` services are part of this contract.

| Service | OpenSSL full provider | MbedTLS full provider |
|---------|-----------------------|-----------------------|
| Trust-anchor lookup/cache | Supported | Supported |
| Hash-algorithm discovery / `HashAllByGuid` | Supported | Supported |
| `AuthenticodeVerifyEx` | Requires CMS-enabled generated OpenSSL library | Verdict only; chain requests return `EFI_UNSUPPORTED` |
| `CmsVerify` | Requires CMS-enabled generated OpenSSL library | Delegates verdict-only calls to `Pkcs7Verify`; chain requests return `FALSE` |
| `CmsGetSignerInfoNum` | Supported; uses the PKCS#7 decoder when CMS is disabled | Returns zero (unsupported) |
| `X509IsPublicKeySupported` | Validates the public key and initializes verification | Supports parsed RSA/ECDSA public keys |

Production `main` currently generates OpenSSL with `OPENSSL_NO_CMS` in both
`configuration-ec.h` and `configuration-noec.h`, and omits CMS sources from its
generated INFs. In that configuration `CmsVerify` returns `FALSE`,
`CmsGetSignerInfoNum` counts records using the existing PKCS#7 decoder, and
`AuthenticodeVerifyEx` returns `EFI_UNSUPPORTED` after parameter validation.
Existing `Pkcs7Verify` and
`AuthenticodeVerify` continue using PKCS#7 verification. Open
[#302](https://github.com/microsoft/mu_crypto_release/pull/302) separately enables
CMS/PQC/TLS; this service port does not enable those features or import its
generated-source/configuration changes.

`GetAuthenticodeHashAlgorithm` discovers, but does not authenticate, the image
digest algorithm. It returns generic `gEfiHashAlgorithmSha*Guid` values from
`Protocol/Hash.h`, not certificate signature GUIDs. Pass that GUID to
`HashAllByGuid` to hash an ordinary buffer, not to compute a PE/COFF image hash.
Trust-anchor lookup matches a supplied TBS-certificate digest; it does not
authenticate the enclosing message or authorize the certificate.

`CmsVerify` requires its optional chain outputs to be supplied together.
`AuthenticodeVerifyEx` instead accepts independently optional outputs: supplying
only one still verifies without capturing a chain, and clears that output to
`NULL` or zero. MbedTLS returns `EFI_UNSUPPORTED` for an Authenticode chain
request only when both outputs are supplied. Provided outputs are also cleared
on failure or unsupported paths. A returned chain is
the signer-to-anchor path captured from successful verification, serialized as
an `EFI_CERT_STACK`; the caller releases it with `FreePool`. Capture is
best-effort: a successful verification can still return no chain if capture or
allocation fails. Callers requiring revocation checks must handle that case,
not substitute an unverified list from `Pkcs7GetSigners`.
Trust-anchor results are also caller-owned copies released with `FreePool`;
release an optional lookup cache with `FreeTrustAnchorX509Cache`.
Public-key capability is not certificate authentication or enrollment policy.

Phase-reduced instances use their existing unsupported stubs for unavailable
operations; all new symbols are defined, including count (zero), public-key
capability (`FALSE`), and CMS verification (`FALSE`). SEC/null instances
provide no crypto operations. Stub instances retain the usual debug assertions.

### Host regression coverage

`OpensslPkg/Test/OpensslPkgHostUnitTest.dsc` and
`MbedTlsPkg/Test/MbedTlsPkgHostUnitTest.dsc` include focused `CryptoServicesTest`
and null-service executables. Their normal output directories are separate:
`Build/OpensslPkg/HostTest` and `Build/MbedTlsPkg/HostTest`.
Coverage includes generic GUID selection, malformed/truncated ASN.1,
trust-anchor cache ownership, invalid RSA public exponents, CMS-disabled and
MbedTLS unsupported behavior, and null/reduced symbol availability. With a
CMS-enabled OpenSSL build, the same CMS test checks the verified chain and
rejects altered content. These tests require the matching production
`MU_BASECORE` service headers; do not replace them with staging ABI headers.

## Further Reading

- [Architecture.md](Architecture.md) — Bin + Loader pattern, X64 vs AARCH64,
  dependency injection
- [FAQs.md](FAQs.md) — Common questions about OneCryptoPkg
