# ECIT Capability Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `GetCryptoOpCapability(OpIdGuid, Buffer, BufferSize)` to BaseCryptLib and `ONE_CRYPTO_PROTOCOL`, with two v1 operations (`gCryptoOpPkcs7VerifyGuid`, `gCryptoOpAuthenticodeVerifyGuid`) that answer at call time by enumerating the linked OpenSSL provider and filtering through a verify-pipeline-owned predicate. No const OID arrays; no boot-time drift gate.

**Architecture:** A single dispatcher in a new `Pk/CryptoOpCapability.c` looks up `OpIdGuid` in a static `CRYPTO_OP_DISPATCH mDispatch[]` table and delegates to per-op handlers that live next to their verify pipeline (`CryptPkcs7VerifyCommon.c`, `CryptAuthenticode.c`). Each handler calls a shared `EnumerateProviderSignatureOids` helper that walks OpenSSL's digest × pk-type cross-product via `EVP_MD_do_all_provided` + `OBJ_find_sigid_by_algs`, then filters NIDs through a small predicate the handler owns. The result is emitted as a CSV-encoded, NUL-terminated ASCII payload (unordered set semantics). `BaseCryptLibOnOneCrypto` forwards through the protocol; `OneCryptoBin` assigns the BaseCryptLib symbol into the protocol struct.

**Tech Stack:** EDK2 C (BaseCryptLib over OpenSSL 4.x EVP API), `UnitTestLib` host tests via `stuart_ci_build`, Project Mu `OneCryptoBin` cross-phase binary.

---

## Source Spec

See [docs/superpowers/specs/2026-06-01-ecit-capability-reporting-design.md](../specs/2026-06-01-ecit-capability-reporting-design.md). This plan implements **§4 only** (the in-scope binary-side surface). §5 (collector, `CryptoConformanceApp`) is intentionally not implemented here.

## Deviation from Spec: MINOR not MAJOR bump

The spec text in §4.3 and §7.2 calls for bumping `ONE_CRYPTO_VERSION_MAJOR` and rejecting consumers with `EFI_INCOMPATIBLE_VERSION` on strict major mismatch. **This plan instead bumps `ONE_CRYPTO_VERSION_MINOR` from `0` to `1`.** Reasoning:

- The `ONE_CRYPTO_PROTOCOL` struct in [MU_BASECORE/CryptoPkg/Include/Protocol/OneCrypto.h](../../../MU_BASECORE/CryptoPkg/Include/Protocol/OneCrypto.h) documents its own contract: `Major - Breaking change to this structure; Minor - Functions added to the end of this structure`. Appending one function pointer is the textbook MINOR case.
- The existing `ValidateCryptoVersion()` in [MU_BASECORE/CryptoPkg/Library/BaseCryptLibOnOneCrypto/OneCryptoLib.c](../../../MU_BASECORE/CryptoPkg/Library/BaseCryptLibOnOneCrypto/OneCryptoLib.c) already implements the graceful `<` (less-than) comparison via the `CALL_CRYPTO_SERVICE(Function, Args, ErrorReturnValue, MinMajor, MinMinor)` macro. A new function declares its required minor at the call site (`MinMajor=1, MinMinor=1`); older binaries return `EFI_UNSUPPORTED` cleanly without rebuilds for unrelated consumers.
- A MAJOR bump would break every consumer of `ONE_CRYPTO_PROTOCOL` for a strictly additive change.

**Atomicity:** The minor bump and the `CryptoProtocol->GetCryptoOpCapability = ...` assignment in `OneCryptoBin` land in the **same commit** (Task 7). Reason: if the bump landed earlier, a consumer that reads `Major == 1, Minor >= 1` would dereference a NULL/garbage function pointer (the existing `CryptoInit` does field-by-field assignment with no zero-init of the struct, so an unassigned field is garbage). Bumping with the assignment guarantees `Minor >= 1` ⇒ field is valid.

If the spec author wants strict MAJOR semantics for this change, swap the bump direction in Task 7 (change `MINOR` constant edit to `MAJOR`) and update Task 6's `CALL_CRYPTO_SERVICE` minor arg back to `0`. The rest of the plan is unaffected.

---

## File Structure Map

### Files to CREATE

| File | Responsibility |
|---|---|
| `MU_BASECORE/CryptoPkg/Include/Library/CryptoCapability.h` | Public `extern` GUIDs (`gCryptoOpPkcs7VerifyGuid`, `gCryptoOpAuthenticodeVerifyGuid`) and `GetCryptoOpCapability` prototype. |
| `OpensslPkg/Library/BaseCryptLib/Pk/CryptoOpCapability.c` | Dispatcher (`GetCryptoOpCapability`), `EnumerateProviderSignatureOids` helper, `mDispatch[]` table. **Linked by every OpenSSL BaseCryptLib INF** (DXE, PEI, SEC, SMM, Runtime, UnitTestHost). |
| `MbedTlsPkg/Library/BaseCryptLib/Pk/CryptoOpCapabilityNull.c` | MbedTLS-side standalone Null `GetCryptoOpCapability` (returns `EFI_NOT_FOUND`). MbedTLS doesn't get the OpenSSL provider-enumeration dispatcher in v1. |
| `MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/CryptoOpCapabilityTests.c` | Host tests for dispatcher, enumeration helper, both per-op handlers, and `IsAuthenticodeSigNidAccepted`. |

### Files to MODIFY

| File | What changes |
|---|---|
| `MU_BASECORE/CryptoPkg/Include/Protocol/OneCrypto.h` | Task 1: add `ONE_CRYPTO_GET_OP_CAPABILITY` typedef, append `GetCryptoOpCapability` field. Task 7: bump `ONE_CRYPTO_VERSION_MINOR` from `0` to `1` (atomic with field assignment). |
| `MU_BASECORE/CryptoPkg/CryptoPkg.dec` | Add two new GUIDs to `[Guids]`. |
| `OpensslPkg/Library/BaseCryptLib/InternalCryptLib.h` | Prototypes for `EnumerateProviderSignatureOids`, `IsAuthenticodeSigNidAccepted`, `Pkcs7VerifyOpCapability`, `AuthenticodeOpCapability`. |
| `OpensslPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyCommon.c` | Add `Pkcs7AcceptAll` predicate + `Pkcs7VerifyOpCapability` handler. |
| `OpensslPkg/Library/BaseCryptLib/Pk/CryptAuthenticode.c` | Add `IsAuthenticodeSigNidAccepted` predicate (mirrors `AuthenticodeExpectedDigestNid` accept-set) + `AuthenticodeOpCapability` handler. |
| `OpensslPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyNull.c` | Null stub of `Pkcs7VerifyOpCapability` returning empty payload. |
| `OpensslPkg/Library/BaseCryptLib/Pk/CryptAuthenticodeNull.c` | Null stubs of `IsAuthenticodeSigNidAccepted` (returns `FALSE`) and `AuthenticodeOpCapability` (returns empty payload). |
| `OpensslPkg/Library/BaseCryptLib/BaseCryptLib.inf` | Add new `Pk/CryptoOpCapability.c` to `[Sources]`; add `[Guids]` entries. |
| `OpensslPkg/Library/BaseCryptLib/UnitTestHostBaseCryptLib.inf` | Add `Pk/CryptoOpCapability.c` (full dispatcher; INF already links full Pkcs7 + Authenticode). |
| `OpensslPkg/Library/BaseCryptLib/PeiCryptLib.inf`, `SecCryptLib.inf`, `RuntimeCryptLib.inf`, `SmmCryptLib.inf` | Add `Pk/CryptoOpCapability.c` to `[Sources]` (full dispatcher; handlers resolve to Null or full variants as each INF already links them). |
| `MbedTlsPkg/Library/BaseCryptLib/BaseCryptLib.inf` (and all phase-specific variants) | Add `Pk/CryptoOpCapabilityNull.c` (MbedTLS-only standalone Null since the OpenSSL-API dispatcher isn't portable to MbedTLS in v1). |
| `MU_BASECORE/CryptoPkg/Library/BaseCryptLibOnOneCrypto/OneCryptoLib.c` | Add `GetCryptoOpCapability` forwarder using `CALL_CRYPTO_SERVICE(GetCryptoOpCapability, ..., 1, 1)`. |
| `OneCryptoPkg/OneCryptoBin/OneCryptoBin.c` | Assign `CryptoProtocol->GetCryptoOpCapability = GetCryptoOpCapability;` in `CryptoInit` **and** bump `ONE_CRYPTO_VERSION_MINOR` in the header in the same commit. |
| `MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/TestBaseCryptLib.h` | Add `extern UINTN mCryptoOpCapabilityTestNum;` and `extern TEST_DESC mCryptoOpCapabilityTest[];`. |
| `MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/BaseCryptLibUnitTests.c` | Append new entry to `mSuiteDesc[]`. |
| `MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/TestBaseCryptLibHost.inf` | Add `CryptoOpCapabilityTests.c` to `[Sources]`. |

### Repository Commit Boundaries

`MU_BASECORE` is fetched by `stuart_ci_setup` as a `GetDependencies()` repo (see [PlatformBuild.py](../../../PlatformBuild.py) lines 60–80; currently pinned to `flickdm/mu_basecore` branch `update/Pqc-BaseCryptLibUnitTests`). It has its own `.git` directory. **Commits affecting `MU_BASECORE/...` files must be made from inside `MU_BASECORE/`**, not from the `mu_crypto_release` root. Each task below that touches MU_BASECORE files calls this out in its commit step.

---

## Build & Test Cheat Sheet

All commands run from the workspace root (`/home/dougflick/git/flickdm/mu_crypto_release`).

```bash
# Host unit tests (OpenSSL flavor) — used by Tasks 2, 3, 4
stuart_ci_build -c .pytool/CISettings.py -p OpensslPkg -t NOOPT \
    -d HostUnitTestCompilerPlugin=run TOOL_CHAIN_TAG=GCC5

# Multi-flavor target build (PEI/Sec/Smm/Runtime stubs compile) — used by Task 5
stuart_ci_build -c .pytool/CISettings.py -p OpensslPkg -t DEBUG TOOL_CHAIN_TAG=CLANGPDB

# MbedTLS build — used by Task 8
stuart_ci_build -c .pytool/CISettings.py -p MbedTlsPkg -t DEBUG TOOL_CHAIN_TAG=CLANGPDB

# OneCryptoBin build — used by Tasks 6, 7, 9
stuart_build -c PlatformBuild.py -a X64 -t DEBUG TOOL_CHAIN_TAG=CLANGPDB
```

Host-test binary location after a successful run:
`Build/OpensslPkg/HostTest/NOOPT_GCC5/X64/BaseCryptLibUnitTestHost` — run it directly to see per-suite pass/fail.

---

## Task 1: Protocol surface + GUIDs + public header

**Files:**
- Modify: `MU_BASECORE/CryptoPkg/Include/Protocol/OneCrypto.h`
- Modify: `MU_BASECORE/CryptoPkg/CryptoPkg.dec`
- Create: `MU_BASECORE/CryptoPkg/Include/Library/CryptoCapability.h`

This is foundation only — no functional behavior yet. The protocol minor version stays at `0`; Task 7 bumps it to `1` simultaneously with assigning the field, so consumers never observe `Minor >= 1` while the field is unassigned.

- [ ] **Step 1: Add `ONE_CRYPTO_GET_OP_CAPABILITY` typedef to `OneCrypto.h`**

In [MU_BASECORE/CryptoPkg/Include/Protocol/OneCrypto.h](../../../MU_BASECORE/CryptoPkg/Include/Protocol/OneCrypto.h), find the existing `ONE_CRYPTO_*` typedef block immediately preceding the `_ONE_CRYPTO_PROTOCOL` struct (just before line ~5260). Add:

```c
/**
  Return the capability descriptor for a given crypto operation.

  The descriptor is an opaque, operation-specific byte payload. For
  verification operations the payload is a CSV-encoded ASCII string of
  algorithm OIDs (e.g. "1.2.840.113549.1.1.11,1.2.840.10045.4.3.2") with
  a trailing NUL. The OIDs are an UNORDERED SET: callers must not infer
  preference from position.

  @param[in]      OpIdGuid    GUID identifying the crypto operation.
  @param[out]     Buffer      NULL to probe required size, else receives payload.
  @param[in,out]  BufferSize  In: size of Buffer. Out: bytes written or required.

  @retval EFI_SUCCESS           Buffer populated (or size returned if Buffer NULL).
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small; *BufferSize set to required.
  @retval EFI_NOT_FOUND         OpIdGuid is unknown to this binary.
  @retval EFI_INVALID_PARAMETER OpIdGuid or BufferSize is NULL.
**/
typedef
EFI_STATUS
(EFIAPI *ONE_CRYPTO_GET_OP_CAPABILITY)(
  IN     CONST EFI_GUID  *OpIdGuid,
  OUT    VOID            *Buffer       OPTIONAL,
  IN OUT UINTN           *BufferSize
  );
```

- [ ] **Step 2: Append `GetCryptoOpCapability` to the `_ONE_CRYPTO_PROTOCOL` struct**

In the same file, find the last existing field in `typedef struct _ONE_CRYPTO_PROTOCOL { ... }` — currently `ONE_CRYPTO_GET_CRYPTO_PROVIDER_VERSION_STRING GetCryptoProviderVersionString;` per [OneCrypto.h#L5348](../../../MU_BASECORE/CryptoPkg/Include/Protocol/OneCrypto.h). Add immediately after it, before the closing brace:

```c
  /// v1.1 ECIT capability reporting -----------------------------------------
  ONE_CRYPTO_GET_OP_CAPABILITY                      GetCryptoOpCapability;
```

**Do NOT bump `ONE_CRYPTO_VERSION_MINOR` in this task.** It stays at `0`. Task 7 bumps it.

- [ ] **Step 3: Add new GUIDs to `CryptoPkg.dec`**

In [MU_BASECORE/CryptoPkg/CryptoPkg.dec](../../../MU_BASECORE/CryptoPkg/CryptoPkg.dec), find the existing `[Guids]` section (around line 45). Append:

```ini
  ## ECIT capability reporting — operation identifier GUIDs.
  #  Payload returned by GetCryptoOpCapability() for each op is a CSV-encoded,
  #  NUL-terminated ASCII string of algorithm OIDs (unordered set).
  gCryptoOpPkcs7VerifyGuid        = { 0x6cc2d4b1, 0x7a93, 0x4d51, { 0x9c, 0x4a, 0x12, 0x8e, 0xb4, 0x05, 0x7f, 0x21 } }
  gCryptoOpAuthenticodeVerifyGuid = { 0x9f3e1bd6, 0x2c0a, 0x4b8e, { 0xab, 0x1f, 0x74, 0x29, 0xd0, 0x83, 0xe1, 0x66 } }
```

(These GUIDs were generated for this design. They are stable forever once committed.)

- [ ] **Step 4: Create the public header `CryptoCapability.h`**

Create [MU_BASECORE/CryptoPkg/Include/Library/CryptoCapability.h](../../../MU_BASECORE/CryptoPkg/Include/Library/CryptoCapability.h):

```c
/** @file
  Public API for ECIT (EFI Crypto Indicator Table) capability reporting.

  GetCryptoOpCapability() lets feature owners ask the linked crypto binary
  "what algorithms do you actually accept for operation X?" at call time.
  The answer is an unordered set of OID strings, CSV-encoded, NUL-terminated;
  empty payload (one NUL byte) means "no algorithm accepted by the verify
  pipeline is supported by the linked provider in this build."

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef CRYPTO_CAPABILITY_H_
#define CRYPTO_CAPABILITY_H_

#include <Uefi.h>

//
// Operation-ID GUIDs. Defined in CryptoPkg.dec [Guids] section; declared
// extern here for consumers.
//
extern EFI_GUID  gCryptoOpPkcs7VerifyGuid;
extern EFI_GUID  gCryptoOpAuthenticodeVerifyGuid;

/**
  Return the capability descriptor for a given crypto operation.

  See ONE_CRYPTO_GET_OP_CAPABILITY in Protocol/OneCrypto.h for full contract.

  @param[in]      OpIdGuid    GUID identifying the crypto operation.
  @param[out]     Buffer      NULL to probe required size, else receives payload.
  @param[in,out]  BufferSize  In: size of Buffer. Out: bytes written or required.

  @retval EFI_SUCCESS           Buffer populated (or size returned if Buffer NULL).
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small; *BufferSize set to required.
  @retval EFI_NOT_FOUND         OpIdGuid is unknown to this binary.
  @retval EFI_INVALID_PARAMETER OpIdGuid or BufferSize is NULL.
**/
EFI_STATUS
EFIAPI
GetCryptoOpCapability (
  IN     CONST EFI_GUID  *OpIdGuid,
  OUT    VOID            *Buffer       OPTIONAL,
  IN OUT UINTN           *BufferSize
  );

#endif // CRYPTO_CAPABILITY_H_
```

- [ ] **Step 5: Verify the protocol header compiles by building OneCryptoPkg**

```bash
stuart_build -c PlatformBuild.py -a X64 -t DEBUG TOOL_CHAIN_TAG=CLANGPDB
```

Expected: build succeeds. The new struct field exists but is unassigned in `CryptoInit` until Task 7. Because we did not bump the minor version, no consumer will claim the field is valid yet.

- [ ] **Step 6: Commit MU_BASECORE-side foundation**

```bash
cd MU_BASECORE
git add CryptoPkg/Include/Protocol/OneCrypto.h \
        CryptoPkg/Include/Library/CryptoCapability.h \
        CryptoPkg/CryptoPkg.dec
git commit -s -m "CryptoPkg: add GetCryptoOpCapability protocol field and public API

Appends ONE_CRYPTO_GET_OP_CAPABILITY function pointer to the end of
ONE_CRYPTO_PROTOCOL. Introduces public header CryptoCapability.h
declaring GetCryptoOpCapability and two op-ID GUIDs (PKCS#7 verify,
Authenticode verify) for ECIT capability reporting.

The minor version bump (1.0 -> 1.1) is deferred to the OneCryptoBin
commit that assigns the function pointer in CryptoInit, so consumers
never observe Minor>=1 while the field is unassigned.

Implementation of the dispatcher and per-op handlers follows in
OpensslPkg."
cd ..
```

(No `mu_crypto_release` commit yet — there are no changes outside `MU_BASECORE` in this task.)

---

## Task 2: Test scaffolding — placeholder suite

**Files:**
- Create: `MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/CryptoOpCapabilityTests.c`
- Modify: `MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/TestBaseCryptLib.h`
- Modify: `MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/BaseCryptLibUnitTests.c`
- Modify: `MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/TestBaseCryptLibHost.inf`

A placeholder suite that asserts trivially is added first so the build wiring is verified end-to-end before real tests land. Tasks 3 and 4 fill in real test cases.

- [ ] **Step 1: Create the test file with a single placeholder test**

Create [MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/CryptoOpCapabilityTests.c](../../../MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/CryptoOpCapabilityTests.c):

```c
/** @file
  Host-based unit tests for GetCryptoOpCapability dispatch and per-op
  handlers in BaseCryptLib.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "TestBaseCryptLib.h"
#include <Library/CryptoCapability.h>

STATIC
UNIT_TEST_STATUS
EFIAPI
TestPlaceholder (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  // Real test cases land in Tasks 3 and 4. This placeholder verifies the
  // test wiring (suite registration, INF [Sources], header include path)
  // is correct before any real implementation exists.
  UT_ASSERT_TRUE (TRUE);
  return UNIT_TEST_PASSED;
}

TEST_DESC  mCryptoOpCapabilityTest[] = {
  //
  // -----Description--------------Class----------------------Function----------Pre---Post--Context
  //
  { "TestPlaceholder",  "CryptoPkg.BaseCryptLib.OpCapability", TestPlaceholder, NULL, NULL, NULL },
};

UINTN  mCryptoOpCapabilityTestNum = ARRAY_SIZE (mCryptoOpCapabilityTest);
```

- [ ] **Step 2: Add externs to `TestBaseCryptLib.h`**

In [MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/TestBaseCryptLib.h](../../../MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/TestBaseCryptLib.h), find the last `extern UINTN` / `extern TEST_DESC` pair (currently `mPqcTestNum` / `mPqcTest`). Append immediately after:

```c
extern UINTN      mCryptoOpCapabilityTestNum;
extern TEST_DESC  mCryptoOpCapabilityTest[];
```

- [ ] **Step 3: Register the suite in `BaseCryptLibUnitTests.c`**

In [MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/BaseCryptLibUnitTests.c](../../../MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/BaseCryptLibUnitTests.c), find the `mSuiteDesc[]` array. Append immediately before the closing `};`:

```c
  { "Crypto op capability tests",    "CryptoPkg.BaseCryptLib", NULL, NULL, &mCryptoOpCapabilityTestNum, mCryptoOpCapabilityTest },
```

- [ ] **Step 4: Add to `TestBaseCryptLibHost.inf` [Sources]**

In [MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/TestBaseCryptLibHost.inf](../../../MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/TestBaseCryptLibHost.inf), in the `[Sources]` block, add a line after `PqcTests.c`:

```ini
  CryptoOpCapabilityTests.c
```

- [ ] **Step 5: Run host tests, expect the placeholder to pass**

```bash
stuart_ci_build -c .pytool/CISettings.py -p OpensslPkg -t NOOPT \
    -d HostUnitTestCompilerPlugin=run TOOL_CHAIN_TAG=GCC5
```

Expected: build succeeds, all suites pass including the new `Crypto op capability tests` suite (1/1 — `TestPlaceholder`). Look for `[PASS] TestPlaceholder` in stdout.

- [ ] **Step 6: Commit test scaffolding**

```bash
cd MU_BASECORE
git add CryptoPkg/Test/UnitTest/Library/BaseCryptLib/CryptoOpCapabilityTests.c \
        CryptoPkg/Test/UnitTest/Library/BaseCryptLib/TestBaseCryptLib.h \
        CryptoPkg/Test/UnitTest/Library/BaseCryptLib/BaseCryptLibUnitTests.c \
        CryptoPkg/Test/UnitTest/Library/BaseCryptLib/TestBaseCryptLibHost.inf
git commit -s -m "CryptoPkg/Test: add CryptoOpCapability test suite scaffolding

Placeholder TEST_DESC array wired into the BaseCryptLib host test
suite. Real test cases land alongside the dispatcher and per-op
handlers in subsequent commits."
cd ..
```

---

## Task 3: PKCS#7 op end-to-end (dispatcher + helper + first handler, TDD)

**Files:**
- Modify: `MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/CryptoOpCapabilityTests.c`
- Modify: `OpensslPkg/Library/BaseCryptLib/InternalCryptLib.h`
- Create: `OpensslPkg/Library/BaseCryptLib/Pk/CryptoOpCapability.c`
- Modify: `OpensslPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyCommon.c`
- Modify: `OpensslPkg/Library/BaseCryptLib/BaseCryptLib.inf`
- Modify: `OpensslPkg/Library/BaseCryptLib/UnitTestHostBaseCryptLib.inf` (host tests link this INF, not `BaseCryptLib.inf`, so the dispatcher must land in both to compile + link the host tests)

- [ ] **Step 1: Write failing tests for `GetCryptoOpCapability` + PKCS#7 handler**

Replace the placeholder body of [CryptoOpCapabilityTests.c](../../../MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/CryptoOpCapabilityTests.c) with:

```c
/** @file
  Host-based unit tests for GetCryptoOpCapability dispatch and per-op
  handlers in BaseCryptLib.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "TestBaseCryptLib.h"
#include <Library/CryptoCapability.h>
#include <Library/BaseMemoryLib.h>

//
// Arbitrary GUID known not to be registered, used for EFI_NOT_FOUND checks.
//
STATIC EFI_GUID  mBogusOpGuid = {
  0xdeadbeef, 0xcafe, 0xbabe, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }
};

STATIC
UNIT_TEST_STATUS
EFIAPI
TestNullParamsRejected (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS  Status;
  UINTN       Size;
  CHAR8       Buf[16];

  Size   = sizeof (Buf);
  Status = GetCryptoOpCapability (NULL, Buf, &Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_INVALID_PARAMETER);

  Status = GetCryptoOpCapability (&gCryptoOpPkcs7VerifyGuid, Buf, NULL);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_INVALID_PARAMETER);

  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestUnknownGuidReturnsNotFound (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS  Status;
  UINTN       Size;

  Size   = 0;
  Status = GetCryptoOpCapability (&mBogusOpGuid, NULL, &Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_NOT_FOUND);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestPkcs7SizingProbe (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS  Status;
  UINTN       Size;

  // Sizing probe: Buffer NULL, BufferSize 0 in, receives required size out,
  // returns SUCCESS. Required size must include the trailing NUL byte
  // (>= 1 even for empty result).
  Size   = 0;
  Status = GetCryptoOpCapability (&gCryptoOpPkcs7VerifyGuid, NULL, &Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_TRUE (Size >= 1);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestPkcs7FetchPayload (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS  Status;
  UINTN       Size;
  CHAR8       *Buf;

  Size   = 0;
  Status = GetCryptoOpCapability (&gCryptoOpPkcs7VerifyGuid, NULL, &Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_TRUE (Size >= 1);

  Buf = AllocatePool (Size);
  UT_ASSERT_NOT_NULL (Buf);

  Status = GetCryptoOpCapability (&gCryptoOpPkcs7VerifyGuid, Buf, &Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);

  // Last byte must be NUL (CSV is NUL-terminated).
  UT_ASSERT_EQUAL (Buf[Size - 1], '\0');

  // OpenSSL-backed PKCS#7 verify accepts at least sha256WithRSAEncryption
  // (OID 1.2.840.113549.1.1.11) in every supported build of this repo,
  // so the CSV payload must contain that OID.
  UT_ASSERT_NOT_NULL (AsciiStrStr (Buf, "1.2.840.113549.1.1.11"));

  FreePool (Buf);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestPkcs7BufferTooSmall (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS  Status;
  UINTN       Size;
  UINTN       Required;
  CHAR8       Tiny[1];

  Required = 0;
  Status   = GetCryptoOpCapability (&gCryptoOpPkcs7VerifyGuid, NULL, &Required);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_TRUE (Required > 1);

  Size   = sizeof (Tiny);  // 1 byte — strictly less than Required.
  Status = GetCryptoOpCapability (&gCryptoOpPkcs7VerifyGuid, Tiny, &Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_BUFFER_TOO_SMALL);
  UT_ASSERT_EQUAL (Size, Required);
  return UNIT_TEST_PASSED;
}

TEST_DESC  mCryptoOpCapabilityTest[] = {
  { "TestNullParamsRejected",      "CryptoPkg.BaseCryptLib.OpCapability", TestNullParamsRejected,      NULL, NULL, NULL },
  { "TestUnknownGuidReturnsNotFound", "CryptoPkg.BaseCryptLib.OpCapability", TestUnknownGuidReturnsNotFound, NULL, NULL, NULL },
  { "TestPkcs7SizingProbe",        "CryptoPkg.BaseCryptLib.OpCapability", TestPkcs7SizingProbe,        NULL, NULL, NULL },
  { "TestPkcs7FetchPayload",       "CryptoPkg.BaseCryptLib.OpCapability", TestPkcs7FetchPayload,       NULL, NULL, NULL },
  { "TestPkcs7BufferTooSmall",     "CryptoPkg.BaseCryptLib.OpCapability", TestPkcs7BufferTooSmall,     NULL, NULL, NULL },
};

UINTN  mCryptoOpCapabilityTestNum = ARRAY_SIZE (mCryptoOpCapabilityTest);
```

- [ ] **Step 2: Run tests, expect link failure (unresolved `GetCryptoOpCapability`)**

```bash
stuart_ci_build -c .pytool/CISettings.py -p OpensslPkg -t NOOPT \
    -d HostUnitTestCompilerPlugin=run TOOL_CHAIN_TAG=GCC5
```

Expected: link FAILS with "undefined reference to `GetCryptoOpCapability`" because no implementation exists yet.

- [ ] **Step 3: Add internal prototypes to `InternalCryptLib.h`**

In [OpensslPkg/Library/BaseCryptLib/InternalCryptLib.h](../../../OpensslPkg/Library/BaseCryptLib/InternalCryptLib.h), append before the file's `#endif`:

```c
//
// ECIT capability reporting — internal helpers (Pk/CryptoOpCapability.c)
//

/**
  Predicate callback used by EnumerateProviderSignatureOids to decide whether
  to emit a given signature NID. Implementations live next to the verify
  pipeline that owns the operation.

  @param[in]  SigNid  OpenSSL signature algorithm NID (e.g. NID_sha256WithRSAEncryption).
  @param[in]  Ctx     Opaque caller-supplied context.

  @retval TRUE   Emit this NID's OID in the CSV.
  @retval FALSE  Skip this NID.
**/
typedef
BOOLEAN
(EFIAPI *CRYPTO_OP_SIG_PREDICATE)(
  IN INT32  SigNid,
  IN VOID   *Ctx
  );

/**
  Enumerate every signature algorithm the linked OpenSSL provider can verify,
  filter through Accept, and emit accepted entries as dotted-OID strings in a
  CSV-encoded, NUL-terminated ASCII payload.

  @param[in]      Accept      Predicate; called for every (digest, pk) pair the
                              provider supports. NIDs returning TRUE are emitted.
  @param[in]      Ctx         Opaque context passed unmodified to Accept.
  @param[out]     Buffer      NULL to probe required size; else receives payload.
  @param[in,out]  BufferSize  In: size of Buffer. Out: bytes written or required
                              (always includes the trailing NUL).

  @retval EFI_SUCCESS           Buffer populated (or size returned if Buffer NULL).
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small; *BufferSize set to required.
**/
EFI_STATUS
EnumerateProviderSignatureOids (
  IN     CRYPTO_OP_SIG_PREDICATE  Accept,
  IN     VOID                     *Ctx,
  OUT    CHAR8                    *Buffer       OPTIONAL,
  IN OUT UINTN                    *BufferSize
  );

//
// Per-op handlers (one per registered Op-ID GUID; co-located with the verify
// pipeline that owns the op).
//
EFI_STATUS
EFIAPI
Pkcs7VerifyOpCapability (
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  );

EFI_STATUS
EFIAPI
AuthenticodeOpCapability (
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  );

/**
  Return TRUE if the Authenticode verify pipeline accepts the given signature
  NID. The body mirrors AuthenticodeExpectedDigestNid (CryptAuthenticode.c):
  accept iff the signature's inner digest NID is SHA-1, SHA-256, SHA-384, or
  SHA-512.

  @param[in]  SigNid  OpenSSL signature algorithm NID.

  @retval TRUE   Authenticode verify will accept this signature algorithm.
  @retval FALSE  Authenticode verify will reject it.
**/
BOOLEAN
EFIAPI
IsAuthenticodeSigNidAccepted (
  IN INT32  SigNid
  );
```

- [ ] **Step 4: Create `Pk/CryptoOpCapability.c` with dispatcher + enumeration helper**

Create [OpensslPkg/Library/BaseCryptLib/Pk/CryptoOpCapability.c](../../../OpensslPkg/Library/BaseCryptLib/Pk/CryptoOpCapability.c):

```c
/** @file
  ECIT capability reporting dispatcher and provider-enumeration helper.

  GetCryptoOpCapability() looks up an Op-ID GUID in mDispatch[] and delegates
  to a per-op handler. Per-op handlers (in their verify pipeline's source
  file, e.g. CryptPkcs7VerifyCommon.c, CryptAuthenticode.c) reuse
  EnumerateProviderSignatureOids and supply a small acceptance predicate.

  No const OID lists exist anywhere in this design: the provider IS the
  list, the predicate IS the policy, both read on every call.

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include <Library/CryptoCapability.h>

#include <openssl/evp.h>
#include <openssl/objects.h>

//
// Per-op handler signature. Same shape as GetCryptoOpCapability minus the
// OpIdGuid parameter (dispatch already matched it).
//
typedef
EFI_STATUS
(EFIAPI *CRYPTO_OP_HANDLER)(
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  );

typedef struct {
  CONST EFI_GUID     *OpId;
  CRYPTO_OP_HANDLER  Handler;
} CRYPTO_OP_DISPATCH;

STATIC CONST CRYPTO_OP_DISPATCH  mDispatch[] = {
  { &gCryptoOpPkcs7VerifyGuid, Pkcs7VerifyOpCapability },
  // AuthenticodeOpCapability registered in Task 4.
};

//
// Public-key types we ask OpenSSL about. List intentionally small and
// matched to what the BaseCryptLib verify code already supports
// (RSA, EC, ED25519, ED448). Adding a new pk type here will surface every
// digest the provider knows how to combine with it.
//
STATIC CONST INT32  mPkNids[] = {
  EVP_PKEY_RSA,
  EVP_PKEY_EC,
  EVP_PKEY_ED25519,
  EVP_PKEY_ED448
};

//
// Iteration state for EVP_MD_do_all_provided. Keeps Accept/Ctx, the output
// buffer, the running write cursor, and a flag for capacity overflow.
//
typedef struct {
  CRYPTO_OP_SIG_PREDICATE  Accept;
  VOID                     *Ctx;
  CHAR8                    *Buffer;       // NULL when sizing-probe only.
  UINTN                    BufferSize;    // Capacity if Buffer != NULL; else 0.
  UINTN                    Written;       // Bytes written so far, excludes NUL.
  BOOLEAN                  Overflow;      // TRUE if a write was skipped due to capacity.
} ENUM_STATE;

/**
  Append a comma-separated entry to the running CSV.

  @param[in,out]  State  Iteration state.
  @param[in]      Entry  NUL-terminated OID string (no comma).
**/
STATIC
VOID
AppendEntry (
  IN OUT ENUM_STATE   *State,
  IN     CONST CHAR8  *Entry
  )
{
  UINTN  EntryLen;
  UINTN  NeedComma;
  UINTN  Need;

  EntryLen  = AsciiStrLen (Entry);
  NeedComma = (State->Written > 0) ? 1 : 0;
  Need      = NeedComma + EntryLen;  // NUL counted separately at finalize.

  if ((State->Buffer == NULL) ||
      (State->Written + Need + 1 > State->BufferSize))
  {
    // Sizing probe, or capacity overflow. Just account.
    if (State->Buffer != NULL) {
      State->Overflow = TRUE;
    }

    State->Written += Need;
    return;
  }

  if (NeedComma != 0) {
    State->Buffer[State->Written++] = ',';
  }

  CopyMem (&State->Buffer[State->Written], Entry, EntryLen);
  State->Written += EntryLen;
}

/**
  Convert a NID to its dotted-decimal OID string and append it via AppendEntry.

  @param[in,out]  State  Iteration state.
  @param[in]      Nid    OpenSSL NID for a signature algorithm.
**/
STATIC
VOID
EmitNidAsOid (
  IN OUT ENUM_STATE  *State,
  IN     INT32       Nid
  )
{
  ASN1_OBJECT  *Obj;
  CHAR8        OidBuf[80];  // Longest realistic OID dotted form is well under 80.
  int          Len;

  Obj = OBJ_nid2obj (Nid);
  if (Obj == NULL) {
    return;
  }

  Len = OBJ_obj2txt (OidBuf, sizeof (OidBuf), Obj, 1 /* always_dotted */);
  if ((Len <= 0) || ((UINTN)Len >= sizeof (OidBuf))) {
    return;
  }

  OidBuf[Len] = '\0';
  AppendEntry (State, OidBuf);
}

/**
  EVP_MD_do_all_provided callback. For each digest, walk mPkNids and, for
  every (digest, pk) pair OpenSSL can combine into a signature, run Accept
  and emit if accepted.
**/
STATIC
VOID
DigestVisitor (
  EVP_MD  *Md,
  VOID    *Arg
  )
{
  ENUM_STATE  *State;
  INT32       DigestNid;
  UINTN       PkIdx;
  INT32       PkNid;
  INT32       SigNid;

  State     = (ENUM_STATE *)Arg;
  DigestNid = EVP_MD_get_type (Md);
  if (DigestNid == NID_undef) {
    return;
  }

  for (PkIdx = 0; PkIdx < ARRAY_SIZE (mPkNids); PkIdx++) {
    PkNid  = mPkNids[PkIdx];
    SigNid = NID_undef;
    if (OBJ_find_sigid_by_algs (&SigNid, DigestNid, PkNid) != 1) {
      continue;  // Provider has no signature OID for this combination.
    }

    if (!State->Accept (SigNid, State->Ctx)) {
      continue;
    }

    EmitNidAsOid (State, SigNid);
  }
}

EFI_STATUS
EnumerateProviderSignatureOids (
  IN     CRYPTO_OP_SIG_PREDICATE  Accept,
  IN     VOID                     *Ctx,
  OUT    CHAR8                    *Buffer       OPTIONAL,
  IN OUT UINTN                    *BufferSize
  )
{
  ENUM_STATE  State;
  UINTN       Required;

  if ((Accept == NULL) || (BufferSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&State, sizeof (State));
  State.Accept     = Accept;
  State.Ctx        = Ctx;
  State.Buffer     = Buffer;
  State.BufferSize = (Buffer != NULL) ? *BufferSize : 0;

  EVP_MD_do_all_provided (NULL /* default library context */, DigestVisitor, &State);

  Required = State.Written + 1;  // +1 for trailing NUL.

  if (Buffer == NULL) {
    *BufferSize = Required;
    return EFI_SUCCESS;
  }

  if (State.Overflow || (*BufferSize < Required)) {
    *BufferSize = Required;
    return EFI_BUFFER_TOO_SMALL;
  }

  Buffer[State.Written] = '\0';
  *BufferSize           = Required;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
GetCryptoOpCapability (
  IN     CONST EFI_GUID  *OpIdGuid,
  OUT    VOID            *Buffer       OPTIONAL,
  IN OUT UINTN           *BufferSize
  )
{
  UINTN  Index;

  if ((OpIdGuid == NULL) || (BufferSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  for (Index = 0; Index < ARRAY_SIZE (mDispatch); Index++) {
    if (CompareGuid (OpIdGuid, mDispatch[Index].OpId)) {
      return mDispatch[Index].Handler ((CHAR8 *)Buffer, BufferSize);
    }
  }

  return EFI_NOT_FOUND;
}
```

- [ ] **Step 5: Add the PKCS#7 handler to `CryptPkcs7VerifyCommon.c`**

In [OpensslPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyCommon.c](../../../OpensslPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyCommon.c), append at the end of the file (after the last `}` of the last function):

```c
//
// ECIT capability reporting — PKCS#7 op handler.
//
// CryptPkcs7VerifyCommon.c hands PKCS#7 blobs straight to OpenSSL's
// PKCS7_verify(), so the verify policy IS the provider's policy. The
// predicate accepts everything the provider already vouches for; no
// additional filtering needed.
//

STATIC
BOOLEAN
EFIAPI
Pkcs7AcceptAll (
  IN INT32  SigNid,
  IN VOID   *Ctx
  )
{
  return TRUE;
}

EFI_STATUS
EFIAPI
Pkcs7VerifyOpCapability (
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  )
{
  return EnumerateProviderSignatureOids (Pkcs7AcceptAll, NULL, Buffer, BufferSize);
}
```

- [ ] **Step 6: Add the new files and packages to `BaseCryptLib.inf` and `UnitTestHostBaseCryptLib.inf`**

For each of [OpensslPkg/Library/BaseCryptLib/BaseCryptLib.inf](../../../OpensslPkg/Library/BaseCryptLib/BaseCryptLib.inf) and [OpensslPkg/Library/BaseCryptLib/UnitTestHostBaseCryptLib.inf](../../../OpensslPkg/Library/BaseCryptLib/UnitTestHostBaseCryptLib.inf):

a) In `[Sources]`, add after `Pk/CryptAuthenticode.c`:

```ini
  Pk/CryptoOpCapability.c
```

b) Ensure `[Packages]` lists `MdePkg/MdePkg.dec` and `CryptoPkg/CryptoPkg.dec` (both should already be present).

c) Add a `[Guids]` section (or extend the existing one):

```ini
[Guids]
  gCryptoOpPkcs7VerifyGuid        ## CONSUMES
  gCryptoOpAuthenticodeVerifyGuid ## CONSUMES
```

The host-test DSC ([OpensslPkg/Test/OpensslPkgHostUnitTest.dsc#L23](../../../OpensslPkg/Test/OpensslPkgHostUnitTest.dsc)) maps `BaseCryptLib` to `UnitTestHostBaseCryptLib.inf`, so without this second INF update the tests would fail to link with "undefined reference to `GetCryptoOpCapability`".

- [ ] **Step 7: Run tests, expect 5/5 PASS**

```bash
stuart_ci_build -c .pytool/CISettings.py -p OpensslPkg -t NOOPT \
    -d HostUnitTestCompilerPlugin=run TOOL_CHAIN_TAG=GCC5
```

Expected: all five new tests pass:

```
[PASS] TestNullParamsRejected
[PASS] TestUnknownGuidReturnsNotFound
[PASS] TestPkcs7SizingProbe
[PASS] TestPkcs7FetchPayload
[PASS] TestPkcs7BufferTooSmall
```

- [ ] **Step 8: Commit (two repos)**

```bash
# First: MU_BASECORE side (tests + internal header reference)
cd MU_BASECORE
git add CryptoPkg/Test/UnitTest/Library/BaseCryptLib/CryptoOpCapabilityTests.c
git commit -s -m "CryptoPkg/Test: add GetCryptoOpCapability dispatch + PKCS#7 tests

NULL parameter, unknown GUID, sizing probe, full fetch, and too-small
buffer paths exercised against the freshly landed dispatcher in
OpensslPkg's BaseCryptLib."
cd ..

# Then: mu_crypto_release side (dispatcher + helper + PKCS#7 handler + INF wiring)
git add OpensslPkg/Library/BaseCryptLib/InternalCryptLib.h \
        OpensslPkg/Library/BaseCryptLib/Pk/CryptoOpCapability.c \
        OpensslPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyCommon.c \
        OpensslPkg/Library/BaseCryptLib/BaseCryptLib.inf \
        OpensslPkg/Library/BaseCryptLib/UnitTestHostBaseCryptLib.inf
git commit -s -m "OpensslPkg/BaseCryptLib: add GetCryptoOpCapability dispatcher + PKCS#7 op

New Pk/CryptoOpCapability.c implements the dispatcher and the shared
EnumerateProviderSignatureOids helper. The helper walks the provider's
digest x pk-type cross-product via EVP_MD_do_all_provided +
OBJ_find_sigid_by_algs and emits a CSV-encoded, NUL-terminated OID
string for entries the supplied predicate accepts.

CryptPkcs7VerifyCommon.c grows a Pkcs7VerifyOpCapability handler that
uses an accept-all predicate, matching the file's existing pass-through
to OpenSSL's PKCS7_verify.

Wired into both BaseCryptLib.inf (target build) and
UnitTestHostBaseCryptLib.inf (host test linkage)."
```

---

## Task 4: Authenticode op (predicate + handler, TDD)

**Files:**
- Modify: `MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/CryptoOpCapabilityTests.c`
- Modify: `OpensslPkg/Library/BaseCryptLib/Pk/CryptAuthenticode.c`
- Modify: `OpensslPkg/Library/BaseCryptLib/Pk/CryptoOpCapability.c` (register handler in `mDispatch[]`)

- [ ] **Step 1: Add failing tests for `IsAuthenticodeSigNidAccepted` + Authenticode op**

In [CryptoOpCapabilityTests.c](../../../MU_BASECORE/CryptoPkg/Test/UnitTest/Library/BaseCryptLib/CryptoOpCapabilityTests.c), add `#include <openssl/objects.h>` near the top (note: this requires the test INF to allow OpenSSL headers — they're already on the include path for the host test). Then add these test functions before the `mCryptoOpCapabilityTest[]` array:

```c
//
// Predicate exposed from CryptAuthenticode.c (declared via InternalCryptLib.h
// in BaseCryptLib but not part of the public surface). The test reaches in
// because behavior parity with the verify pipeline IS the test invariant.
//
BOOLEAN EFIAPI IsAuthenticodeSigNidAccepted (IN INT32  SigNid);

STATIC
UNIT_TEST_STATUS
EFIAPI
TestAuthenticodePredicateAcceptsSha2Rsa (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UT_ASSERT_TRUE (IsAuthenticodeSigNidAccepted (NID_sha256WithRSAEncryption));
  UT_ASSERT_TRUE (IsAuthenticodeSigNidAccepted (NID_sha384WithRSAEncryption));
  UT_ASSERT_TRUE (IsAuthenticodeSigNidAccepted (NID_sha512WithRSAEncryption));
  UT_ASSERT_TRUE (IsAuthenticodeSigNidAccepted (NID_sha1WithRSAEncryption));
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestAuthenticodePredicateRejectsMd5 (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UT_ASSERT_FALSE (IsAuthenticodeSigNidAccepted (NID_md5WithRSAEncryption));
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestAuthenticodeIsSubsetOfPkcs7 (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS  Status;
  UINTN       AuthSize;
  UINTN       Pkcs7Size;
  CHAR8       *AuthBuf;
  CHAR8       *Pkcs7Buf;
  CHAR8       *Cursor;
  CHAR8       *Comma;
  CHAR8       Oid[80];

  // Fetch both CSVs.
  AuthSize = 0;
  Status   = GetCryptoOpCapability (&gCryptoOpAuthenticodeVerifyGuid, NULL, &AuthSize);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  AuthBuf = AllocatePool (AuthSize);
  UT_ASSERT_NOT_NULL (AuthBuf);
  Status = GetCryptoOpCapability (&gCryptoOpAuthenticodeVerifyGuid, AuthBuf, &AuthSize);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);

  Pkcs7Size = 0;
  Status    = GetCryptoOpCapability (&gCryptoOpPkcs7VerifyGuid, NULL, &Pkcs7Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  Pkcs7Buf = AllocatePool (Pkcs7Size);
  UT_ASSERT_NOT_NULL (Pkcs7Buf);
  Status = GetCryptoOpCapability (&gCryptoOpPkcs7VerifyGuid, Pkcs7Buf, &Pkcs7Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);

  // Every OID in the Authenticode CSV must also appear in the PKCS#7 CSV.
  Cursor = AuthBuf;
  while ((Cursor != NULL) && (*Cursor != '\0')) {
    Comma = AsciiStrStr (Cursor, ",");
    if (Comma != NULL) {
      UINTN Len = (UINTN)(Comma - Cursor);
      UT_ASSERT_TRUE (Len < sizeof (Oid));
      CopyMem (Oid, Cursor, Len);
      Oid[Len] = '\0';
      Cursor   = Comma + 1;
    } else {
      AsciiStrCpyS (Oid, sizeof (Oid), Cursor);
      Cursor = NULL;
    }

    UT_ASSERT_NOT_NULL (AsciiStrStr (Pkcs7Buf, Oid));
  }

  FreePool (AuthBuf);
  FreePool (Pkcs7Buf);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestAuthenticodeExcludesMd5Oid (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS  Status;
  UINTN       Size;
  CHAR8       *Buf;

  Size   = 0;
  Status = GetCryptoOpCapability (&gCryptoOpAuthenticodeVerifyGuid, NULL, &Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  Buf = AllocatePool (Size);
  UT_ASSERT_NOT_NULL (Buf);
  Status = GetCryptoOpCapability (&gCryptoOpAuthenticodeVerifyGuid, Buf, &Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);

  // md5WithRSAEncryption is OID 1.2.840.113549.1.1.4 — must not appear in
  // the Authenticode CSV even though it is in the PKCS#7 CSV.
  UT_ASSERT_TRUE (AsciiStrStr (Buf, "1.2.840.113549.1.1.4") == NULL);

  FreePool (Buf);
  return UNIT_TEST_PASSED;
}

//
// Spec §6.1: "Empty-payload behavior — forcing a predicate that rejects
// everything returns single NUL byte". Reach into the internal helper by
// forward declaration; it's not part of the public CryptoCapability.h
// surface (only declared in OpensslPkg's private InternalCryptLib.h).
//
typedef BOOLEAN (EFIAPI *CRYPTO_OP_SIG_PREDICATE) (INT32 SigNid, VOID *Ctx);

EFI_STATUS
EnumerateProviderSignatureOids (
  IN     CRYPTO_OP_SIG_PREDICATE  Accept,
  IN     VOID                     *Ctx,
  OUT    CHAR8                    *Buffer       OPTIONAL,
  IN OUT UINTN                    *BufferSize
  );

STATIC
BOOLEAN
EFIAPI
RejectAll (
  IN INT32  SigNid,
  IN VOID   *Ctx
  )
{
  return FALSE;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
TestEnumerateRejectAllProducesEmptyPayload (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS  Status;
  UINTN       Size;
  CHAR8       Buf[8];

  // Sizing probe with always-FALSE predicate: required size is 1 (just NUL).
  Size   = 0;
  Status = EnumerateProviderSignatureOids (RejectAll, NULL, NULL, &Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (Size, 1);

  // Fetch with provided buffer: single NUL byte written.
  Size   = sizeof (Buf);
  Buf[0] = 0xAA;  // poison to detect non-write.
  Status = EnumerateProviderSignatureOids (RejectAll, NULL, Buf, &Size);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  UT_ASSERT_EQUAL (Size, 1);
  UT_ASSERT_EQUAL (Buf[0], '\0');
  return UNIT_TEST_PASSED;
}
```

Add to the `mCryptoOpCapabilityTest[]` array (before the closing `};`):

```c
  { "TestAuthenticodePredicateAcceptsSha2Rsa", "CryptoPkg.BaseCryptLib.OpCapability", TestAuthenticodePredicateAcceptsSha2Rsa, NULL, NULL, NULL },
  { "TestAuthenticodePredicateRejectsMd5",     "CryptoPkg.BaseCryptLib.OpCapability", TestAuthenticodePredicateRejectsMd5,     NULL, NULL, NULL },
  { "TestAuthenticodeIsSubsetOfPkcs7",         "CryptoPkg.BaseCryptLib.OpCapability", TestAuthenticodeIsSubsetOfPkcs7,         NULL, NULL, NULL },
  { "TestAuthenticodeExcludesMd5Oid",          "CryptoPkg.BaseCryptLib.OpCapability", TestAuthenticodeExcludesMd5Oid,          NULL, NULL, NULL },
  { "TestEnumerateRejectAllProducesEmptyPayload", "CryptoPkg.BaseCryptLib.OpCapability", TestEnumerateRejectAllProducesEmptyPayload, NULL, NULL, NULL },
```

- [ ] **Step 2: Run tests, expect link failure (unresolved `IsAuthenticodeSigNidAccepted`, `AuthenticodeOpCapability` not registered)**

```bash
stuart_ci_build -c .pytool/CISettings.py -p OpensslPkg -t NOOPT \
    -d HostUnitTestCompilerPlugin=run TOOL_CHAIN_TAG=GCC5
```

Expected: link FAILS with "undefined reference to `IsAuthenticodeSigNidAccepted`".

- [ ] **Step 3: Implement `IsAuthenticodeSigNidAccepted` and `AuthenticodeOpCapability` in `CryptAuthenticode.c`**

In [OpensslPkg/Library/BaseCryptLib/Pk/CryptAuthenticode.c](../../../OpensslPkg/Library/BaseCryptLib/Pk/CryptAuthenticode.c), append at the end of the file:

```c
//
// ECIT capability reporting — Authenticode op handler + predicate.
//
// IsAuthenticodeSigNidAccepted mirrors AuthenticodeExpectedDigestNid above:
// Authenticode accepts only signatures whose inner DigestInfo digestAlgorithm
// is SHA-1, SHA-256, SHA-384, or SHA-512. By driving the capability answer
// off the same digest set the verify-time decision uses, the reported OIDs
// stay in lockstep with verify policy with no separate allowlist.
//

BOOLEAN
EFIAPI
IsAuthenticodeSigNidAccepted (
  IN INT32  SigNid
  )
{
  int  DigestNid;
  int  PkNid;

  DigestNid = NID_undef;
  PkNid     = NID_undef;
  if (OBJ_find_sigid_algs (SigNid, &DigestNid, &PkNid) != 1) {
    return FALSE;
  }

  switch (DigestNid) {
    case NID_sha1:
    case NID_sha256:
    case NID_sha384:
    case NID_sha512:
      return TRUE;
    default:
      return FALSE;
  }
}

STATIC
BOOLEAN
EFIAPI
AuthenticodeAccept (
  IN INT32  SigNid,
  IN VOID   *Ctx
  )
{
  return IsAuthenticodeSigNidAccepted (SigNid);
}

EFI_STATUS
EFIAPI
AuthenticodeOpCapability (
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  )
{
  return EnumerateProviderSignatureOids (AuthenticodeAccept, NULL, Buffer, BufferSize);
}
```

- [ ] **Step 4: Register `AuthenticodeOpCapability` in the dispatch table**

In [OpensslPkg/Library/BaseCryptLib/Pk/CryptoOpCapability.c](../../../OpensslPkg/Library/BaseCryptLib/Pk/CryptoOpCapability.c), replace the `mDispatch[]` definition with:

```c
STATIC CONST CRYPTO_OP_DISPATCH  mDispatch[] = {
  { &gCryptoOpPkcs7VerifyGuid,        Pkcs7VerifyOpCapability  },
  { &gCryptoOpAuthenticodeVerifyGuid, AuthenticodeOpCapability },
};
```

- [ ] **Step 5: Run tests, expect 10/10 PASS**

```bash
stuart_ci_build -c .pytool/CISettings.py -p OpensslPkg -t NOOPT \
    -d HostUnitTestCompilerPlugin=run TOOL_CHAIN_TAG=GCC5
```

Expected: all ten `CryptoOpCapability` tests pass (5 from Task 3 + 4 Authenticode + 1 empty-payload).

- [ ] **Step 6: Commit (two repos)**

```bash
cd MU_BASECORE
git add CryptoPkg/Test/UnitTest/Library/BaseCryptLib/CryptoOpCapabilityTests.c
git commit -s -m "CryptoPkg/Test: add Authenticode predicate + op-handler tests

Asserts IsAuthenticodeSigNidAccepted matches AuthenticodeExpectedDigestNid's
accept-set (SHA-1/256/384/512 RSA accepted, MD5 rejected) and verifies the
Authenticode CSV is a strict subset of the PKCS#7 CSV with no MD5 entries."
cd ..

git add OpensslPkg/Library/BaseCryptLib/Pk/CryptAuthenticode.c \
        OpensslPkg/Library/BaseCryptLib/Pk/CryptoOpCapability.c
git commit -s -m "OpensslPkg/BaseCryptLib: add Authenticode op capability handler

IsAuthenticodeSigNidAccepted lives next to AuthenticodeExpectedDigestNid in
CryptAuthenticode.c so the capability answer tracks verify-time policy by
construction. AuthenticodeOpCapability wires the predicate into the shared
EnumerateProviderSignatureOids helper. The dispatch table in
CryptoOpCapability.c now serves both registered Op-ID GUIDs."
```

---

## Task 5: Null-variant handlers + non-DXE BaseCryptLib INF wiring

**Files:**
- Modify: `OpensslPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyNull.c`
- Modify: `OpensslPkg/Library/BaseCryptLib/Pk/CryptAuthenticodeNull.c`
- Modify: `OpensslPkg/Library/BaseCryptLib/PeiCryptLib.inf`
- Modify: `OpensslPkg/Library/BaseCryptLib/SecCryptLib.inf`
- Modify: `OpensslPkg/Library/BaseCryptLib/RuntimeCryptLib.inf`
- Modify: `OpensslPkg/Library/BaseCryptLib/SmmCryptLib.inf`

**Design:** Every OpenSSL BaseCryptLib INF links the same full `Pk/CryptoOpCapability.c` dispatcher (no separate Null dispatcher needed). The dispatcher references `Pkcs7VerifyOpCapability` and `AuthenticodeOpCapability` extern; each INF resolves those externs to whichever variant it already links:

| INF | `Pkcs7VerifyOpCapability` resolves to | `AuthenticodeOpCapability` resolves to |
|---|---|---|
| `BaseCryptLib.inf` (DXE, set by Task 3) | full (`CryptPkcs7VerifyCommon.c`) | full (`CryptAuthenticode.c`) |
| `UnitTestHostBaseCryptLib.inf` (set by Task 3) | full | full |
| `PeiCryptLib.inf` | full (Pei links `CryptPkcs7VerifyCommon.c`) | Null (`CryptAuthenticodeNull.c`) |
| `RuntimeCryptLib.inf` | full | Null |
| `SmmCryptLib.inf` | full | Null |
| `SecCryptLib.inf` | Null (`CryptPkcs7VerifyNull.c`) | Null |

So this task: (a) adds the missing Null handler symbols in the Null verify files, and (b) wires `Pk/CryptoOpCapability.c` into the four non-DXE OpenSSL INFs.

- [ ] **Step 1: Add Null stub of `Pkcs7VerifyOpCapability` in `CryptPkcs7VerifyNull.c`**

In [OpensslPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyNull.c](../../../OpensslPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyNull.c), append at the end of the file:

```c
//
// ECIT capability — Null. This BaseCryptLib flavor does not link PKCS#7
// verify, so the op has no algorithms to report. Honest empty payload
// (single NUL byte) per the spec's empty-set contract.
//
EFI_STATUS
EFIAPI
Pkcs7VerifyOpCapability (
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  )
{
  if (BufferSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Buffer == NULL) {
    *BufferSize = 1;
    return EFI_SUCCESS;
  }

  if (*BufferSize < 1) {
    *BufferSize = 1;
    return EFI_BUFFER_TOO_SMALL;
  }

  Buffer[0]   = '\0';
  *BufferSize = 1;
  return EFI_SUCCESS;
}
```

- [ ] **Step 2: Add Null stubs in `CryptAuthenticodeNull.c`**

In [OpensslPkg/Library/BaseCryptLib/Pk/CryptAuthenticodeNull.c](../../../OpensslPkg/Library/BaseCryptLib/Pk/CryptAuthenticodeNull.c), append at the end of the file:

```c
//
// ECIT capability — Null. This BaseCryptLib flavor does not link
// Authenticode verify.
//

BOOLEAN
EFIAPI
IsAuthenticodeSigNidAccepted (
  IN INT32  SigNid
  )
{
  return FALSE;
}

EFI_STATUS
EFIAPI
AuthenticodeOpCapability (
  OUT    CHAR8  *Buffer       OPTIONAL,
  IN OUT UINTN  *BufferSize
  )
{
  if (BufferSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Buffer == NULL) {
    *BufferSize = 1;
    return EFI_SUCCESS;
  }

  if (*BufferSize < 1) {
    *BufferSize = 1;
    return EFI_BUFFER_TOO_SMALL;
  }

  Buffer[0]   = '\0';
  *BufferSize = 1;
  return EFI_SUCCESS;
}
```

- [ ] **Step 3: Add `Pk/CryptoOpCapability.c` + `[Guids]` to each non-DXE OpenSSL INF**

For each of:

- `OpensslPkg/Library/BaseCryptLib/PeiCryptLib.inf`
- `OpensslPkg/Library/BaseCryptLib/SecCryptLib.inf`
- `OpensslPkg/Library/BaseCryptLib/RuntimeCryptLib.inf`
- `OpensslPkg/Library/BaseCryptLib/SmmCryptLib.inf`

In `[Sources]`, add (place next to the other `Pk/Crypt*` entries):

```ini
  Pk/CryptoOpCapability.c
```

In `[Guids]` (add the section if missing):

```ini
[Guids]
  gCryptoOpPkcs7VerifyGuid        ## CONSUMES
  gCryptoOpAuthenticodeVerifyGuid ## CONSUMES
```

- [ ] **Step 4: Build all OpensslPkg targets**

```bash
stuart_ci_build -c .pytool/CISettings.py -p OpensslPkg -t DEBUG TOOL_CHAIN_TAG=CLANGPDB
```

Expected: build succeeds for every BaseCryptLib INF flavor.

- [ ] **Step 5: Re-run host tests to confirm no regression**

```bash
stuart_ci_build -c .pytool/CISettings.py -p OpensslPkg -t NOOPT \
    -d HostUnitTestCompilerPlugin=run TOOL_CHAIN_TAG=GCC5
```

Expected: all 10 `CryptoOpCapability` tests still pass (5 from Task 3 + 4 from Task 4 + 1 empty-payload from Task 4 Step 1a).

- [ ] **Step 6: Commit**

```bash
git add OpensslPkg/Library/BaseCryptLib/Pk/CryptPkcs7VerifyNull.c \
        OpensslPkg/Library/BaseCryptLib/Pk/CryptAuthenticodeNull.c \
        OpensslPkg/Library/BaseCryptLib/PeiCryptLib.inf \
        OpensslPkg/Library/BaseCryptLib/SecCryptLib.inf \
        OpensslPkg/Library/BaseCryptLib/RuntimeCryptLib.inf \
        OpensslPkg/Library/BaseCryptLib/SmmCryptLib.inf
git commit -s -m "OpensslPkg/BaseCryptLib: Null op handlers + non-DXE dispatcher wiring

Non-DXE flavors (PEI, Sec, Runtime, SMM) link the same full
GetCryptoOpCapability dispatcher as DXE. Per-op handlers
(Pkcs7VerifyOpCapability, AuthenticodeOpCapability) and the
IsAuthenticodeSigNidAccepted predicate resolve through extern to
whichever Pkcs7Verify/Authenticode variant (full or Null) each INF
already links. The Null stubs in CryptPkcs7VerifyNull.c and
CryptAuthenticodeNull.c return an honest single-NUL-byte empty payload."
```

---

## Task 6: Protocol forwarder in `BaseCryptLibOnOneCrypto`

**Files:**
- Modify: `MU_BASECORE/CryptoPkg/Library/BaseCryptLibOnOneCrypto/OneCryptoLib.c`

- [ ] **Step 1: Add the forwarder function**

In [MU_BASECORE/CryptoPkg/Library/BaseCryptLibOnOneCrypto/OneCryptoLib.c](../../../MU_BASECORE/CryptoPkg/Library/BaseCryptLibOnOneCrypto/OneCryptoLib.c), at the end of the file (after the last existing forwarder), add:

```c
EFI_STATUS
EFIAPI
GetCryptoOpCapability (
  IN     CONST EFI_GUID  *OpIdGuid,
  OUT    VOID            *Buffer       OPTIONAL,
  IN OUT UINTN           *BufferSize
  )
{
  CALL_CRYPTO_SERVICE (
    GetCryptoOpCapability,
    (OpIdGuid, Buffer, BufferSize),
    EFI_UNSUPPORTED,
    1,
    1
    );
}
```

Note: `MinMajor=1, MinMinor=1`. An older binary (1.0) cleanly returns `EFI_UNSUPPORTED` via `ValidateCryptoVersion`'s less-than check; no rebuild required for unrelated consumers.

- [ ] **Step 2: Build BaseCryptLibOnOneCrypto via OneCryptoPkg DSC**

```bash
stuart_build -c PlatformBuild.py -a X64 -t DEBUG TOOL_CHAIN_TAG=CLANGPDB
```

Expected: build succeeds.

- [ ] **Step 3: Commit**

```bash
cd MU_BASECORE
git add CryptoPkg/Library/BaseCryptLibOnOneCrypto/OneCryptoLib.c
git commit -s -m "CryptoPkg/BaseCryptLibOnOneCrypto: forward GetCryptoOpCapability

Uses the existing CALL_CRYPTO_SERVICE macro with MinMajor=1, MinMinor=1.
Consumers linked against an older OneCryptoBin (1.0) receive
EFI_UNSUPPORTED via ValidateCryptoVersion's backward-compatible '<'
comparison, with no rebuild required."
cd ..
```

---

## Task 7: `OneCryptoBin` protocol assignment + minor-version bump (atomic)

**Files:**
- Modify: `OneCryptoPkg/OneCryptoBin/OneCryptoBin.c`
- Modify: `MU_BASECORE/CryptoPkg/Include/Protocol/OneCrypto.h` (bump minor)

This task lands both halves of the v1.1 advertisement in one logical change. The Bin commit assigns the function pointer; the MU_BASECORE commit bumps the minor. Order: MU_BASECORE first (so any rebuild of the Bin in this task sees the new minor immediately), then the Bin commit.

- [ ] **Step 1: Bump `ONE_CRYPTO_VERSION_MINOR` to `1`**

In [MU_BASECORE/CryptoPkg/Include/Protocol/OneCrypto.h](../../../MU_BASECORE/CryptoPkg/Include/Protocol/OneCrypto.h) at the version constants block (~lines 54–55):

```c
#define ONE_CRYPTO_VERSION_MAJOR  1ULL
#define ONE_CRYPTO_VERSION_MINOR  1ULL
```

(Change `0ULL` to `1ULL` on the minor line. Major stays `1ULL`.)

- [ ] **Step 2: Assign the new function pointer in `CryptoInit`**

In [OneCryptoPkg/OneCryptoBin/OneCryptoBin.c](../../../OneCryptoPkg/OneCryptoBin/OneCryptoBin.c), find the end of `CryptoInit()` (the function that populates `CryptoProtocol->...` field-by-field; ends with assignments to `GetCryptoProviderVersionString` or similar). Add immediately before the closing `}`:

```c
  //
  // ECIT capability reporting
  //
  CryptoProtocol->GetCryptoOpCapability = GetCryptoOpCapability;
```

`GetCryptoOpCapability` is the public symbol from `CryptoCapability.h`; OneCryptoBin already includes `BaseCryptLib.h` and statically links the full `BaseCryptLib.inf` (which brings in `Pk/CryptoOpCapability.c` from Task 3).

- [ ] **Step 3: Add `CryptoCapability.h` include if not already present**

Inspect the top of `OneCryptoBin.c`. If `<Library/CryptoCapability.h>` is not already included, add:

```c
#include <Library/CryptoCapability.h>
```

(near the other `<Library/...>` includes).

- [ ] **Step 4: Build OneCryptoBin and verify the protocol field is populated**

```bash
stuart_build -c PlatformBuild.py -a X64 -t DEBUG TOOL_CHAIN_TAG=CLANGPDB
```

Expected: build succeeds. The resulting OneCryptoBin reports protocol version 1.1 and `GetCryptoOpCapability` is a valid function pointer.

- [ ] **Step 5: Commit (two repos; MU_BASECORE first)**

```bash
# MU_BASECORE: the version bump.
cd MU_BASECORE
git add CryptoPkg/Include/Protocol/OneCrypto.h
git commit -s -m "CryptoPkg: bump ONE_CRYPTO_VERSION_MINOR to 1 for GetCryptoOpCapability

The protocol struct field was appended in a prior commit but
intentionally not advertised via minor bump until the OneCryptoBin
binary actually assigns it. This commit + the immediately-following
OneCryptoBin commit form the atomic v1.1 release."
cd ..

# mu_crypto_release: the Bin assignment.
git add OneCryptoPkg/OneCryptoBin/OneCryptoBin.c
git commit -s -m "OneCryptoPkg/OneCryptoBin: publish GetCryptoOpCapability in protocol

CryptoInit now assigns the BaseCryptLib symbol into the new
ONE_CRYPTO_PROTOCOL field. Paired with the MU_BASECORE minor-version
bump in the previous commit, the MM-resident binary now reports
v1.1; older 1.0-aware consumers continue to work unchanged via
ValidateCryptoVersion's less-than comparison."
```

---

## Task 8: MbedTLS parity (Null only)

Per spec §8 open question, MbedTLS provider enumeration is deferred. This task ships a Null implementation so MbedTLS builds don't break.

**Files:**
- Create: `MbedTlsPkg/Library/BaseCryptLib/Pk/CryptoOpCapabilityNull.c`
- Modify: every `MbedTlsPkg/Library/BaseCryptLib/*.inf`

- [ ] **Step 1: Locate all MbedTLS BaseCryptLib INFs**

```bash
find MbedTlsPkg/Library/BaseCryptLib -maxdepth 2 -name "*.inf"
```

Expected: a list of phase-specific INFs (BaseCryptLib.inf and its variants).

- [ ] **Step 2: Create the MbedTLS Null implementation**

Create [MbedTlsPkg/Library/BaseCryptLib/Pk/CryptoOpCapabilityNull.c](../../../MbedTlsPkg/Library/BaseCryptLib/Pk/CryptoOpCapabilityNull.c):

```c
/** @file
  MbedTLS-side Null implementation of GetCryptoOpCapability.

  Returns EFI_NOT_FOUND for every operation. Real provider enumeration
  over mbedtls_md_list / mbedtls_pk_info_from_type / mbedtls_oid_get_*
  is deferred per the design spec's open question (§8).

  Copyright (C) Microsoft Corporation
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/CryptoCapability.h>

EFI_STATUS
EFIAPI
GetCryptoOpCapability (
  IN     CONST EFI_GUID  *OpIdGuid,
  OUT    VOID            *Buffer       OPTIONAL,
  IN OUT UINTN           *BufferSize
  )
{
  if ((OpIdGuid == NULL) || (BufferSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_NOT_FOUND;
}
```

Note: the MbedTLS Null is **standalone** — it does not reference `Pkcs7VerifyOpCapability` or `AuthenticodeOpCapability` extern symbols (unlike the OpenSSL dispatcher), so no per-pipeline handler stubs are needed in MbedTLS in v1.

- [ ] **Step 3: Add `Pk/CryptoOpCapabilityNull.c` and `[Guids]` to each MbedTLS INF**

For each `.inf` found in Step 1, in `[Sources]` add:

```ini
  Pk/CryptoOpCapabilityNull.c
```

And add `[Guids]`:

```ini
[Guids]
  gCryptoOpPkcs7VerifyGuid        ## CONSUMES
  gCryptoOpAuthenticodeVerifyGuid ## CONSUMES
```

- [ ] **Step 4: Build MbedTlsPkg**

```bash
stuart_ci_build -c .pytool/CISettings.py -p MbedTlsPkg -t DEBUG TOOL_CHAIN_TAG=CLANGPDB
```

Expected: build succeeds.

- [ ] **Step 5: Commit**

```bash
git add MbedTlsPkg/Library/BaseCryptLib/
git commit -s -m "MbedTlsPkg/BaseCryptLib: Null GetCryptoOpCapability for parity

MbedTLS-backed BaseCryptLib gets a standalone Null GetCryptoOpCapability
returning EFI_NOT_FOUND for every Op-ID. Real provider enumeration over
mbedtls_md_list / mbedtls_pk_info_from_type / mbedtls_oid_get_* is
deferred per the design spec's open question (section 8)."
```

---

## Task 9: Integration verification

- [ ] **Step 1: Run the full OpensslPkg CI build matrix**

```bash
stuart_ci_build -c .pytool/CISettings.py -p OpensslPkg -t DEBUG TOOL_CHAIN_TAG=CLANGPDB
stuart_ci_build -c .pytool/CISettings.py -p OpensslPkg -t RELEASE TOOL_CHAIN_TAG=CLANGPDB
stuart_ci_build -c .pytool/CISettings.py -p OpensslPkg -t NOOPT \
    -d HostUnitTestCompilerPlugin=run TOOL_CHAIN_TAG=GCC5
```

Expected: all three succeed; the host-test invocation reports 10/10 `CryptoOpCapability` tests pass plus all pre-existing suites still green.

- [ ] **Step 2: Run the full MbedTlsPkg CI build**

```bash
stuart_ci_build -c .pytool/CISettings.py -p MbedTlsPkg -t DEBUG TOOL_CHAIN_TAG=CLANGPDB
stuart_ci_build -c .pytool/CISettings.py -p MbedTlsPkg -t RELEASE TOOL_CHAIN_TAG=CLANGPDB
```

Expected: both succeed.

- [ ] **Step 3: Run the full OneCryptoPkg matrix**

```bash
stuart_build -c PlatformBuild.py TOOL_CHAIN_TAG=CLANGPDB
```

Expected: build succeeds for both DEBUG and RELEASE, both X64 and AARCH64.

- [ ] **Step 4: Spot-check the bundler picks up the new minor version**

```bash
python OneCryptoPkg/Plugin/OneCryptoBundler/OneCryptoBundler.py /tmp/OneCryptoTest.zip
```

Expected: output indicates version `1.1` (the bundler reads `ONE_CRYPTO_VERSION_MAJOR/MINOR` from the protocol header — see [OneCryptoBundler.py#L340-365](../../../OneCryptoPkg/Plugin/OneCryptoBundler/OneCryptoBundler.py)).

- [ ] **Step 5: Final cleanup commit (if any drift)**

If any task left a build warning, dangling include, or unreferenced symbol, fix it here in a single tidying commit. Otherwise this step is a no-op.

```bash
# Only if needed:
git status
# ... fix ...
git commit -s -m "ECIT capability: post-integration tidy"
```

---

## Risks & follow-ups (out of scope here)

- **MbedTLS real implementation.** Task 8 ships Null only. A follow-up patch implements `EnumerateProviderSignatureOids` over `mbedtls_md_list` / `mbedtls_pk_info_from_type` / `mbedtls_oid_get_*` so MbedTLS-backed BaseCryptLib also reports meaningful capability sets.
- **Per-handler CSV caching.** Per spec §8, the helper recomputes on every call. If profiling shows this matters, add a `STATIC CHAR8 *mCached; STATIC UINTN mCachedSize;` per-handler guard. Safe because the provider is static for the lifetime of the binary.
- **`CryptoConformanceApp`** (spec §5.6). Lives outside this repo; design only.
- **Collector driver** (spec §5). Lives in MU_BASECORE; design only.
- **GUID stability.** Once Task 1 lands the two GUIDs to `CryptoPkg.dec`, they are stable forever. Do not regenerate.
