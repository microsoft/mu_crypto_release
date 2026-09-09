#!/usr/bin/env python3
# @file
# Keep the OpenSSL / Mbed TLS version badges in README.md in sync with the
# actual submodule versions (the single source of truth).
#
# The version strings are derived from the submodule working trees:
#   - OpenSSL:  OpensslPkg/Library/OpensslLib/openssl/VERSION.dat
#   - Mbed TLS: MbedTlsPkg/Library/MbedTlsLib/mbedtls/include/mbedtls/build_info.h
#
# Usage:
#   python Scripts/sync_readme_versions.py            # rewrite README badges
#   python Scripts/sync_readme_versions.py --check    # fail if badges are stale
#   python Scripts/sync_readme_versions.py --component openssl --check
#
# In CI the relevant submodule is only present in the job that builds that
# package, so --component lets each job verify just the badge it can see.
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"

OPENSSL_VERSION_DAT = REPO_ROOT / "OpensslPkg/Library/OpensslLib/openssl/VERSION.dat"
MBEDTLS_BUILD_INFO = REPO_ROOT / "MbedTlsPkg/Library/MbedTlsLib/mbedtls/include/mbedtls/build_info.h"

# Each component: how to read its version and how to render its badge line.
OPENSSL_BADGE_RE = re.compile(
    r"\[!\[OpenSSL\]\(https://img\.shields\.io/badge/OpenSSL-[^)]*\)\]"
    r"\(https://github\.com/openssl/openssl/releases/tag/[^)]*\)"
)
MBEDTLS_BADGE_RE = re.compile(
    r"\[!\[Mbed TLS\]\(https://img\.shields\.io/badge/Mbed_TLS-[^)]*\)\]"
    r"\(https://github\.com/Mbed-TLS/mbedtls/releases/tag/[^)]*\)"
)


def shield_escape(text: str) -> str:
    """Escape a shields.io badge message segment (order matters)."""
    return text.replace("_", "__").replace("-", "--").replace(" ", "_")


def read_openssl_version() -> str:
    if not OPENSSL_VERSION_DAT.is_file():
        raise FileNotFoundError(
            f"{OPENSSL_VERSION_DAT} not found; run 'git submodule update --init "
            "OpensslPkg/Library/OpensslLib/openssl' first."
        )
    fields = {}
    for line in OPENSSL_VERSION_DAT.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip().strip('"')
    version = f"{fields['MAJOR']}.{fields['MINOR']}.{fields['PATCH']}"
    pre = fields.get("PRE_RELEASE_TAG", "")
    if pre:
        version += f"-{pre}"
    return version


def read_mbedtls_version() -> str:
    if not MBEDTLS_BUILD_INFO.is_file():
        raise FileNotFoundError(
            f"{MBEDTLS_BUILD_INFO} not found; run 'git submodule update --init "
            "MbedTlsPkg/Library/MbedTlsLib/mbedtls' first."
        )
    match = re.search(
        r'#define\s+MBEDTLS_VERSION_STRING\s+"([^"]+)"',
        MBEDTLS_BUILD_INFO.read_text(encoding="utf-8"),
    )
    if not match:
        raise ValueError(f"MBEDTLS_VERSION_STRING not found in {MBEDTLS_BUILD_INFO}")
    return match.group(1)


def openssl_badge(version: str) -> str:
    return (
        f"[![OpenSSL](https://img.shields.io/badge/OpenSSL-{shield_escape(version)}-blue)]"
        f"(https://github.com/openssl/openssl/releases/tag/openssl-{version})"
    )


def mbedtls_badge(version: str) -> str:
    return (
        f"[![Mbed TLS](https://img.shields.io/badge/Mbed_TLS-{shield_escape(version)}-blue)]"
        f"(https://github.com/Mbed-TLS/mbedtls/releases/tag/v{version})"
    )


def build_replacements(component: str):
    """Return list of (name, regex, new_badge) for the requested component(s)."""
    replacements = []
    if component in ("openssl", "all"):
        replacements.append(
            ("OpenSSL", OPENSSL_BADGE_RE, openssl_badge(read_openssl_version()))
        )
    if component in ("mbedtls", "all"):
        replacements.append(
            ("Mbed TLS", MBEDTLS_BADGE_RE, mbedtls_badge(read_mbedtls_version()))
        )
    return replacements


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if README badges are out of date (do not modify).",
    )
    parser.add_argument(
        "--component",
        choices=("openssl", "mbedtls", "all"),
        default="all",
        help="Which badge(s) to verify/update (default: all).",
    )
    args = parser.parse_args()

    # Preserve original (CRLF) line endings by disabling newline translation.
    with open(README, "r", encoding="utf-8", newline="") as fh:
        content = fh.read()
    updated = content
    stale = []

    for name, pattern, new_badge in build_replacements(args.component):
        if not pattern.search(updated):
            print(f"error: {name} badge not found in README.md", file=sys.stderr)
            return 2
        if pattern.search(updated).group(0) != new_badge:
            stale.append(name)
        updated = pattern.sub(lambda _m, b=new_badge: b, updated)

    if updated == content:
        print("README badges are up to date.")
        return 0

    if args.check:
        print(
            "error: README badge(s) out of date: "
            + ", ".join(stale)
            + "\n       Run 'python Scripts/sync_readme_versions.py' to update.",
            file=sys.stderr,
        )
        return 1

    with open(README, "w", encoding="utf-8", newline="") as fh:
        fh.write(updated)
    print("Updated README badges: " + ", ".join(stale))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
