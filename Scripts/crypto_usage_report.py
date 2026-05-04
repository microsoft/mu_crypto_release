#!/usr/bin/env python3
"""Analyze crypto function usage for an EDK2 platform from a BUILD_REPORT.TXT.

Parses the build report to find modules that consume BaseCryptLib/TlsLib,
then scans their source files to identify which specific crypto functions
are called. Produces a per-phase, per-module usage report.

Requires: Python 3.8+, no external packages.

Example:
    python crypto_usage_report.py \\
        -r Build/QemuQ35PkgX64/DEBUG_GCC5/BUILD_REPORT.TXT \\
        -w /home/user/mu_tiano_platforms

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

# Crypto headers to parse for known function names (edk2-relative paths)
CRYPTO_HEADERS = [
    "CryptoPkg/Include/Library/BaseCryptLib.h",
    "CryptoPkg/Include/Library/TlsLib.h",
    "CryptoPkg/Include/Library/HmacSha1Lib.h",
    "CryptoPkg/Include/Library/HashApiLib.h",
]

# Library classes that indicate a module consumes crypto services
CRYPTO_LIBRARY_CLASSES = {"basecryptlib", "tlslib", "hmacsha1lib", "hashapilib"}

# Substrings in INF paths that identify crypto *provider* implementations
# (identified by path name markers). These are excluded from source scanning
# because they are known crypto provider implementations.
CRYPTO_PROVIDER_MARKERS = [
    "BaseCryptLibOnOneCrypto",
    "BaseCryptLibOnProtocolPpi",
    "BaseCryptLibNull",
    "BaseCryptLibMbedTls",
    "TlsLibNull",
    "HmacSha1Lib/HmacSha1Lib",  # implementation, not consumer
    "BaseHashApiLib",
]

# Family classification rules (order matters — first match wins)
# Functions not matched here get auto-derived family names from
# their CamelCase prefix, so new crypto families in the headers
# are automatically discovered.
CRYPTO_FAMILIES = [
    ("MD5",          re.compile(r"^Md5")),
    ("SHA-1",        re.compile(r"^Sha1")),
    ("SHA-256",      re.compile(r"^Sha256")),
    ("SHA-384",      re.compile(r"^Sha384")),
    ("SHA-512",      re.compile(r"^Sha512")),
    ("SM3",          re.compile(r"^Sm3")),
    ("ParallelHash", re.compile(r"^ParallelHash")),
    ("HMAC-SHA1",    re.compile(r"^HmacSha1")),
    ("HMAC-SHA256",  re.compile(r"^HmacSha256")),
    ("HMAC-SHA384",  re.compile(r"^HmacSha384")),
    ("AES",          re.compile(r"^Aes|^AeadAesGcm")),
    ("RSA",          re.compile(r"^Rsa")),
    ("PKCS",         re.compile(r"^Pkcs")),
    ("X509/ASN1",    re.compile(r"^X509|^Asn1")),
    ("Authenticode", re.compile(r"^Authenticode|^ImageTimestamp|^VerifyEKUs")),
    ("DH",           re.compile(r"^Dh")),
    ("Random",       re.compile(r"^Random")),
    ("HKDF",         re.compile(r"^Hkdf")),
    ("BigNum",       re.compile(r"^BigNum")),
    ("EC",           re.compile(r"^Ec")),
    ("TLS",          re.compile(r"^Tls")),
    ("HashApi",      re.compile(r"^HashApi")),
    ("Misc",         re.compile(r"^GetCryptoProvider|^BaseCryptInit")),
]

# Driver type string (from build report) → boot phase mapping
PHASE_MAP = {
    "pei_core": "PEI",
    "peim": "PEI",
    "dxe_core": "DXE",
    "driver": "DXE",
    "dxe_driver": "DXE",
    "uefi_driver": "DXE",
    "runtime_driver": "Runtime",
    "dxe_runtime_driver": "Runtime",
    "smm_driver": "SMM",
    "dxe_smm_driver": "SMM",
    "smm_core": "SMM",
    "mm_standalone": "StandaloneMM",
    "mm_core_standalone": "StandaloneMM",
    "application": "Application",
    "uefi_application": "Application",
}

# Regex to match EDK2 package directory names (e.g. "CryptoPkg", "MdePkg")
# in absolute paths. Matches any path segment ending in "Pkg".
RE_PKG_DIR = re.compile(r"/([A-Za-z0-9]+Pkg)/")

# Build report delimiters
RE_REGION_START = re.compile(r"^>={50,}<$")
RE_REGION_END = re.compile(r"^<={50,}>$")
RE_SUBSECTION_START = re.compile(r"^>-{50,}<$")
RE_SUBSECTION_END = re.compile(r"^<-{50,}>$")
RE_SEPARATOR = re.compile(r"^[-=]{50,}$")

# Header function declaration pattern: "FunctionName (" at start of line
RE_FUNC_DECL = re.compile(r"^([A-Z][a-zA-Z0-9]+)\s*\(", re.MULTILINE)

# Words that match RE_FUNC_DECL but are not crypto functions (e.g. from
# license headers: "Copyright (c) Microsoft").
HEADER_FALSE_POSITIVES = {"Copyright", "SPDX"}

# ─────────────────────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class ModuleInfo:
    """A module parsed from the build report."""
    name: str = ""
    inf_path: str = ""           # edk2-relative path from report header
    arch: str = ""
    driver_type: str = ""
    phase: str = ""
    guid: str = ""
    libraries: Dict[str, str] = field(default_factory=dict)  # class → abs INF


@dataclass
class LibraryCryptoUsage:
    """Crypto functions found in one library's source files."""
    inf_path: str = ""
    lib_class: str = ""
    functions: Set[str] = field(default_factory=set)


@dataclass
class ModuleCryptoUsage:
    """Aggregated crypto usage for a module."""
    module: ModuleInfo = None
    library_usages: List[LibraryCryptoUsage] = field(default_factory=list)
    all_functions: Set[str] = field(default_factory=set)
    families: Dict[str, Set[str]] = field(default_factory=dict)
    total_sources_scanned: int = 0


# ─────────────────────────────────────────────────────────────────────────────
# Build Report Parser
# ─────────────────────────────────────────────────────────────────────────────


def parse_build_report(report_path: str) -> Tuple[dict, List[ModuleInfo]]:
    """Parse BUILD_REPORT.TXT and extract module information.

    Returns:
        (header_info, list_of_modules)
    """
    with open(report_path, "r", errors="replace") as f:
        lines = [line.rstrip("\r\n") for line in f]

    header = _parse_report_header(lines)
    modules = _parse_module_regions(lines)
    return header, modules


def _parse_report_header(lines: list) -> dict:
    """Extract platform-level info from the report header."""
    header = {}
    for line in lines:
        stripped = line.strip()
        if RE_REGION_START.match(stripped):
            break
        parts = stripped.partition(":")
        if parts[1] and parts[2].strip():
            key = parts[0].strip().lower()
            val = parts[2].strip()
            if key == "platform name":
                header["platform_name"] = val
            elif key == "platform dsc path":
                header["dsc_path"] = val
            elif key == "output path":
                header["output_path"] = val
    return header


def _parse_module_regions(lines: list) -> List[ModuleInfo]:
    """Find and parse all Module Summary regions in the report."""
    modules = []
    i = 0
    while i < len(lines):
        if (RE_REGION_START.match(lines[i].strip()) and
                i + 1 < len(lines) and
                lines[i + 1].strip() == "Module Summary"):
            mod, i = _parse_one_module(lines, i)
            if mod and mod.name:
                modules.append(mod)
        else:
            i += 1
    return modules


def _parse_one_module(lines: list, start: int) -> Tuple[Optional[ModuleInfo], int]:
    """Parse a single module region starting at `start`.

    Returns (ModuleInfo, next_line_index).
    """
    mod = ModuleInfo()
    i = start + 2  # skip ">===<" and "Module Summary"

    # --- Parse header key: value pairs ---
    while i < len(lines):
        line = lines[i].strip()
        if RE_SEPARATOR.match(line) or RE_SUBSECTION_START.match(line):
            break
        if RE_REGION_END.match(line):
            return mod, i + 1

        parts = line.partition(":")
        if parts[1] and parts[2].strip():
            key = parts[0].strip().lower()
            value = parts[2].strip()
            if key == "module name":
                mod.name = value
            elif key == "module arch":
                mod.arch = value
            elif key == "module inf path":
                while ".inf" not in value.lower() and i + 1 < len(lines):
                    i += 1
                    value += "/" + lines[i].strip()
                mod.inf_path = os.path.normpath(value.replace("\\", "/"))
            elif key == "file guid":
                mod.guid = value
            elif key == "driver type":
                m = re.search(r"\(([^)]+)\)", value)
                if m:
                    mod.driver_type = m.group(1)
                    mod.phase = PHASE_MAP.get(m.group(1).lower(), "Unknown")
        i += 1

    # --- Find Library subsection ---
    while i < len(lines):
        line = lines[i].strip()
        if RE_REGION_END.match(line):
            return mod, i + 1
        if RE_SUBSECTION_START.match(line):
            i += 1
            if i < len(lines) and lines[i].strip() == "Library":
                i += 1  # skip "Library"
                if i < len(lines) and RE_SEPARATOR.match(lines[i].strip()):
                    i += 1  # skip separator
                mod.libraries, i = _parse_library_subsection(lines, i)
                continue
        i += 1

    return mod, i


def _parse_library_subsection(lines: list, start: int) -> Tuple[Dict[str, str], int]:
    """Parse library entries from the Library subsection.

    Returns (libraries_dict, next_line_index).
    """
    MAX_LIBRARY_ENTRY_LINES = 50  # Guard against malformed BUILD_REPORT
    libraries = {}
    null_count = 0
    i = start

    while i < len(lines):
        line = lines[i].strip()
        if RE_SUBSECTION_END.match(line) or RE_SUBSECTION_START.match(line) or RE_REGION_END.match(line):
            break
        if not line or RE_SEPARATOR.match(line):
            i += 1
            continue

        # Accumulate until we have a complete entry with "}"
        entry = line
        entry_lines = 0
        while "}" not in entry and i + 1 < len(lines) and entry_lines < MAX_LIBRARY_ENTRY_LINES:
            i += 1
            entry_lines += 1
            entry += " " + lines[i].strip()

        if "{" in entry and "}" in entry:
            inf_path = entry.partition("{")[0].strip()
            class_info = entry.partition("{")[2].partition("}")[0]
            lib_class = class_info.partition(":")[0].strip()

            if lib_class.lower() == "null":
                lib_class = f"NULL{null_count}"
                null_count += 1

            libraries[lib_class] = inf_path

        i += 1

    return libraries, i


# ─────────────────────────────────────────────────────────────────────────────
# Package Root Discovery
# ─────────────────────────────────────────────────────────────────────────────


def discover_package_roots(modules: List[ModuleInfo]) -> List[str]:
    """Discover package root directories from absolute library INF paths.

    Scans all library paths for directory segments matching *Pkg (the
    standard EDK2 package naming convention) and extracts the parent
    directory as a potential root.  This avoids a hardcoded package list
    and works for any platform.
    """
    roots = set()
    for mod in modules:
        for lib_path in mod.libraries.values():
            normalized = lib_path.replace("\\", "/")
            m = RE_PKG_DIR.search(normalized)
            if m:
                candidate = normalized[:m.start()]
                if os.path.isdir(candidate):
                    roots.add(candidate)
    return sorted(roots, key=len, reverse=True)  # longer roots first


def discover_package_roots_from_workspace(workspace: str) -> List[str]:
    """Discover package roots by locating the known crypto headers."""
    roots = set()
    expected_headers = [header.replace("\\", "/") for header in CRYPTO_HEADERS]

    for dirpath, _, filenames in os.walk(workspace):
        for filename in filenames:
            relative_path = os.path.relpath(
                os.path.join(dirpath, filename), workspace
            ).replace("\\", "/")
            for header_rel in expected_headers:
                if relative_path.endswith(header_rel):
                    prefix = relative_path[:-len(header_rel)].rstrip("/")
                    root = os.path.join(workspace, prefix) if prefix else workspace
                    if os.path.isdir(root):
                        roots.add(os.path.normpath(root))

    return sorted(roots, key=len, reverse=True)


def resolve_inf_path(relative_inf: str, package_roots: List[str]) -> Optional[str]:
    """Resolve an edk2-relative INF path to an absolute path."""
    for root in package_roots:
        candidate = os.path.join(root, relative_inf)
        if os.path.isfile(candidate):
            return candidate
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Crypto Function Extraction from Headers
# ─────────────────────────────────────────────────────────────────────────────


def extract_crypto_functions(package_roots: List[str]) -> Set[str]:
    """Extract known crypto function names from header files.

    All function declarations in the crypto headers are trusted as
    crypto API functions.  No prefix filter is applied, so new
    families added to the headers are automatically discovered.
    """
    functions = set()
    for header_rel in CRYPTO_HEADERS:
        header_path = resolve_inf_path(header_rel, package_roots)
        if header_path and os.path.isfile(header_path):
            with open(header_path, errors="replace") as f:
                content = f.read()
            for m in RE_FUNC_DECL.finditer(content):
                name = m.group(1)
                if name not in HEADER_FALSE_POSITIVES:
                    functions.add(name)

    if not functions:
        print("  WARNING: Could not parse crypto headers", file=sys.stderr)

    return functions


# ─────────────────────────────────────────────────────────────────────────────
# INF Source File Extraction
# ─────────────────────────────────────────────────────────────────────────────


def parse_inf_sources(inf_path: str, arch: str = "X64") -> List[str]:
    """Parse an INF file and return absolute paths to .c source files."""
    if not os.path.isfile(inf_path):
        return []

    source_files = []
    in_sources = False
    inf_dir = os.path.dirname(inf_path)
    arch_lower = arch.lower()

    try:
        with open(inf_path, errors="replace") as f:
            for raw_line in f:
                stripped = raw_line.strip()

                # Skip blank lines and pure comments
                if not stripped or stripped.startswith("#"):
                    continue

                # Section header detection
                if stripped.startswith("["):
                    section_lower = stripped.lower()
                    in_sources = False
                    if "sources" in section_lower:
                        # Include [Sources], [Sources.common], [Sources.X64]
                        in_sources = (
                            section_lower.startswith("[sources]") or
                            "[sources.common" in section_lower or
                            f"[sources.{arch_lower}" in section_lower
                        )
                    continue

                if in_sources:
                    # Strip inline comments
                    src_line = stripped.split("#")[0].strip()
                    if not src_line:
                        continue
                    # Take path before any | (toolchain filter)
                    src = src_line.split("|")[0].strip()
                    if src.lower().endswith(".c"):
                        abs_path = os.path.normpath(os.path.join(inf_dir, src))
                        if os.path.isfile(abs_path):
                            source_files.append(abs_path)
    except (IOError, UnicodeDecodeError):
        pass

    return source_files


# ─────────────────────────────────────────────────────────────────────────────
# Crypto Function Scanner
# ─────────────────────────────────────────────────────────────────────────────


def build_scanner_pattern(known_functions: Set[str]) -> re.Pattern:
    """Build a compiled regex that matches any known crypto function name."""
    sorted_funcs = sorted(known_functions, key=len, reverse=True)
    pattern = r"\b(" + "|".join(re.escape(f) for f in sorted_funcs) + r")\b"
    return re.compile(pattern)


def scan_file_for_crypto(filepath: str, pattern: re.Pattern) -> Set[str]:
    """Scan a C source file for crypto function references."""
    try:
        with open(filepath, errors="replace") as f:
            content = f.read()
    except IOError:
        return set()
    return set(pattern.findall(content))


def is_crypto_provider(inf_path: str) -> bool:
    """Check if an INF is a crypto provider implementation (not a consumer)."""
    normalized = inf_path.replace("\\", "/")
    parts = normalized.split("/")
    return any(marker in parts for marker in CRYPTO_PROVIDER_MARKERS)


# ─────────────────────────────────────────────────────────────────────────────
# Family Classification
# ─────────────────────────────────────────────────────────────────────────────


def _derive_family_name(func_name: str) -> str:
    """Derive a family name from a CamelCase function name.

    Splits on CamelCase boundaries and drops the last word
    (typically the action verb: Init, Free, Sign, Verify, etc.).
    E.g. MlDsaSign -> MlDsa, SlhDsaVerify -> SlhDsa.
    """
    words = re.findall(r'[A-Z][a-z0-9]*|[0-9]+', func_name)
    if len(words) <= 1:
        return func_name
    return "".join(words[:-1])


def classify_function(func_name: str) -> str:
    """Classify a crypto function into a family.

    Uses CRYPTO_FAMILIES for known families (with friendly names),
    then falls back to auto-derivation from the CamelCase prefix.
    """
    for family_name, pattern in CRYPTO_FAMILIES:
        if pattern.match(func_name):
            return family_name
    return _derive_family_name(func_name)


def classify_functions(functions: Set[str]) -> Dict[str, Set[str]]:
    """Group functions by crypto family."""
    families = defaultdict(set)
    for func in functions:
        families[classify_function(func)].add(func)
    return dict(families)


def find_auto_discovered_families(
    functions: Set[str],
) -> Dict[str, Set[str]]:
    """Return families derived from function names rather than manual rules."""
    manual_families = {family_name for family_name, _ in CRYPTO_FAMILIES}
    derived_families = defaultdict(set)
    for func in functions:
        family = classify_function(func)
        if family not in manual_families:
            derived_families[family].add(func)
    return dict(sorted(derived_families.items()))


# ─────────────────────────────────────────────────────────────────────────────
# Analysis
# ─────────────────────────────────────────────────────────────────────────────


def is_crypto_consumer(mod: ModuleInfo) -> bool:
    """Check if a module links any crypto library class."""
    for cls in mod.libraries:
        # Strip trailing digits (NULL0, NULL1, ...) and check
        base = cls.lower().rstrip("0123456789")
        if base in CRYPTO_LIBRARY_CLASSES:
            return True
    return False


def analyze_module(
    mod: ModuleInfo,
    package_roots: List[str],
    scanner: re.Pattern,
) -> Optional[ModuleCryptoUsage]:
    """Analyze a single module's crypto function usage."""
    usage = ModuleCryptoUsage(module=mod)

    # Scan the module's own source files
    module_abs = resolve_inf_path(mod.inf_path, package_roots)
    if module_abs:
        _scan_inf_sources(module_abs, "(module)", mod.arch, scanner, usage)

    # Scan each linked library (skip crypto provider implementations)
    for lib_class, lib_inf_path in mod.libraries.items():
        if is_crypto_provider(lib_inf_path):
            continue
        _scan_inf_sources(lib_inf_path, lib_class, mod.arch, scanner, usage)

    if not usage.all_functions:
        return None

    usage.families = classify_functions(usage.all_functions)
    return usage


def _scan_inf_sources(
    inf_path: str,
    lib_class: str,
    arch: str,
    scanner: re.Pattern,
    usage: ModuleCryptoUsage,
):
    """Parse an INF for .c sources, scan them, and accumulate findings."""
    sources = parse_inf_sources(inf_path, arch)
    usage.total_sources_scanned += len(sources)

    found = set()
    for src in sources:
        found |= scan_file_for_crypto(src, scanner)

    if found:
        usage.library_usages.append(LibraryCryptoUsage(
            inf_path=inf_path,
            lib_class=lib_class,
            functions=found,
        ))
        usage.all_functions |= found


# ─────────────────────────────────────────────────────────────────────────────
# Report Output
# ─────────────────────────────────────────────────────────────────────────────


def shorten_path(abs_path: str, package_roots: List[str]) -> str:
    """Shorten an absolute path to a readable relative form."""
    normalized = abs_path.replace("\\", "/")
    for root in package_roots:
        prefix = root.replace("\\", "/").rstrip("/") + "/"
        if normalized.startswith(prefix):
            return normalized[len(prefix):]
    # Fallback: show from the first *Pkg/ directory onward
    m = RE_PKG_DIR.search(normalized)
    if m:
        return normalized[m.start() + 1:]
    return os.path.basename(abs_path)


def output_table(
    header: dict,
    results: List[ModuleCryptoUsage],
    known_functions: Set[str],
    package_roots: List[str],
    verbose: bool,
):
    """Print a human-readable table report to stdout."""
    platform = header.get("platform_name", "Unknown")

    print()
    print("=" * 78)
    print(f"  Platform Crypto Usage Report")
    print(f"  Platform:          {platform}")
    print(f"  Modules:           {header.get('total_modules', '?')} total, "
          f"{len(results)} use crypto")
    print(f"  Known functions:   {len(known_functions)}")
    print("=" * 78)

    # Group results by boot phase
    by_phase = defaultdict(list)
    for usage in results:
        by_phase[usage.module.phase].append(usage)

    phase_order = ["PEI", "DXE", "Runtime", "SMM", "StandaloneMM",
                   "Application", "Unknown"]

    for phase in phase_order:
        if phase not in by_phase:
            continue
        phase_list = by_phase[phase]
        print()
        n = len(phase_list)
        print(f"--- {phase} Phase ({n} module{'s' if n != 1 else ''}) ---")

        for usage in sorted(phase_list, key=lambda u: u.module.name):
            mod = usage.module
            print()
            print(f"  {mod.name} ({mod.inf_path})")
            if mod.guid:
                print(f"    GUID: {mod.guid}")

            if verbose:
                print(f"    Sources scanned: {usage.total_sources_scanned}")
                # Show crypto provider
                for cls, path in mod.libraries.items():
                    if is_crypto_provider(path):
                        print(f"    Crypto via: {shorten_path(path, package_roots)} "
                              f"({cls.rstrip('0123456789')})")
                # Show contributing libraries
                for lu in usage.library_usages:
                    short = shorten_path(lu.inf_path, package_roots)
                    funcs = ", ".join(sorted(lu.functions))
                    print(f"    [{lu.lib_class}] {short}")
                    print(f"      -> {funcs}")

            # Show families and functions (known order first, then auto-derived)
            known_order = [name for name, _ in CRYPTO_FAMILIES]
            ordered = [f for f in known_order if f in usage.families]
            ordered += sorted(f for f in usage.families if f not in set(known_order))
            for family_name in ordered:
                funcs = sorted(usage.families[family_name])
                print(f"    {family_name:14s} {', '.join(funcs)}")

    # Summary
    used = set()
    all_funcs = set()
    for u in results:
        used |= set(u.families.keys())
        all_funcs |= u.all_functions

    all_known_families = set(classify_functions(known_functions).keys())
    unused = sorted(all_known_families - used - {"Misc", "Unknown"})
    used_display = sorted(used - {"Misc", "Unknown"})

    print()
    print("=" * 78)
    print("  Summary")
    print("=" * 78)
    print(f"  Families in use:     {', '.join(used_display)}")
    if unused:
        print(f"  Families NOT used:   {', '.join(unused)}")
    print(f"  Unique functions:    {len(all_funcs)} / {len(known_functions)}")

    # List all unique functions
    print()
    print("  All crypto functions used by this platform:")
    for func in sorted(all_funcs):
        family = classify_function(func)
        print(f"    {func:40s} [{family}]")
    print()


def output_json(
    header: dict,
    results: List[ModuleCryptoUsage],
    known_functions: Set[str],
    package_roots: List[str],
):
    """Print a JSON report to stdout."""
    used = set()
    all_funcs = set()
    for u in results:
        used |= set(u.families.keys())
        all_funcs |= u.all_functions

    all_known_families = set(classify_functions(known_functions).keys())
    unused = all_known_families - used - {"Misc", "Unknown"}

    report = {
        "platform": header.get("platform_name", "Unknown"),
        "summary": {
            "total_modules": header.get("total_modules", 0),
            "crypto_consumers": len(results),
            "unique_functions": len(all_funcs),
            "total_known_functions": len(known_functions),
            "families_used": sorted(used - {"Misc"}),
            "families_unused": sorted(unused),
            "all_functions_used": sorted(all_funcs),
        },
        "modules": {},
    }

    for usage in results:
        mod = usage.module
        entry = {
            "inf": mod.inf_path,
            "guid": mod.guid,
            "phase": mod.phase,
            "arch": mod.arch,
            "driver_type": mod.driver_type,
            "functions": sorted(usage.all_functions),
            "families": {k: sorted(v) for k, v in sorted(usage.families.items())},
            "sources_scanned": usage.total_sources_scanned,
        }
        if usage.library_usages:
            entry["contributing_libraries"] = [
                {
                    "class": lu.lib_class,
                    "inf": shorten_path(lu.inf_path, package_roots),
                    "functions": sorted(lu.functions),
                    "full_path": lu.inf_path,  # Full INF path for NULL library disambiguation
                }
                for lu in usage.library_usages
            ]
        # Use GUID to disambiguate modules with the same name (e.g. FmpDxe)
        key = mod.name if mod.guid is None else f"{mod.name} [{mod.guid}]"
        report["modules"][key] = entry

    print(json.dumps(report, indent=2))


def output_family_validation(known_functions: Set[str]):
    """Report families discovered via automatic prefix derivation."""
    auto_families = find_auto_discovered_families(known_functions)

    print()
    print("=" * 78)
    print("  Auto-Discovered Crypto Families")
    print("=" * 78)

    if not auto_families:
        print("  No auto-derived families discovered.")
        print()
        return

    print("  These families are derived from header function prefixes and are")
    print("  not explicitly listed in CRYPTO_FAMILIES:")
    print()
    for family_name, funcs in auto_families.items():
        print(f"  {family_name:20s} {', '.join(sorted(funcs))}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────


def parse_args():
    p = argparse.ArgumentParser(
        description="Analyze crypto function usage from an EDK2 BUILD_REPORT.TXT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python %(prog)s \\
      -r Build/QemuQ35PkgX64/DEBUG_GCC5/BUILD_REPORT.TXT \\
      -w /home/user/mu_tiano_platforms

  python %(prog)s \\
      -w /home/user/mu_tiano_platforms \\
      --validate-families
        """,
    )
    p.add_argument("-r", "--report",
                   help="Path to BUILD_REPORT.TXT")
    p.add_argument("-w", "--workspace", required=True,
                   help="Workspace root directory")
    p.add_argument("-f", "--format", choices=["table", "json"], default="table",
                   help="Output format (default: table)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show per-library attribution detail")
    p.add_argument("-e", "--exclude", nargs="+", default=[],
                   metavar="PATTERN",
                   help="Exclude modules whose name matches any PATTERN "
                        "(substring match, case-insensitive). "
                        "E.g. -e UnitTest TestApp")
    p.add_argument("--validate-families", action="store_true",
                   help="Report crypto families discovered from header prefixes "
                        "that are not explicitly listed in CRYPTO_FAMILIES")
    return p.parse_args()


def main():
    args = parse_args()

    workspace = os.path.abspath(args.workspace)

    if not os.path.isdir(workspace):
        print(f"ERROR: Workspace not found: {workspace}", file=sys.stderr)
        sys.exit(1)

    report_path = None
    if args.report:
        report_path = os.path.abspath(args.report)
        if not os.path.isfile(report_path):
            print(f"ERROR: Report not found: {report_path}", file=sys.stderr)
            sys.exit(1)
    elif not args.validate_families:
        print("ERROR: --report is required unless --validate-families is used",
              file=sys.stderr)
        sys.exit(1)

    header = {}
    modules = []

    if report_path:
        # Step 1: Parse the build report
        print("Parsing build report...", file=sys.stderr)
        header, modules = parse_build_report(report_path)
        header["total_modules"] = len(modules)
        print(f"  Found {len(modules)} modules", file=sys.stderr)

        if not modules:
            print("ERROR: No modules found in report", file=sys.stderr)
            sys.exit(1)

    # Step 2: Discover package root directories
    package_roots = discover_package_roots(modules) if modules else []
    if not package_roots:
        package_roots = discover_package_roots_from_workspace(workspace)
    # Always include workspace root as a fallback
    if workspace not in package_roots:
        package_roots.append(workspace)
    print(f"  Discovered {len(package_roots)} package root(s)", file=sys.stderr)

    # Step 3: Extract known crypto functions from headers
    known_functions = extract_crypto_functions(package_roots)
    print(f"  Loaded {len(known_functions)} known crypto functions", file=sys.stderr)

    if not known_functions:
        print("ERROR: No crypto functions found — check workspace path", file=sys.stderr)
        sys.exit(1)

    if args.validate_families:
        output_family_validation(known_functions)
        return

    scanner = build_scanner_pattern(known_functions)

    # Step 4: Identify and analyze crypto consumers
    exclude_patterns = [p.lower() for p in args.exclude]
    consumers = [m for m in modules if is_crypto_consumer(m)]
    if exclude_patterns:
        before = len(consumers)
        consumers = [
            m for m in consumers
            if not any(pat in m.name.lower() for pat in exclude_patterns)
        ]
        skipped = before - len(consumers)
        if skipped:
            print(f"  Excluded {skipped} module(s) matching: {', '.join(args.exclude)}",
                  file=sys.stderr)
    print(f"  Found {len(consumers)} crypto-consuming modules", file=sys.stderr)

    print("Scanning source files...", file=sys.stderr)
    results = []
    for mod in consumers:
        usage = analyze_module(mod, package_roots, scanner)
        if usage:
            results.append(usage)

    total_scanned = sum(u.total_sources_scanned for u in results)
    print(f"  Scanned {total_scanned} source files", file=sys.stderr)
    print(f"  {len(results)} modules have actual crypto function calls",
          file=sys.stderr)

    # Step 5: Output
    if args.format == "json":
        output_json(header, results, known_functions, package_roots)
    else:
        output_table(header, results, known_functions, package_roots,
                     args.verbose)


if __name__ == "__main__":
    main()