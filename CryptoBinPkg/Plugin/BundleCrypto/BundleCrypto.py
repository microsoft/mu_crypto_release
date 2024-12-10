## @file BundleCrypto.py
# Plugin to Bundle the CryptoBin build output
#
##
# Copyright (c) Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
from edk2toolext.environment.plugintypes.uefi_build_plugin import IUefiBuildPlugin
from pathlib import Path

class BundleCrypto(IUefiBuildPlugin):

    def do_post_build(self, thebuilder):
        #Path to Build output
        build_path = Path(thebuilder.env.GetValue("BUILD_OUTPUT_BASE"))
        #Path to where each bundle will be placed
        bundle_dir = Path(thebuilder.ws) / "Bundle" / thebuilder.flavor / thebuilder.env.GetValue("TARGET")

        # Copy .pdb, .depex, .map, .efi files for each architecture built.
        arch_list = thebuilder.env.GetValue("TARGET_ARCH")
        for arch in arch_list.split(" "):
            target_dir = bundle_dir / arch
            target_dir.mkdir(parents=True, exist_ok=True)
            arch_build_path = build_path / arch
            files = list(arch_build_path.rglob("*.pdb")) \
                + list(arch_build_path.rglob("*.map")) \
                + list(arch_build_path.rglob("*.efi")) \
                + list(arch_build_path.rglob("*.depex"))
            for file in files:
                # pdb exists in DEBUG and OUTPUT directory. Same file.
                file_out = target_dir / file.name
                if file.parent.name != "OUTPUT":
                    continue
                # If it exists and has the same file identifier, skip it.
                if file_out.exists() and file.stat().st_ino == file_out.stat().st_ino:
                    continue
                if "vc1" in file.name.lower():
                    continue

                file_out.unlink(missing_ok=True)
                file_out.hardlink_to(file)

        # Copy the Build report
        br_src = Path(thebuilder.env.GetValue("BUILD_OUTPUT_BASE"), "BUILD_REPORT.TXT")
        br_dst = bundle_dir / f"BUILD_REPORT_{arch_list.replace(' ', '_')}.TXT"
        if not br_dst.exists() or br_dst.stat().st_ino != br_src.stat().st_ino:
            br_dst.unlink(missing_ok=True)
            br_dst.hardlink_to(br_src)

        # Copy the build log
        bl_src = Path(thebuilder.ws) / "Build" / f"BUILDLOG_CryptoBin_{thebuilder.flavor}_{thebuilder.env.GetValue('TARGET')}.txt"
        bl_dst = bundle_dir / f"BUILDLOG_CryptoBin_{thebuilder.flavor}_{thebuilder.env.GetValue('TARGET')}_{arch_list.replace(' ', '_')}.txt"
        if not bl_dst.exists() or bl_dst.stat().st_ino != bl_src.stat().st_ino:
            bl_dst.unlink(missing_ok=True)
            bl_dst.hardlink_to(bl_src)

        # Copy CryptoBinPkg/Driver/* contents (excluding Packaging)
        driver_src = Path(thebuilder.edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath("CryptoBinPkg")) / "Driver"
        driver_out = Path(thebuilder.ws) / "Bundle" / "Driver"
        driver_out.mkdir(parents=True, exist_ok=True)
        for file in driver_src.iterdir():
            if file.is_dir():
                continue
            file_out = driver_out / file.name
            file_out.unlink(missing_ok=True)
            file_out.hardlink_to(file)
        driver_bin_src = driver_src / "Bin"
        driver_bin_out = driver_out / "Bin"
        driver_bin_out.mkdir(parents=True, exist_ok=True)
        for file in driver_bin_src.iterdir():
            if file.is_dir():
                continue
            file_out = driver_bin_out / file.name
            file_out.unlink(missing_ok=True)
            file_out.hardlink_to(file)

        return 0
