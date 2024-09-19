import zipfile
import urllib.request
import sys
import subprocess
import shutil
import requests
import os
import argparse
import ssl
import certifi
from typing import List

from pathlib import Path 
import xml.etree.ElementTree

#
#  Script for running QEMU with the appropriate options for the given SKU/ARCH.
#
#  Copyright (c) Microsoft Corporation
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

#
# Constants
#

STARTUP_SCRIPT = r'''
#!/bin/nsh
echo -off
for %a run (0 10)
    if exist fs%a:\startup.nsh then
        fs%a:
        goto FOUND_IT
    endif
endfor

:FOUND_IT

if not exist BaseCryptLibUnitTestApp_JUNIT.XML then
    BaseCryptLibUnitTestApp.efi
endif
rm *_JUNIT_RESULT.XML
rm *_Cache.dat
if exist BaseCryptLibUnitTestApp_JUNIT.XML then
    mv BaseCryptLibUnitTestApp_JUNIT.XML BaseCryptLibUnitTestApp_JUNIT_RESULT.XML
endif
BaseCryptLibUnitTestApp.efi -d
reset -s
'''

DEFAULT_VERSION = "0.1.0"

VIRTUAL_DRIVE_PATH = Path("Build/Test/VirtualDrive.vhd")

#
# Setup and parse arguments.
#

parser = argparse.ArgumentParser()

# HINT: Run with '--help all' to get complete help.
parser.add_argument("-u", "--update", action="store_true",
                    help="Updates the firmware binaries.")
parser.add_argument("--firmwaredir", default="./firmware",
                    help="Directory to download and use firmware binaries.")
parser.add_argument("-a", "--arch", default="X64",
                    choices=["X64", "arm64"], help="The guest architecture for the VM.")
parser.add_argument("-c", "--cores", default=2, type=int,
                    help="The number of cores for the VM. This may be overridden based on the configuration.")
parser.add_argument("-m", "--memory", default="4096",
                    help="The memory size to use in Mb.")
parser.add_argument("--accel", default="tcg",
                    choices=["tcg", "kvm", "whpx"], help="Acceleration back-end to use in QEMU.")
parser.add_argument("--version", default=DEFAULT_VERSION,
                    help="The Project MU firmware version to use.")
parser.add_argument("--qemudir", default="",
                    help="Path to a custom QEMU install directory.")
parser.add_argument("--debugfw", action="store_true",
                    help="Enables update to use the DEBUG firmware binaries.")
parser.add_argument("--verbose", action="store_true",
                    help="Enabled verbose script prints.")
parser.add_argument("--force", action="store_true",
                    help="Disables automatic correction of VM configurations.")
parser.add_argument("--timeout", type=int, default=None,
                    help="The number of seconds to wait before killing the QEMU process.")

args = parser.parse_args()

#
# Script routines.
#


def main():
    # Run special operations if requested.
    if args.update:
        update_firmware()
        download_qemu()
        return
    
    # Make virtual drive with Crypto Test
    os.makedirs(VIRTUAL_DRIVE_PATH, exist_ok=True)
    shutil.copy("Build/CryptoBin_STANDARD/DEBUG_VS2022/X64/BaseCryptLibUnitTestApp.efi", VIRTUAL_DRIVE_PATH)
    nsh_path = VIRTUAL_DRIVE_PATH / "startup.nsh"
    create_startup_script(STARTUP_SCRIPT, nsh_path)


    # Build the platform specific arguments.
    qemu_args = []
    
    # Use X64 Qemu because all we care about is the shell test results
    build_args_x64(qemu_args)

    # General device config
    qemu_args += ["-name", f"MU-{args.arch}"]
    qemu_args += ["-m", f"{args.memory}"]
    qemu_args += ["-smp", f"{args.cores}"]

    # Add virtual drive with crypto test
    qemu_args += ["-drive", f"file=fat:rw:{VIRTUAL_DRIVE_PATH},format=raw,media=disk"]

    # Launch QEMU
    run_qemu(qemu_args)

    # Get test results
    result = report_results("Build/Test/Results")
    print("Crypto results: " + str(result))
    if not result:
        raise RuntimeError("Crypto Tests Failed!")


def build_args_x64(qemu_args: List[str]):
    smm_value = "off" if args.accel == "whpx" else "on"
    qemu_args += [f"{args.qemudir}qemu-system-x86_64"]
    qemu_args += ["-cpu", "qemu64,+rdrand,umip,+smep,+popcnt,+sse4.2,+sse4.1"]
    qemu_args += ["-global", "ICH9-LPC.disable_s3=1"]
    qemu_args += ["-machine", f"q35,smm={smm_value},accel={args.accel}"]
    qemu_args += ["-debugcon", "stdio"]  # file:uefi-x64.log
    qemu_args += ["-global", "isa-debugcon.iobase=0x402"]
    qemu_args += ["-vga", "cirrus"]

    # Flash storage
    if smm_value == "on":
        code_fd = f"{args.firmwaredir}/x64/QemuQ35/VisualStudio-x64/QEMUQ35_CODE.fd"
        data_fd = f"{args.firmwaredir}/x64/QemuQ35/VisualStudio-x64/QEMUQ35_VARS.fd"
        qemu_args += ["-global",
                      "driver=cfi.pflash01,property=secure,value=on"]
    else:
        print("Switching to no-SMM firmware for WHPX.")
        code_fd = f"{args.firmwaredir}/x64/QemuQ35.NoSmm/VisualStudio-NoSmm-x64/QEMUQ35_CODE.fd"
        data_fd = f"{args.firmwaredir}/x64/QemuQ35.NoSmm/VisualStudio-NoSmm-x64/QEMUQ35_VARS.fd"

    qemu_args += ["-drive",
                  f"if=pflash,format=raw,unit=0,file={code_fd},readonly=on"]
    qemu_args += ["-drive", f"if=pflash,format=raw,unit=1,file={data_fd}"]

    if args.cores > 4 and not args.force:
        print("Only 4 core currently supported for ARM64, setting cores to 4.")
        args.cores = 4

def run_qemu(qemu_args: List[str]):
    if args.verbose:
        print(qemu_args)
        subprocess.run([qemu_args[0], "--version"])
    try:
        subprocess.run(qemu_args, timeout=args.timeout)
    except subprocess.TimeoutExpired as e:
        print(f"QEMU Ran longer then {args.timeout} seconds.")
        return
    except Exception as e:
        raise e


def update_firmware():
    # Check if this is the newest version for awareness.
    latest_version = get_latest_version()
    if args.version == "latest":
        args.version = latest_version
    elif args.version != latest_version:
        print("#############################################################")
        print(f"NOTE: A newer version of firmware available! {latest_version}")
        print("#############################################################\n")

    #
    # Updates the firmware to the following configuration.
    #     <root>/<arch>/<platform>/<build_toolchain>/<files>
    #
    print(f"Updating firmware to version {args.version}...")

    if not os.path.exists(args.firmwaredir):
        os.makedirs(args.firmwaredir)

    #fw_info_list = [["QemuQ35", "x64", True],
    #                ["QemuQ35.NoSmm", "x64", False],
    #                ["QemuSbsa", "aarch64", True]]
    fw_info_list = [["QemuQ35", "x64", True]]

    # Avoids potentially missing SSL certs
    ssl.create_default_context(cafile=certifi.where())
    for fw_info in fw_info_list:
        build_type = "DEBUG" if args.debugfw and fw_info[2] else "RELEASE"
        url = f"https://github.com/microsoft/mu_tiano_platforms/releases/download/v{args.version}/Mu.{fw_info[0]}.FW.{build_type}-{args.version}.zip"
        zip_path = f"{args.firmwaredir}/{fw_info[0]}.zip"

        print(f"Downloading {fw_info[0]} from {url}")
        urllib.request.urlretrieve(url, zip_path)
        print(f"Unzipping {fw_info[0]}")
        unzip_path = f"{args.firmwaredir}/{fw_info[1]}/{fw_info[0]}/"
        shutil.rmtree(unzip_path, ignore_errors=True)
        with zipfile.ZipFile(zip_path, "r") as zip:
            zip.extractall(unzip_path)
        os.remove(zip_path)

    print("Done.")

def download_qemu():
    # Check if this is the newest version for awareness.
    latest_version = get_latest_version()
    if args.version == "latest":
        args.version = latest_version
    elif args.version != latest_version:
        print("#############################################################")
        print(f"NOTE: A newer version of QEMU available! {latest_version}")
        print("#############################################################\n")

    #
    # Updates the firmware to the following configuration.
    #     <root>/<arch>/<platform>/<build_toolchain>/<files>
    #
    print(f"Updating QEMU to version {args.version}...")

    if not os.path.exists(args.qemudir):
        os.makedirs(args.qemudir)

    # Avoids potentially missing SSL certs
    ssl.create_default_context(cafile=certifi.where())
    url = f"https://github.com/microsoft/mu_tiano_platforms/releases/download/v{args.version}/qemu-windows-v{args.version}.zip"
    zip_path = f"{args.qemudir}/qemu-windows-v{args.version}.zip"

    print(f"Downloading Qemu from {url}")
    urllib.request.urlretrieve(url, zip_path)
    print(f"Unzipping Qemu")
    unzip_path = f"{args.qemudir}/X64"
    shutil.rmtree(unzip_path, ignore_errors=True)
    with zipfile.ZipFile(zip_path, "r") as zip:
        zip.extractall(unzip_path)
    os.remove(zip_path)

    print("Done.")


def get_latest_version():
    response = requests.get(
        "https://api.github.com/repos/microsoft/mu_tiano_platforms/releases/latest")

    version = response.json()["name"]
    assert version[0] == 'v'
    return version[1:]

def create_startup_script(lines: list[str], file_path):
    split_lines = lines.split("\n")
    with open(file_path, "w") as nsh:
        for l in split_lines:
            nsh.write(l + "\n")
    return nsh

def report_results(result_output_dir: Path) -> list[(str, str)]:
    """Prints test results to the terminal and returns the number of failed tests."""
    os.makedirs(result_output_dir, exist_ok=True)
    test = "BaseCryptLibUnitTestApp"

    passed = True
    result_file = "BaseCryptLibUnitTestApp_JUNIT_RESULT.XML"
    #local_file_path = result_output_dir / result_file
    result_path = VIRTUAL_DRIVE_PATH / result_file
    shutil.copy(result_path, result_output_dir)
    if os.path.isfile(result_path):
                print('\n' + os.path.basename(test))
                root = xml.etree.ElementTree.parse(result_path).getroot()
                for suite in root:
                    print(" ")
                    for case in suite:
                        print('\t\t' + case.attrib['classname'] + " - ")
                        caseresult = "\t\t\tPASS"
                        for result in case:
                            if result.tag == 'failure':
                                passed = False
                                caseresult = "\t\tFAIL" + " - " + result.attrib['message']
                        print( caseresult)
    else:
        print("%s Test Failed - No Results File" % os.path.basename(test))
        passed = False
    return passed

try:
    main()
except KeyboardInterrupt as e:
    sys.stdout.write("\n")
    pass
