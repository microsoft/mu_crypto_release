from pathlib import Path
import os
import argparse
from datetime import datetime




def validate_list(list_arg: str, valid_list: list):
    valid_items = ",".join(valid_list)
    items = tuple(item.strip() for item in list_arg.split(","))
    for item in items:
        if item not in valid_list:
            raise ValueError("must be in set: {%s}" % valid_items)
    return items

def validate_targets(target_arg: str):
    return validate_list(target_arg, ["RELEASE", "DEBUG"])

def validate_flavors(flavor_arg: str):
    return validate_list(flavor_arg, ["STANDARD", "ALL", "TINY_SHA", "SMALL_SHA_RSA", "MINIMAL_SHA_SM3"])

def validate_archs(archs_arg: str):
    return validate_list(archs_arg, ["X64", "IA32", "AARCH64"])

def validate_toolchain(toolchain_arg: str):
    valid_items = ["VS2022", "GCC5"]
    if toolchain_arg not in valid_items:
            raise ValueError("must be in set: {%s}" % valid_items)
    return toolchain_arg

#
# Setup and parse arguments.
#
parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", dest="target", type=str, required=True, type=validate_targets) # RELEASE, DEBUG
parser.add_argument("-f", "--flavor", dest="flavor", type=str, required=True, type=validate_flavors) # STANDARD, ALL, TINY_SHA, etc.
parser.add_argument("-a", "--arch", dest="arch", type=str, required=True, type=validate_archs) # X64, IA32, AARCAA4
parser.add_argument("-b", "--branch", dest="branch", type=str, required=True,) # release/202311, dev, etc.
parser.add_argument("-c", "--toolchain", dest="toolchain", type=str, required=True, type=validate_toolchain) # VS2022, GCC5

args = parser.parse_args()

def main():
    for flavor in args.flavor:
        for target in args.target.split(" "):
            build_path = Path(__file__).parent / "Build" / f"CryptoBin_{flavor}" / f"{target}_{args.toolchain}"
            report_file_name = "Report_" + flavor + ".txt"
            report_File = build_path / report_file_name
            report_File.touch()
            title = f"CRYPTO BINARIES REPORT - {flavor} FLAVOR\n"
            time = datetime.now().strftime('%Y-%m-%d %H:%M:%S\n')
            report = [title, time]
            report.append("=============================================\n")
            report.append("<------Crypto binaries sizes report------>\n")

            for arch in args.arch.split(" "):
                arch_build_path = build_path / arch
                # write flavor and architecture name to report file
            report += ["Arch: " + arch + "\n", "--------------------------------\n"]
            # get built binaries
            files = list(arch_build_path.glob("*.efi")).sort()
            for file in files:
                # get file size
                file_size = file.stat().st_size
                # write file name and its' size to report file
                report.append(f"{file.name} - {file_size/1024} KB\n")




