# @file AssembleNugetPackage.py
# Script to rearrange a standard build output directory
# into the correct format for Nuget publication.
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import glob
import argparse
import shutil
import logging
import sys

sys.path.append(os.path.dirname(__file__))
from CommonBuildSettngs import CommonPlatform

SCRIPT_PATH = os.path.abspath(__file__)
SCRIPT_DIR = os.path.dirname(SCRIPT_PATH)


def parse_args():
    arg_parse = argparse.ArgumentParser(f"{CommonPlatform.BaseName} AssembleNugetPackage.py",
                                        description="assembles the final directory structure format for "
                                        + f"the {CommonPlatform.BaseName} Nuget feed")

    def validate_abs_path(path_arg: str):
        if not os.path.exists(path_arg):
            raise ValueError(f"path '{path_arg}' is not valid")
        return os.path.abspath(path_arg)

    arg_parse.add_argument(dest="input_dir", type=validate_abs_path,
                           help="the directory containing the build files to assemble")
    default_output = os.path.join(SCRIPT_DIR, "NugetPackage")
    arg_parse.add_argument("-o", "--output-dir", dest="output_dir",
                           default=default_output,
                           help=f"destination path to assemble the package. [default: '{default_output}']")
    arg_parse.add_argument("-e", "--extra", dest="extra_paths", action="append",
                           type=validate_abs_path, default=[],
                           help="extra files/dirs to include in the root of the package")
    arg_parse.add_argument("-f", "--force", dest="force",
                           default=False, action="store_true",
                           help="if set, will delete the output directory, if present")
    arg_parse.add_argument("-l", "--logs", dest="copy_logs",
                           default=False, action="store_true",
                           help="if set, will also copy all of the generated log files into the package")
    arg_parse.add_argument("-v", "--verbose", dest="verbose",
                           default=False, action="store_true",
                           help="if set, enables verbose logging")

    # TODO: Maybe support filtering SOME archs/flavors/targets/etc?

    args = arg_parse.parse_args()
    return (args, arg_parse)


def main():
    (args, arg_parse) = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
    logging.debug(arg_parse.format_usage())
    logging.info(f"Assembling package at: {args.output_dir}...")

    # Create the output directory.
    if os.path.exists(args.output_dir):
        if args.force:
            logging.info("Removing existing directory...")
            shutil.rmtree(args.output_dir)
        else:
            raise ValueError(f"output path '{args.output_dir}' already exists")
    os.makedirs(args.output_dir, exist_ok=True)

    # [Optional] Copy base logs
    if args.copy_logs:
        args.extra_paths += [
            os.path.join(args.input_dir, "SETUPLOG.txt"),
            os.path.join(args.input_dir, "UPDATE_LOG.txt"),
        ]

    # Copy all the files as they are found in the build directory.
    for flavor in CommonPlatform.AvailableFlavors:
        flavor_dir_name = f"{CommonPlatform.BaseName}_{flavor}"
        flavor_input_dir = os.path.join(args.input_dir, flavor_dir_name)
        logging.debug(f"FLAVOR PATH: '{flavor_input_dir}'")

        for target in CommonPlatform.TargetsSupported:
            target_dest_path = os.path.join(args.output_dir, flavor, target)
            if not os.path.exists(target_dest_path):
                os.makedirs(target_dest_path)

            # Copy all Depexes
            # These are not unique per arch, so just copy the first one of each module
            # we encounter.
            search_path = os.path.join(flavor_input_dir, f"{target}*", "**")
            logging.debug(f"TARGET SEARCH PATH: '{search_path}'")
            for path in glob.iglob(os.path.join(search_path, "Crypto*.depex"), recursive=True):
                output_path = os.path.join(target_dest_path, os.path.basename(path))
                if not os.path.exists(output_path):
                    logging.debug(f"{path} -> {output_path}")
                    shutil.copy(path, output_path)

            # Copy all driver binaries
            for arch in CommonPlatform.ArchSupported:
                arch_dest_path = os.path.join(target_dest_path, arch)
                search_path = os.path.join(flavor_dir_name, f"{target}*", arch)
                logging.debug(f"ARCH SEARCH PATH: '{search_path}'")
                for path in glob.iglob(os.path.join(args.input_dir, search_path, "Crypto*.efi")):
                    if not os.path.exists(arch_dest_path):
                        os.makedirs(arch_dest_path)
                    logging.debug(f"{path} -> {arch_dest_path}")
                    shutil.copy(path, arch_dest_path)

            # [Optional] Copy logs
            if args.copy_logs:
                log_file = os.path.join(args.input_dir,
                                        f"BUILDLOG_{CommonPlatform.BaseName}_{flavor}_{target}.txt")
                if os.path.isfile(log_file):
                    logging.debug(f"{log_file} -> {target_dest_path}")
                    shutil.copy(log_file, target_dest_path)

                search_path = os.path.join(flavor_input_dir, f"{target}*")
                for path in glob.iglob(os.path.join(search_path, "BUILD_REPORT.TXT"), recursive=True):
                    output_path = os.path.join(target_dest_path, os.path.basename(path))
                    if not os.path.exists(output_path):
                        logging.debug(f"{path} -> {output_path}")
                        shutil.copy(path, output_path)

    # Finally, copy any extra paths to the output.
    for extra_path in args.extra_paths:
        if os.path.isfile(extra_path):
            logging.debug(f"{extra_path} -> {args.output_dir}")
            shutil.copy(extra_path, args.output_dir)
        else:
            logging.warning(f"Extra path could not be found: {extra_path}")


if __name__ == "__main__":
    main()
