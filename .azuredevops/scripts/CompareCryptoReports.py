from pathlib import Path
import argparse

#
# Setup and parse arguments.
#
parser = argparse.ArgumentParser()
parser.add_argument("-s", "--source", dest="source", type=str, required=True) # Source report file
parser.add_argument("-t", "--target", dest="target", type=str, required=True) # Target report file
args = parser.parse_args()

#
# Initialize dictionaries to store data from the reports.
#

# basic report information
source_report_info = {"flavor": "", "branch_commit": "", "tool_chain": ""}
target_report_info = {"flavor": "", "Mode": "", "Build Time": "", "branch_commit": "", "tool_chain": ""}

# binaries sizes per architecture
source_binary_sizes_per_arch = {}
target_binary_sizes_per_arch = {}

# openssl linked lib for binary per arh
source_linked_openssllib_per_arch = {}
target_linked_openssllib_per_arch = {}

# openssl configuration flags
source_openssl_conf_report = {}
target_openssl_conf_report = {}

def parse_report(report_file, report_info, binary_sizes_per_arch, linked_openssllib_per_arch, openssl_conf_report):
    with report_file.open() as f:
        lines = f.readlines()

        record_sizes = False
        record_linked_openssllib = False

        for line in lines:

            # get basic report information
            if "FLAVOR" in line:
                flavor = line.split("-")[1].strip()
                report_info["flavor"] = flavor
                mode = line.split("-")[2].strip()
                report_info["Mode"] = mode
            elif "Build Time" in line:
                report_info["Build Time"] = line.split(":")[1].strip()
            elif "Branch" and "Commit" in line:
                report_info["branch_commit"] = line
            elif "Tool Chain" in line:
                report_info["tool_chain"] = line.split(":")[1].strip()

            elif "ARCH" in line:
                arch = line.split(":")[1].strip()
                binary_sizes_per_arch[arch] = {}
                linked_openssllib_per_arch[arch] = {}

            elif "Crypto binaries sizes report" in line:
                record_sizes = True
            elif  "Linked Openssl configuration" in line:
                record_sizes = False
                record_linked_openssllib = True
            
            # crypto binaries info
            elif ".efi" in line:
                binary_name = line.split("-")[0].strip()
                # sizes info
                if record_sizes:
                    sizes = line.split("-")[1].strip()
                    uncompressed_size = sizes.split("|")[0].split(":")[1].strip()
                    compressed_size = sizes.split("|")[1].split(":")[1].strip()

                    binary_sizes_per_arch[arch][binary_name] = {"Uncompressed size": uncompressed_size, "LZMA compressed size": compressed_size}
                    
                # linked openssl lib info
                if record_linked_openssllib:
                    openssllib = line.split("-")[1].split(":")[1].strip()
                    linked_openssllib_per_arch[arch][binary_name] = openssllib

            elif "File: OpensslLib" in line:
                current_openssl_lib_file = line.split(":")[1].strip()
                openssl_conf_report[current_openssl_lib_file] = {"OPENSSL_FLAGS": [], "OPENSSL_FLAGS_CONFIG": []}

            elif "DEFINE OPENSSL_FLAGS" in line:
                define_openssl_flags = line.split("=")[0].strip().split()[1].strip()
                flags_list = line.split("=")[1].strip().split()
                openssl_conf_report[current_openssl_lib_file][define_openssl_flags] = flags_list

def compare_reports():
    pass
    
if __name__ == '__main__':
    source_report_file = Path(args.source)
    target_report_file = Path(args.target)

    # read the source report file
    parse_report(source_report_file, source_report_info, source_binary_sizes_per_arch, source_linked_openssllib_per_arch, source_openssl_conf_report)

    # read the target report file
    parse_report(target_report_file, target_report_info, target_binary_sizes_per_arch, target_linked_openssllib_per_arch, target_openssl_conf_report)

    compare_reports()



