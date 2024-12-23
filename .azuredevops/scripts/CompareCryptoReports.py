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
source_report_info = {"flavor": "", "build_target": "", "Build Time": "", "branch_commit": "", "tool_chain": ""}
target_report_info = {"flavor": "", "build_target": "", "Build Time": "", "branch_commit": "", "tool_chain": ""}

# binaries sizes per architecture
source_binary_sizes_per_arch = {}
target_binary_sizes_per_arch = {}

# openssl linked lib for binary per arh
source_linked_openssllib_per_arch = {}
target_linked_openssllib_per_arch = {}

# openssl configuration flags
source_openssl_conf_report = {}
target_openssl_conf_report = {}

size_change_threshold = 10 # in percentage %

def log_warning(msg):
    print(f"##[warning]{msg}\n")

def log_error(msg):
    print(f"##[error]{msg}\n")

def log_section(msg):
    print(f"##[section]{msg}\n")

def parse_report(report_file, report_info, binary_sizes_per_arch, linked_openssllib_per_arch, openssl_conf_report):
    with report_file.open() as f:
        lines = f.readlines()

        record_sizes = False
        record_linked_openssllib = False

        for line in lines:

            # get basic report information
            if "FLAVOR" in line:
                flavor = line.split("-")[1].strip().split()[0]
                report_info["flavor"] = flavor
                build_target = line.split("-")[2].strip()
                report_info["build_target"] = build_target
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

def compare_sizes(source_sizes, target_sizes):
     # compare binaries sizes per architecture
    for arch in source_sizes:
        log_section(f"Comparing binary sizes for Arch {arch}:")
        if arch not in target_sizes:
            log_warning(f"Architecture {arch} not found in target report!")
            continue
        for binary in source_sizes[arch]:
            if binary not in target_sizes[arch]:
                log_warning(f"A new binary has been added! - {binary} is not found in target report for architecture {arch}") # log warning - New Binary!
                continue
            source_binary_size = source_sizes[arch][binary]
            target_binary_size = target_sizes[arch][binary]

            # get compressed and uncompressed sizes
            source_binary_size_uncompressed = float(source_binary_size['Uncompressed size'].split()[0])
            source_binary_size_compressed = float(source_binary_size['LZMA compressed size'].split()[0])
            target_binary_size_uncompressed = float(target_binary_size['Uncompressed size'].split()[0])
            target_binary_size_compressed = float(target_binary_size['LZMA compressed size'].split()[0])

            # calculate size difference in percentage
            size_diff_uncompressed = round((source_binary_size_uncompressed / target_binary_size_uncompressed - 1) * 100, 2)
            size_diff_compressed = round((source_binary_size_compressed / target_binary_size_compressed - 1) * 100, 2)

            # check increase & decrease in uncompressed size
            if size_diff_uncompressed >= size_change_threshold: # check increase in size
                log_warning(f"Uncompressed size for {binary} in architecture {arch} has increased by {size_diff_uncompressed}%!") # log warning - Increase in size!
            if size_diff_uncompressed <= (-size_change_threshold): # check decrease in size
                log_warning(f"Uncompressed size for {binary} in architecture {arch} has decreased by {size_diff_uncompressed}%!") # log warning - Decrease in size!

            # check increase & decrease in compressed size
            if size_diff_compressed >= size_change_threshold:
                log_warning(
                    f"Compressed size for {binary} in architecture {arch} has increased by {size_diff_compressed}%!")  # log warning - Increase in size!
            if size_diff_compressed <= (-size_change_threshold):
                log_warning(
                    f"Compressed size for {binary} in architecture {arch} has decreased by {size_diff_compressed}%!")  # log warning - Decrease in size!
        
        # check if a binary is missing in source report
        for binary in target_sizes[arch]:
            if binary not in source_sizes[arch]:
                log_warning(f"A binary has been removed! - {binary} is not found in source report for architecture {arch}") # log warning - Missing Binary!

def comapre_linked_openssllib(source_linked_openssllib, target_linked_openssllib):
    for arch in source_linked_openssllib:
        log_section(f"Comparing linked OpensslLib for Arch: {arch}:")

        for binary in source_linked_openssllib[arch]:
            source_linked_openssllib_for_binary = source_linked_openssllib[arch][binary]
            target_linked_openssllib_for_binary = target_linked_openssllib[arch][binary]

            if source_linked_openssllib_for_binary != target_linked_openssllib_for_binary:
                log_warning(
                    f"Linked OpensslLib has been changed for {binary} in architecture {arch}! - New {source_linked_openssllib_for_binary}, Old {target_linked_openssllib_for_binary}")  # log warning - Change in linked OpensslLib*.inf!

def compare_openssl_flags(source_flags, target_flags):
    for file in source_flags:
        log_section(f"Comparing OpensslLib configuration flags for file {file}:")
        if file not in target_flags:
            log_warning(f"A new OpensslLib*.inf has been added! - {file} is not found in target report") # log warning - New OpensslLib*.inf file!
            continue
        
        # compare "OPENSSL_FLAGS" 
        source_flags_for_file = source_flags[file]["OPENSSL_FLAGS"]
        target_flags_for_file = target_flags[file]["OPENSSL_FLAGS"]

        for flag in source_flags_for_file:
            if flag not in target_flags_for_file:
                log_warning(f"A new flag has been added in {file}! - In OPENSSL_FLAGS section, flag {flag} is not found in target report") # log warning - New flag in OpensslLib*.inf file!

        for flag in target_flags_for_file:
            if flag not in source_flags_for_file:
                log_warning(f"A flag has been removed in {file}! - In OPENSSL_FLAGS section, flag {flag} is not found in source report") # log warning - Missing flag in OpensslLib*.inf file!

        # compare "OPENSSL_FLAGS_CONFIG"
        source_configflags_for_file = source_flags[file]["OPENSSL_FLAGS_CONFIG"]
        target_configflags_for_file = target_flags[file]["OPENSSL_FLAGS_CONFIG"]

        for flag in source_configflags_for_file:
            if flag not in target_configflags_for_file:
                log_warning(f"A new flag has been added in {file}! - In OPENSSL_FLAGS_CONFIG section, flag {flag} is not found in target report") # log warning - New flag in OpensslLib*.inf file!

        for flag in target_configflags_for_file:
            if flag not in source_configflags_for_file:
                log_warning(f"A flag has been removed in {file}! - In OPENSSL_FLAGS_CONFIG section, flag {flag} is not found in source report") # log warning - Missing flag in OpensslLib*.inf file!
    
    for file in target_flags:
        if file not in source_flags:
            log_warning(f"An OpensslLib*.inf has been removed! - {file} is not found in source report") # log warning - Missing OpensslLib*.inf file!

def compare_reports(source_reports, target_reports):
    # print and compare basic report information
    print("Source Branch Report Info:\n")
    #print(f"Branch and Commit: {source_reports['info']['branch_commit']}")
    print(f"Flavor: {source_reports['info']['flavor']}\n")
    print(f"Build Target: {source_reports['info']['build_target']}\n")
    print(f"Tool Chain: {source_reports['info']['tool_chain']}\n")
    print(f"Build Time: {source_reports['info']['Build Time']}\n\n")

    print("Target Branch Report Info:\n")
    #print(f"Branch and Commit: {target_reports['info']['branch_commit']}")
    print(f"Flavor: {target_reports['info']['flavor']}\n")
    print(f"Build Target: {target_reports['info']['build_target']}\n")
    print(f"Tool Chain: {target_reports['info']['tool_chain']}\n")
    print(f"Build Time: {target_reports['info']['Build Time']}\n\n")

    if(source_reports['info']['flavor'] != target_reports['info']['flavor']):
        log_warning("Reports are for different flavors!")
    
    if(source_reports['info']['build_target'] != target_reports['info']['build_target']):
        log_warning("Reports are for different build targets!")
    

    # compare binary sizes per architecture
    compare_sizes(source_reports['sizes_per_arch'], target_reports['sizes_per_arch'])

    # compare linked openssl lib for binary per architecture
    # already reported new/missing binaries in the sizes comparison, so no need to report them again here
    comapre_linked_openssllib(source_reports['linked_openssllib_per_arch'], target_reports['linked_openssllib_per_arch'])

    # compare openssl configuration flags
    compare_openssl_flags(source_reports['openssl_libs_flags'], target_reports['openssl_libs_flags'])

    log_section("Comparison completed successfully!")


if __name__ == '__main__':
    source_report_file = Path(args.source)
    target_report_file = Path(args.target)

    # read the source report file
    log_section(f"Parsing source report file: {source_report_file}")
    parse_report(source_report_file, source_report_info, source_binary_sizes_per_arch, source_linked_openssllib_per_arch, source_openssl_conf_report)

    # read the target report file
    log_section(f"Parsing target report file: {target_report_file}")
    parse_report(target_report_file, target_report_info, target_binary_sizes_per_arch, target_linked_openssllib_per_arch, target_openssl_conf_report)

    # wrap the parsed information in single dict
    source_reports = {"info": source_report_info, "sizes_per_arch": source_binary_sizes_per_arch, "linked_openssllib_per_arch": source_linked_openssllib_per_arch, "openssl_libs_flags": source_openssl_conf_report}
    target_reports = {"info": target_report_info, "sizes_per_arch": target_binary_sizes_per_arch, "linked_openssllib_per_arch": target_linked_openssllib_per_arch, "openssl_libs_flags": target_openssl_conf_report}

    # compare the reports
    log_section("Comparing reports")
    compare_reports(source_reports, target_reports)