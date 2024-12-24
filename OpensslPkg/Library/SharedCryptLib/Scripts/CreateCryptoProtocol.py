
import argparse
import re
import io
import json
import os
import datetime

from collections import OrderedDict

DEBUG = False


def cli() -> dict:
    argparse.ArgumentParser(description="Transforms a header file into a protocol that can be used in UEFI")
    parser = argparse.ArgumentParser()

    parser.add_argument("header_file", help="The header file to be transformed")
    parser.add_argument(
        "-o", "--output", help="The output file to write the transformed protocol header file to", default="SharedCryptoProtocol.h")
    parser.add_argument("-d", "--debug", help="Enable debug mode", action="store_true", default=False)

    args = parser.parse_args()
    return args


def convert_to_underscores(name: str) -> str:
    """
    Converts a camel case string to an uppercase string with underscores.

    This function takes a string in camel case format and converts it to a
    string where words are separated by underscores and all characters are
    in uppercase.

    Args:
        name (str): The camel case string to be converted.

    Returns:
        str: The converted string in uppercase with underscores.
    """
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).upper()


def create_divider(indent=" " * 0, divider="=", length=80, begin=None) -> str:
    """
    Creates a divider string with a specified length, indentation, and divider character.

    Args:
        indent (str): The string to use for indentation. Default is an empty string.
        divider (str): The character to use for the divider. Default is '='.
        length (int): The total length of the divider string. Default is 80.
        begin (str, optional): The beginning string to prepend to the divider. If None, defaults to the indent followed by "// ".

    Returns:
        str: The formatted divider string.

    Raises:
        ValueError: If the specified length is less than the length of the begin string.
    """
    if begin is None:
        begin = f"{indent}// "
    if length < len(begin):
        raise ValueError(f"Length must be at least the length of the begin string {len(begin)}")
    return begin + divider * (length - len(begin)) + "\n"


def extract_version(file: io.TextIOWrapper) -> tuple:
    """
    Extracts the version information from a file.
    The function reads the content of the provided file and searches for version
    definitions in the format:

    #define VERSION_MAJOR     <major>ULL
    #define VERSION_MINOR     <minor>ULL
    #define VERSION_REVISION  <revision>ULL
    Args:
        file (io.TextIOWrapper): The file object to read from.
    Returns:
        tuple: A tuple containing the major, minor, and revision version numbers as integers.
    Raises:
        ValueError: If the version information cannot be parsed from the file.
    """

    file.seek(0)
    content = file.read()
    version_pattern = re.compile(
        r"#define VERSION_MAJOR\s+(\d+ULL)\s+#define VERSION_MINOR\s+(\d+ULL)\s+#define VERSION_REVISION\s+(\d+ULL)")
    match = version_pattern.search(content)
    if not match:
        raise ValueError("Failed to parse version")
    major = match.group(1)
    minor = match.group(2)
    revision = match.group(3)

    # convert to int (remove ULL)
    major = int(major[:-3])
    minor = int(minor[:-3])
    revision = int(revision[:-3])

    return major, minor, revision


def get_functions(f: io.TextIOWrapper) -> dict:
    """
    Extracts the functions from the header file.

    Args:
        f (io.TextIOWrapper): The file object.

    Returns:
        dict: A dictionary of functions where the key is the function name and the value is a dictionary containing the function details.

    Return Value has been the biggest challenge - any change to the regex must be tested against examples like this:

        /**
        Checks if Big Number is odd.

        @param[in]   Bn     Big number.

        @retval TRUE   Bn is odd (Bn % 2 == 1).
        @retval FALSE  otherwise.
        **/
        BOOLEAN
        EFIAPI
        BigNumIsOdd (
            IN CONST VOID  *Bn
        );

        /**
        Copy Big number.

        @param[out]  BnDst     Destination.
        @param[in]   BnSrc     Source.

        @retval BnDst on success.
        @retval NULL otherwise.
        **/
        VOID *
        EFIAPI
        BigNumCopy (
            OUT VOID       *BnDst,
            IN CONST VOID  *BnSrc
        );

        /**
        Get constant Big number with value of "1".
        This may be used to save expensive allocations.

        @retval Big Number with value of 1.
        **/
        CONST VOID *
        EFIAPI
        BigNumValueOne (
            VOID
        );
    """
    f.seek(0)
    content = f.read()

    #
    # Dictionary to store the functions in the file - keep the order of the functions
    #
    functions = OrderedDict()

    #
    # Regex to find function declarations
    #
    function_pattern = re.compile(
        r'\n(?P<comment>\/\*\*[\s\S]*?\*\/)\n(?P<return_type>[\w\s\*]+)\n(?P<calling_convention>EFIAPI)\s(?P<function_name>\w+)\s*\((?P<params>[\s\S]*?)\);',
        re.DOTALL
    )

    version_pattern = re.compile(
        r'\@since\s(?P<version>((\d+).(\d+).(\d+)))',
        re.DOTALL
    )

    group_pattern = re.compile(
        r'\@ingroup\s(?P<group_name>(.+))\n',
        re.DOTALL
    )

    function_name_pattern = re.compile(
        r'EFIAPI\n(?P<function>\w+)\s\(',
        re.DOTALL
    )

    matches = function_pattern.findall(content)
    for match in matches:
        comment = match[0]
        return_type = match[1]
        calling_convention = match[2]
        function_name = match[3]
        params = match[4]

        # if any of these fail raise an error
        if not comment or not return_type or not calling_convention or not function_name or not params:
            #
            # Early warning system to catch any issues with the regex - this may not be the most robust way to do this
            #
            raise ValueError(f"Failed to parse function {function_name}")

        version_match = version_pattern.search(comment)
        if not version_match:
            raise ValueError(f"Version not found in the comment for function {function_name}")

        group_match = group_pattern.search(comment)
        if not group_match:
            raise ValueError(f"Group not found in the comment for function {function_name}")

        typedef_name = convert_to_underscores(function_name)
        functions.update({
            function_name: {
                'typedef_name': typedef_name,
                'comment': comment.strip(),
                'return_type': return_type.strip(),
                'calling_convention': calling_convention.strip(),
                'params': params,
                'version': version_match['version'],
                'group': group_match['group_name']
            }
        })

    #
    # Write the functions to a file for debugging
    #
    if DEBUG:
        with open('functions.json', 'w') as f:
            print("Writing functions to functions.json")
            f.write(json.dumps(functions, indent=4))

    #
    # Count the number of "EFIAPI" in the file and compare it to the number of functions found
    # Early warning system to catch any issues with the regex - this may not be the most robust way to do this
    #
    matches = function_name_pattern.findall(content)
    if len(matches) != len(functions):
        for function in functions:
            if function not in matches:
                print(f"Missing!: {function}")

        for match in matches:
            if match not in functions:
                print(f"Missing!: {match}")

        raise ValueError(f"EFIAPI count does not match the number of functions found {
                         len(matches)} != {len(functions)}")

    return functions


def create_typedefs(functions: dict) -> str:
    """
    Creates the typedefs for the functions.

    Args:
        functions (dict): A dictionary of functions where the key is the function name and the value is a dictionary containing the function details.

    Returns:
        str: A string containing the typedefs for the functions
    """
    typedefs = []
    for function in functions:
        comment = functions[function]['comment']
        typedef_name = functions[function]['typedef_name']
        return_type = functions[function]['return_type']
        calling_convention = functions[function]['calling_convention']
        params = functions[function]['params']
        typedef = f"{comment}\ntypedef {return_type} ({calling_convention} *SHARED_{typedef_name})({params});\n\n"
        typedefs.append(typedef)
    return "".join(typedefs)


def create_protocol_structure(functions: dict, indent=" " * 2) -> str:
    """
    Creates the protocol structure.

    Args:
        functions (dict): A dictionary of functions where the key is the function name and the value is a dictionary containing the function details.
        indent (str): The indentation to use.

    Returns:
        str: A string containing the protocol structure.
    """

    version = None
    group = None
    previous_group = None

    #
    # reorganize the functions based on group and version
    # Group functions by version
    #
    grouped_functions = OrderedDict()
    for function in functions:
        version = functions[function]['version']
        if version not in grouped_functions:
            grouped_functions[version] = []
        grouped_functions[version].append(function)

    sorted_versions = sorted(grouped_functions.keys(), key=lambda v: tuple(map(int, v.split('.'))))

    structure = ""
    structure += "\n/**\n"
    structure += f"{indent}@struct _SHARED_CRYPTO_PROTOCOL\n"
    structure += f"{indent}@brief This structure defines the protocol for shared cryptographic operations.\n\n"
    structure += f"{indent}The _SHARED_CRYPTO_PROTOCOL structure provides a standardized interface for\n"
    structure += f"{indent}cryptographic functions, enabling interoperability and consistent usage across\n"
    structure += f"{indent}different cryptographic implementations.\n\n"
    structure += f"{indent}Supports functions from versions:\n"
    for version in sorted_versions:
        structure += f"{indent} - {version}\n"
    structure += "\n"
    structure += f"{indent}@since 1.0.0\n"
    structure += f"{indent}@ingroup SharedCryptoProtocol\n"
    structure += "**/\n"

    #
    # Begin the structure
    #
    structure += "typedef struct _SHARED_CRYPTO_PROTOCOL\n{\n"

    #
    # Add the versioning information to the protocol structure
    #
    structure += create_divider(indent=indent, divider="-", length=80)
    structure += f"{indent}// Versioning\n"
    structure += f"{indent}// Major.Minor.Revision\n"
    structure += f"{indent}// Major - Breaking change to this structure\n"
    structure += f"{indent}// Minor - Functions added to the end of this structure\n"
    structure += f"{indent}// Revision - Some non breaking change\n"
    structure += f"{indent}//\n"
    structure += create_divider(indent=indent, divider="-", length=80)

    for version in sorted_versions:
        group = None
        previous_group = None
        for function in grouped_functions[version]:
            typedef_name = functions[function]['typedef_name']
            group = functions[function]["group"]

            if previous_group != group:
                previous_group = group
                structure += create_divider(divider="-", length=80, begin=f"{indent}/// v{version} {group} ")
            #
            # Add the function to the protocol structure
            #
            structure += f"{indent}SHARED_{typedef_name} {function};\n"

    structure += "} SHARED_CRYPTO_PROTOCOL;\n\n"

    return structure


def process_header_file(header_file: str, output_file: str) -> dict:
    """
    Processes the header file and writes the protocol to the output file.
    """
    with open(header_file, 'r') as file:

        major, minor, revision = extract_version(file)
        functions = get_functions(file)
        typedefs = create_typedefs(functions)
        protocol_structure = create_protocol_structure(functions)

        guard_statement = f"{convert_to_underscores(os.path.basename(output_file).split('.')[0])}_"

        with open(output_file, 'w') as f:
            f.write("//")
            f.write("// This file was generated by CreateProtocol.py\n")
            f.write("// Timestamp: {:%Y-%b-%d %H:%M:%S}\n".format(datetime.datetime.now()))
            f.write(f"#ifndef {guard_statement}\n")
            f.write(f"#define {guard_statement}\n\n")
            f.write("#include <Uefi.h>\n\n")
            f.write("#include <SharedCryptoDefs.h> // TODO should this be Protocol or Library?\n\n")
            f.write(create_divider())
            f.write(f"// Protocol version: {major}.{minor}.{revision}\n")
            f.write(create_divider())
            # f.write(version_region)
            # f.write(create_divider())
            f.write("\n")
            # TODO
            # f.write(rsa_key_tag_region)
            f.write(create_divider())
            f.write("// Typedef Declarations\n")
            f.write(create_divider())
            f.write(typedefs)

            f.write(create_divider())
            f.write("// Protocol\n")
            f.write(create_divider())
            f.write(protocol_structure)

            f.write(f"#endif // {guard_statement}\n")

        print(f"Protocol written to {output_file}")


if __name__ == "__main__":
    args = cli()

    if args.debug:
        DEBUG = True
    process_header_file(args.header_file, args.output)
