
import argparse
import re
import io
import json
import os
import datetime
import logging

from collections import OrderedDict
from dataclasses import dataclass

logger = logging.getLogger(os.path.basename(__file__))
DEBUG = False

level = 'INFO'
if DEBUG:
    level = 'DEBUG'
    basic_config_level = logging.DEBUG

try:
    import coloredlogs
    # To enable debugging set level to 'DEBUG'
    coloredlogs.install(level=level, logger=logger, fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
except ImportError:
    logging.basicConfig(level=basic_config_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INCLUDE_PATH = os.path.join(SCRIPT_DIR, "../Include")
LIBRARY_PATH = os.path.join(SCRIPT_DIR, "../Library/Include")

# Paths to the library and include directories
LIBRARY_INCLUDE_PATH = os.path.join(LIBRARY_PATH, "Include")
BASE_CRYPTO_PATH = os.path.join(LIBRARY_PATH, "BaseCryptLibOnProtocol")

# Default group for functions that don't have a group specified
# TODO Ideally this would have a different name like "Shared"
DEFAULT_GROUP = "BaseCrypt"
LIBRARY_GROUPS = [
    "Tls",
    "Hash",
]  # Any function that doesn't fit into the groups above will be added to one large group


@dataclass
class FunctionDetails:
    full_text: str
    typedef_name: str
    comment: str
    return_type: str
    calling_convention: str
    params: str
    version: str
    group: str


@dataclass
class FunctionInfo:
    functions: dict
    typedefs: dict
    version: tuple


def cli() -> dict:
    argparse.ArgumentParser(description="Transforms a header file into a protocol that can be used in UEFI")
    parser = argparse.ArgumentParser()

    parser.add_argument("header_file", help="The header file to be transformed")

    parser.add_argument("-p", "--generate-protocol", help="Generate the protocol file",
                        action="store_true", default=False)
    parser.add_argument(
        "--output-protocol", help="The output file to write the transformed protocol header file to", default=os.path.join(INCLUDE_PATH, "SharedCryptoProtocol.h"))
    parser.add_argument("-l", "--generate-library", help="Generate the library file",
                        action="store_true", default=False)

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


def extract_function_details(file_content):
    """
    Extracts details of functions from the given file content.
    This function parses the provided file content to identify and extract details of functions,
    including their comments, return types, calling conventions, parameters, version, and group.
    It uses regular expressions to match the start and end of function definitions, as well as
    to extract specific details from the comment blocks.
    Args:
        file_content (list of str): The content of the file as a list of strings, where each string
                                    represents a line in the file.
    Returns:
        OrderedDict: An ordered dictionary where the keys are function names and the values are
                     instances of FunctionDetails containing the extracted details of each function.
    Raises:
        ValueError: If a required component (comment, function name, group, or version) is not found
                    in the function definition.
    """

    # Regex patterns to match the start and end of a function
    # The start pattern is the beginning of a comment block
    # Example: /**
    begin_pattern = re.compile(
        r"\/\*\*",
        re.DOTALL
    )

    # The end pattern is the end of a function definition
    # Example: );
    end_pattern = re.compile(
        r".*?\);",
        re.DOTALL
    )

    # The comment pattern is the comment block that contains the function details
    # Example: /** {comment} **/
    comment_pattern = re.compile(
        r"\/\*\*[\s\S]*?\*\/",
        re.DOTALL
    )

    # The group pattern is the @ingroup tag that contains the group name
    # Example: @ingroup GroupName
    group_pattern = re.compile(
        r'\@ingroup\s(.+)\n',
        re.DOTALL
    )

    # The version pattern is the @since tag that contains the version number
    # Example: @since 1.0.0
    version_pattern = re.compile(
        r'\@since\s((\d+).(\d+).(\d+))',
        re.DOTALL
    )

    functions = OrderedDict()
    in_function = False
    function_text = []

    # Simple state machine for parsing the functions out of the file
    for lineno, line in enumerate(file_content):
        if re.search(begin_pattern, line):
            # if we see a function start, we should reset the in_function flag
            logger.debug(f"StateMachine: Start @ {lineno}")
            if in_function:
                logger.debug(f"StateMachine: Restart @ {lineno}")

            in_function = True
            function_text = [line]
        elif re.search(end_pattern, line) and in_function:

            logger.debug(f"StateMachine: End @ {lineno}")
            function_text.append(line)

            parsable_text = ''.join(function_text)

            comment_match = re.search(comment_pattern, parsable_text)
            if not comment_match:
                logger.warning(f"Comment not found for function. Line Number: {lineno}")
                raise ValueError(f"Comment not found for function. Line Number: {lineno}")
            comment = comment_match.group(0)
            # Remove comment from parsable_text - this will make it easier to
            # parse the rest of the text
            parsable_text = re.sub(comment_pattern, '', parsable_text)

            function_info = parsable_text.strip().split('\n')
            return_type = function_info[0]
            calling_convention = function_info[1]
            if calling_convention != 'EFIAPI':
                logger.error(f"Calling convention wasn't EFIAPI! Line Number: {lineno}")
                raise ValueError(f"Calling convention wasn't EFIAPI! Line Number: {lineno}")

            function_name, opening_bracket = function_info[2].split(' ')
            if opening_bracket != '(':
                logger.error(f"Function name not found. Line Number: {lineno}")
                raise ValueError(f"Function name not found. Line Number: {lineno}")
            # once we find the start of params - this will run until we see );
            params = function_info[3:-1]

            group_match = re.search(group_pattern, comment)
            if not group_match:
                logger.error(f"Group not found for function. {function_name}")
                raise ValueError(f"Group not found for function. {function_name}")
            group = group_match.group(1)

            version_match = re.search(version_pattern, comment)
            if not version_match:
                logger.error(f"Version not found for function. {function_name}")
                raise ValueError("Version not found for function.")
            version = version_match.group(1)

            functions[function_name] = FunctionDetails(
                full_text=''.join(function_text),
                typedef_name='',
                comment=comment,
                return_type=return_type,
                calling_convention=calling_convention,
                params='\n'.join(params),
                version=version,
                group=group
            )
            in_function = False
        elif '#define' in line.lower() and in_function:
            # Defines are not functions and should reset the in_function flag

            logger.debug(f"StateMachine: Reset @ {lineno}")

            in_function = False
            function_text = []
        elif in_function:
            function_text.append(line)

    logger.info(f"Found {len(functions)} unique functions")

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
        typedef_name = convert_to_underscores(function)
        comment = functions[function].comment
        return_type = functions[function].return_type
        calling_convention = functions[function].calling_convention
        params = functions[function].params
        typedef = f"{comment}\ntypedef {return_type} ({calling_convention} *SHARED_{typedef_name})(\n{params}\n  );\n\n"
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

    logger.info("Generating the protocol structure")

    #
    # reorganize the functions based on group and version
    # Group functions by version
    #
    grouped_functions = OrderedDict()
    for function in functions:
        version = functions[function].version
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

            typedef_name = convert_to_underscores(function)

            group = functions[function].group

            if previous_group != group:
                previous_group = group
                structure += create_divider(divider="-", length=80, begin=f"{indent}/// v{version} {group} ")
            #
            # Add the function to the protocol structure
            #
            structure += f"{indent}SHARED_{typedef_name} {function};\n"

    structure += "} SHARED_CRYPTO_PROTOCOL;\n\n"

    return structure


def generate_autogenerated_file_comment() -> str:
    lines = "// {0}\n".format("-" * 78)
    lines += f"// AUTOGENERATED BY {os.path.basename(__file__)}\n"
    lines += "// GENERATED ON: {:%Y-%b-%d %H:%M:%S}\n".format(datetime.datetime.now())
    lines += "// DO NOT MODIFY\n"
    lines += "// {0}\n".format("-" * 78)
    return lines


def generate_protocol(file_name: str, function_info: FunctionInfo, output_file: str):
    """
    Generates a protocol file based on the provided function information and writes it to the specified output file.
    Args:
        file_name (str): The name of the file to include in the protocol file.
        function_info (FunctionInfo): An object containing information about the functions, typedefs, and version.
        output_file (str): The path to the output file where the protocol will be written.
    Returns:
        None
    """

    logger.info("Generating the Protocol file")

    # The C structure built from the typedefs
    protocol_structure = create_protocol_structure(function_info.functions)

    # The C guard statement
    guard_statement = f"{convert_to_underscores(os.path.basename(output_file).split('.')[0])}_"
    major, minor, revision = function_info.version
    typedefs = function_info.typedefs

    with open(output_file, 'w') as f:
        f.write(generate_autogenerated_file_comment())
        f.write(f"#ifndef {guard_statement}\n")
        f.write(f"#define {guard_statement}\n\n")
        f.write("#include <Uefi.h>\n")
        f.write(f"#include <{file_name}>\n\n")
        f.write(create_divider())
        f.write(f"// Protocol version: {major}.{minor}.{revision}\n")
        f.write(create_divider())
        f.write("\n")
        f.write(create_divider())
        f.write("// Typedef Declarations\n")
        f.write(create_divider())
        f.write(typedefs)
        f.write(create_divider())
        f.write("// Protocol\n")
        f.write(create_divider())
        f.write(protocol_structure)

        f.write(f"#endif // {guard_statement}\n")

    logger.info(f"Protocol written to {output_file}")


def generate_library(file_name: str, function_info: FunctionInfo):

    logger.info("Generating the library headers")

    grouped_functions = {group: [] for group in LIBRARY_GROUPS}
    grouped_functions[DEFAULT_GROUP] = []

    for function, details in function_info.functions.items():
        group_found = False
        for group in LIBRARY_GROUPS:
            if group.lower() in details.group.lower():
                grouped_functions[group].append(function)
                group_found = True
                break
        if not group_found:
            grouped_functions[DEFAULT_GROUP].append(function)

    #
    # Generate the library files
    #
    for group in grouped_functions:
        basename = f"{group}ApiLib.h"

        if not os.path.exists(LIBRARY_INCLUDE_PATH):
            os.makedirs(LIBRARY_INCLUDE_PATH)

        library_file = os.path.join(LIBRARY_INCLUDE_PATH, basename)

        guard_statement = f"{convert_to_underscores(os.path.basename(basename).split('.')[0])}_"
        with open(library_file, 'w') as f:
            f.write("//")
            f.write(generate_autogenerated_file_comment())
            f.write(f"#ifndef {guard_statement}\n")
            f.write(f"#define {guard_statement}\n\n")
            f.write("#include <Uefi.h>\n")
            f.write(create_divider())
            f.write(f"// Library for {group}\n")
            f.write(create_divider())
            f.write("\n")

            for function_name in grouped_functions[group]:
                function = function_info.functions[function_name]
                f.write(f"{function.comment}\n")
                f.write(f"{function.return_type}\n")
                f.write(f"{function.calling_convention}\n")
                f.write(f"{function_name} (")
                f.write(f"{function.params});\n\n")

            f.write(f"#endif // {guard_statement}\n")

        logger.info(f"Library file written to {library_file}")

    #
    # Generate the BaseCrypt library file
    #

def process_header_file(header_file: str, output_file: str) -> dict:
    """
    Processes the header file and writes the protocol to the output file.
    """

    with open(header_file, 'r') as file:

        file_name = os.path.basename(header_file)

        functions = extract_function_details(file)
        function_info = FunctionInfo(functions, create_typedefs(functions), extract_version(file))
        generate_protocol(file_name, function_info, output_file)
        generate_library(file_name, function_info)


if __name__ == "__main__":
    args = cli()

    if args.debug:
        DEBUG = True
    process_header_file(args.header_file, args.output_protocol)
