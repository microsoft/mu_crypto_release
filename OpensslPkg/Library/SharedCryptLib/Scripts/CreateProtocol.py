
import argparse
import re
import io
import json

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
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).upper()


def create_divider(indent=" " * 0, divider="=", length=80) -> str:
    begin = f"{indent}// "
    if length < len(begin):
        raise ValueError(f"Length must be at least the length of the begin string {len(begin)}")
    return begin + divider * (length - len(begin)) + "\n"

def extract_version(version: str):
    """
    #define VERSION_MAJOR     1ULL
    #define VERSION_MINOR     0ULL
    #define VERSION_REVISION  0ULL
    """
    version_pattern = re.compile(r"#define VERSION_MAJOR\s+(\d+ULL)\s+#define VERSION_MINOR\s+(\d+ULL)\s+#define VERSION_REVISION\s+(\d+ULL)")
    match = version_pattern.match(version)
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

def extract_copy_region(f: io.TextIOWrapper, section: str) -> list:
    """
    Extracts region of the file content that start with "// COPY_REGION_BEGIN [[section]]"
    and end with "// COPY_REGION_END [[section]]".

    Args:
        file_content (str): The content of the file as a string.

    Returns:
        list: A list of extracted regions as strings.
    """
    start_marker = f"// COPY_REGION_BEGIN [[{section}]]"
    end_marker = f"// COPY_REGION_END [[{section}]]"

    regions = []
    start_index = 0

    f.seek(0)
    content = f.read()
    start_index = content.find(start_marker)
    if start_index == -1:
        raise ValueError(f"Start marker '{start_marker}' not found in the file.")
    end_index = content.find(end_marker, start_index)
    if end_index == -1:
        raise ValueError(f"End marker '{end_marker}' not found in the file.")
    region_start = start_index + len(start_marker)
    region_end = end_index
    regions.append(content[region_start:region_end].strip())

    # combine all regions into one string
    regions = "".join(regions) + "\n"

    return regions


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
        r'(?P<comment>\/\*\*[\s\S]*?\*\/)\n(?P<return_type>[\w\s\*]+)\n(?P<calling_convention>EFIAPI)\s(?P<function_name>\w+)\s*\((?P<params>[\s\S]*?)\);',
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

        typedef_name = convert_to_underscores(function_name)
        functions.update({
            function_name: {
                'typedef_name': typedef_name,
                'comment': comment.strip(),
                'return_type': return_type.strip(),
                'calling_convention': calling_convention.strip(),
                'params': params
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
    efiapi_count = content.count("EFIAPI")
    if efiapi_count != len(functions):
        raise ValueError(f"EFIAPI count does not match the number of functions found {efiapi_count} != {len(functions)}")

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

    structure = "typedef struct _SHARED_CRYPTO_PROTOCOL\n{\n"

    structure += create_divider(indent=indent, divider="-", length=80)
    structure += f"{indent}// Versioning\n"
    structure += f"{indent}// Major.Minor.Revision\n"
    structure += f"{indent}// Major - Breaking change to this structure\n"
    structure += f"{indent}// Minor - Functions added to the end of this structure\n"
    structure += f"{indent}// Revision - Some non breaking change\n"
    structure += f"{indent}//\n"
    structure += f"{indent}// The caller should fill in with a function that provides the version of the protocol they are expecting.\n"
    structure += f"{indent}// When initializing the protocol, the callee filling in the crypto functions will check the version\n"
    structure += f"{indent}// and attempt to provide the functions that match the version requested.\n"
    structure += create_divider(indent=indent, divider="-", length=80)
    for function in functions:
        typedef_name = functions[function]['typedef_name']

        #
        # Add the function to the protocol structure
        #
        structure += f"{indent}SHARED_{typedef_name} {function};\n"

        #
        # Add a divider after the GET_VERSION function
        # This is just to provide a visual break in the protocol structure
        # TODO make this more generic to the class of functions and not just GET_VERSION
        #
        if "GET_VERSION" in typedef_name:
            structure += create_divider(indent=indent, divider="-", length=80)

    structure += "} SHARED_CRYPTO_PROTOCOL;\n\n"

    return structure


def process_header_file(header_file: str, output_file: str) -> dict:
    """
    Processes the header file and writes the protocol to the output file.
    """
    with open(header_file, 'r') as file:

        version_region = extract_copy_region(file, section="VERSION")
        functions = get_functions(file)
        typedefs = create_typedefs(functions)
        protocol_structure = create_protocol_structure(functions)

        with open(output_file, 'w') as f:
            f.write("//")
            f.write("// This file was generated by CreateProtocol.py\n") # TODO: Add date
            f.write("#ifndef __PROTOCOL_H__\n")
            f.write("#define __PROTOCOL_H__\n\n")

            f.write("#include <Uefi.h>\n\n")
            f.write("#include \"SharedCryptDecl.h\" // TODO should this be Protocol or Library?\n\n")
            f.write(create_divider())
            major, minor, revision = extract_version(version_region)
            f.write(f"// Protocol version: {major}.{minor}.{revision}\n")
            f.write(create_divider())
            #f.write(version_region)
            #f.write(create_divider())
            f.write("\n")
            # TODO
            #f.write(rsa_key_tag_region)
            f.write(create_divider())
            f.write("// Typedef Declarations\n")
            f.write(create_divider())
            f.write(typedefs)

            f.write(create_divider())
            f.write("// Protocol\n")
            f.write(create_divider())
            f.write(protocol_structure)

            f.write("#endif // __PROTOCOL_H__\n")

        print(f"Protocol written to {output_file}")

    #create_c_definitions(functions=functions, output_file="temp.out.c")

def create_c_definitions(functions: dict, output_file="temp.out.c"):
    with open(output_file, 'w') as file:
        file.write("VOID\n")
        file.write("EFIAPI\n")
        file.write("InitAvailableCrypto (\n")
        file.write("  SHARED_CRYPTO_PROTOCOL  *Crypto\n")
        file.write(")\n")
        file.write("{\n")
        file.write(f"// total functions: {len(functions)}\n")
        for function in functions:
            file.write(f"  Crypto->{function} = {function};\n")
        file.write("}\n")


if __name__ == "__main__":
    args = cli()

    if args.debug:
        DEBUG = True
    process_header_file(args.header_file, args.output)
