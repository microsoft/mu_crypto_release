"""
python CreateSharedCryptDecl.py SharedCryptoProtocol.h -o SharedCryptDecl.h
"""
import argparse
import re

def cli() -> dict:
    argparse.ArgumentParser(description="Transforms a protocol file into a header file that can be used in UEFI")
    parser = argparse.ArgumentParser()

    parser.add_argument("protocol_header_file", help="The protocol header file to be transformed")
    parser.add_argument("-o", "--output", help="The output file to write the transformed protocol header file to", default="protocol.h")

    args = parser.parse_args()
    return args

RSA_KEY_INFO = """
///
/// RSA Key Tags Definition used in RsaSetKey() function for key component identification.
///
typedef enum {
  RsaKeyN,      ///< RSA public Modulus (N)
  RsaKeyE,      ///< RSA Public exponent (e)
  RsaKeyD,      ///< RSA Private exponent (d)
  RsaKeyP,      ///< RSA secret prime factor of Modulus (p)
  RsaKeyQ,      ///< RSA secret prime factor of Modules (q)
  RsaKeyDp,     ///< p's CRT exponent (== d mod (p - 1))
  RsaKeyDq,     ///< q's CRT exponent (== d mod (q - 1))
  RsaKeyQInv    ///< The CRT coefficient (== 1/q mod p)
} RSA_KEY_TAG;
"""

def extract_copy_regions(file_content: str) -> list:
    """
    Extracts all regions of the file content that start with "// COPY_REGION_BEGIN"
    and end with "// COPY_REGION_END".

    Args:
        file_content (str): The content of the file as a string.

    Returns:
        list: A list of extracted regions as strings.
    """
    start_marker = "// COPY_REGION_BEGIN"
    end_marker = "// COPY_REGION_END"

    regions = []
    start_index = 0

    while True:
        start_index = file_content.find(start_marker, start_index)
        if start_index == -1:
            break
        end_index = file_content.find(end_marker, start_index)
        if end_index == -1:
            break

        # Extract the region without the markers
        region_start = start_index + len(start_marker)
        region_end = end_index
        regions.append(file_content[region_start:region_end].strip())
        start_index = end_index + len(end_marker)

    return regions

def parse_typedefs(file_content: str) -> list:
    """
    Parses the given file content to extract C function typedefs along with preceding comments.

    Args:
        file_content (str): The content of the file as a string.

    Returns:
        list: A list of dictionaries, each containing the following keys:
            - 'comment' (str): The comment preceding the typedef.
            - 'return_type' (str): The return type of the function.
            - 'calling_convention' (str): The calling convention of the function.
            - 'function_name' (str): The name of the function.
            - 'params' (list): A list of parameter strings.
    """
    typedefs = {}

    typedef_pattern = re.compile(
        r'(?P<comment>/\*\*.*?\*/)\s*typedef\s+(?P<return_type>(?:\w+\s)*\w+\s*\*?)\((?P<calling_convention>\w+)\s\*(?P<typedef_type>\w+)\)\((?P<params>\s*([\s\S]*?)\s*)\);',
        re.DOTALL
    )
    matches = typedef_pattern.findall(file_content)
    for match in matches:

        comment = match[0]
        return_type = match[1]
        calling_convention = match[2]
        typedef_type = match[3]
        params = match[4]
        param_list = [param.strip() for param in params.split(',')]

        typedefs[typedef_type] = {
            'comment': comment.strip(),
            'return_type': return_type.strip(),
            'calling_convention': calling_convention.strip(),
            'params': param_list
        }

    return typedefs

def parse_shared_crypto_protocol(file_content: str) -> dict:
    protocol_pattern = re.compile(r'typedef struct _SHARED_CRYPTO_PROTOCOL\s*{\s*([^}]+)\s*}\s*SHARED_CRYPTO_PROTOCOL;')
    match = protocol_pattern.search(file_content)
    if not match:
        return {}

    protocol_content = match.group(1)

    function_pattern = re.compile(r'(SHARED_\w+)\s+(\w+);')
    functions = function_pattern.findall(protocol_content)

    function_map = {}
    for typedef, method in functions:
        function_map[method] = typedef

    return function_map

def generate_function_declarations(typedefs: dict, function_map: dict) -> str:

    declarations = []

    for function, typedef in function_map.items():
        return_type = typedefs[typedef]["return_type"]
        calling_convention = typedefs[typedef]["calling_convention"]
        params = typedefs[typedef]["params"]
        declaration = typedefs[typedef]["comment"]
        declaration += f"\n{return_type}\n{calling_convention}\n{function}(\n  {',\n  '.join(params)});"
        declarations.append(declaration)
    return "\n\n".join(declarations)


def write_to_header_file(output_file: str, copied_region: [], declarations: str):
    print(f"Writing to {output_file}")
    with open(output_file, 'w') as f:
        f.write("#ifndef _PROTOCOL_H_\n")
        f.write("#define _PROTOCOL_H_\n\n")
        f.write("#include <Uefi.h>\n\n")
        for region in copied_region:
            f.write(region)
            f.write("\n\n")

        f.write(RSA_KEY_INFO)
        f.write("\n\n")
        f.write(declarations)
        f.write("\n\n#endif")

def main():
    args = cli()
    with open(args.protocol_header_file, 'r') as f:
        file_content = f.read()

    copied_region = extract_copy_regions(file_content)
    typedefs = parse_typedefs(file_content)
    functions_map = parse_shared_crypto_protocol(file_content)
    functions = generate_function_declarations(typedefs, functions_map)
    write_to_header_file(args.output, copied_region, functions)

if __name__ == "__main__":
    main()