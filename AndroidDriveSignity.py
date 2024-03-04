import os
import argparse

# Dictionary to hold symbol addresses and names
symbols_dict = {}

def parse_kallsyms(file_path):
    # Parse the kallsyms file to populate the symbols dictionary
    global symbols_dict
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split(' ')
            if len(parts) == 3:
                address, symbol_type, symbol_name = parts
                symbols_dict[address] = symbol_name

def check_original_instruction(kernel_data, patch_offset):
    # Check if the original instruction at the given offset is PACIASP
    return kernel_data[patch_offset:patch_offset + 4] == bytearray.fromhex("3F 23 03 D5")

def prepare_patch_data(original_patch_data_hex, has_paciasp):
    # Prepare the patch data, adding PACIASP and AUTIASP instructions if necessary
    if has_paciasp:
        return bytearray.fromhex("3F 23 03 D5") + bytearray.fromhex(original_patch_data_hex)[:4] + bytearray.fromhex("BF 23 03 D5") + bytearray.fromhex(original_patch_data_hex)[4:]
    else:
        return bytearray.fromhex(original_patch_data_hex)

def patch_symbol(kernel_data, symbol_name, base_address, original_patch_data_hex):
    # Patch the symbol in the kernel data with the given patch data
    symbol_address = None
    for address, name in symbols_dict.items():
        if name == symbol_name:
            symbol_address = int(address, 16)
            break

    if symbol_address is None:
        print(f"Error: {symbol_name} symbol not found.")
        return False

    relative_address = symbol_address - base_address
    patch_offset = relative_address

    # Check if the original instruction is PACIASP and prepare the patch data accordingly
    has_paciasp = check_original_instruction(kernel_data, patch_offset)
    if has_paciasp:
        print(f"Symbol {symbol_name} Offset 0x{patch_offset:X} has PACIASP enabled.")
    else:
        print(f"Symbol {symbol_name} Offset 0x{patch_offset:X} has PACIASP disabled.")
    patch_data = prepare_patch_data(original_patch_data_hex, has_paciasp)

    kernel_data[patch_offset:patch_offset + len(patch_data)] = patch_data
    return True

def patch_kernel_file(kernel_file_path, kallsyms_file_path, output_file_path):
    # Main function to patch the kernel file based on the provided kallsyms file
    parse_kallsyms(kallsyms_file_path)

    base_address = int(list(symbols_dict.keys())[0], 16)

    with open(kernel_file_path, 'rb') as kernel_file:
        kernel_data = bytearray(kernel_file.read())

    # Apply patches to specified symbols
    patch_symbol(kernel_data, "check_modinfo", base_address, "00 00 80 52 C0 03 5F D6")
    patch_symbol(kernel_data, "check_version", base_address, "20 00 80 52 C0 03 5F D6")
    # The GKI kernel may not have this function
    patch_symbol(kernel_data, "module_sig_check", base_address, "00 00 80 52 C0 03 5F D6")

    # Save the patched kernel data to the output file
    with open(output_file_path, 'wb') as output_file:
        output_file.write(kernel_data)

    print(f"Kernel file patched and saved to {output_file_path}")

if __name__ == "__main__":
    # Command line argument parsing
    parser = argparse.ArgumentParser(description="Patch kernel file with provided symbol modifications.")
    parser.add_argument("kernel_file_path", type=str, help="Path to the binary kernel file.")
    parser.add_argument("kallsyms_file_path", type=str, help="Path to the kallsyms symbol file.")
    parser.add_argument("output_file_path", type=str, help="Path where the patched kernel file will be saved.")

    args = parser.parse_args()

    # Execute the patching process with provided arguments
    patch_kernel_file(args.kernel_file_path, args.kallsyms_file_path, args.output_file_path)
