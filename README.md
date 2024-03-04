# `AndroidDriveSignity`

AndroidDriveSignity is a Python script designed for patching Android kernel files, enabling the loading of drivers without being subject to various verification checks, specifically signature verifications. This tool aims to facilitate the development and testing process by allowing developers to bypass the kernel's built-in security measures that prevent unofficial or modified drivers from being loaded.

### Features

- **Targeted Symbol Patching:** Modifies specific symbols within the kernel (`check_modinfo`, `check_version`, and `module_sig_check`) to circumvent driver signature verification mechanisms.
- **Intelligent Patching:** Dynamically adjusts patching based on the presence of the PACIASP instruction, ensuring compatibility across different kernel configurations.
- **User-Friendly CLI:** Provides a straightforward command-line interface for specifying the kernel binary, the kallsyms symbol table, and the output file paths.

### Prerequisites

Before using AndroidDriveSignity, make sure you have:

- Python 3.x installed on your system.
- The target Android kernel binary file and its corresponding kallsyms symbol table file.
- A clear understanding of the risks involved with kernel patching and modifying driver verification mechanisms.

### Usage

1. **Prepare the Necessary Files:** Ensure you have the kernel binary file (`kernel_file_path`), the kallsyms symbol table file (`kallsyms_file_path`), and a destination for the patched kernel (`output_file_path`).

2. **Execute AndroidDriveSignity:** Navigate to the script's directory in your terminal or command prompt and run:

   ```bash
   python AndroidDriveSignity.py <kernel_file_path> <kallsyms_file_path> <output_file_path>
