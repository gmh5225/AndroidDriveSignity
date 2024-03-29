# `AndroidDriveSignity`

AndroidDriveSignity is a Python script designed for patching Android kernel``(ARMv8.3)`` files, enabling the loading of drivers without being subject to various verification checks, specifically signature verifications. This tool aims to facilitate the development and testing process by allowing developers to bypass the kernel's built-in security measures that prevent unofficial or modified drivers from being loaded.

### Features

- **Targeted Symbol Patching:** Modifies specific symbols within the kernel (`check_modinfo`, `check_version`, and `module_sig_check`) to circumvent driver signature verification mechanisms.
- **Intelligent Patching:** Dynamically adjusts patching based on the presence of the PACIASP instruction, ensuring compatibility across different kernel configurations.
- **User-Friendly CLI:** Provides a straightforward command-line interface for specifying the kernel binary, the kallsyms symbol table, and the output file paths.

### Requirements

- Rooted Android devices``(ARMv8.3)`` with [Magisk](https://github.com/topjohnwu/Magisk) or [KernelSU](https://github.com/tiann/KernelSU)
- Python 3.x
- ADB

### Usage

1. **Prepare the Necessary Files:** Ensure you have the kernel binary file (`kernel_file_path`), the kallsyms symbol table file (`kallsyms_file_path`), and a destination for the patched kernel (`output_file_path`).

2. **Execute AndroidDriveSignity:** Navigate to the script's directory in your terminal or command prompt and run:

   ```bash
   python AndroidDriveSignity.py <kernel_file_path> <kallsyms_file_path> <output_file_path>

### How to get your kallsyms?
```
adb shell
su
echo 0 > /proc/sys/kernel/kptr_restrict
exit
exit
adb shell su -c "cat /proc/kallsyms > /data/local/tmp/kallsyms"
adb pull /data/local/tmp/kallsyms
```

### How to extract your kernel file?
If there are two partitions, prioritize trying "boot_a":
```
adb shell su -c "dd if=$(readlink /dev/block/by-name/boot_a) of=/data/local/tmp/boot.img"
```
If there is only one partition, then it is "boot.img":
```
adb shell su -c "dd if=$(readlink /dev/block/by-name/boot) of=/data/local/tmp/boot.img"
```
Then, pull the boot image to your local machine:
```
adb pull /data/local/tmp/boot.img
```

Finally, use [magiskboot](https://github.com/svoboda18/magiskboot/releases) to extract the kernel file from boot.img.
```
magiskboot --unpack boot.img
```
You will obtain two files: one is the ``kernel``(your kernel file), and the other is ``ramdisk.cpio``.

### Testing on android12-5.10
```
python AndroidDriveSignity.py kernel kallsyms new-kernel
move/mv new-kernel kernel
magiskboot --repack boot.img
adb reboot bootloader
fastboot flash boot new-boot.img
fastboot reboot
adb push demo.ko /data/local/tmp
adb shell su -c insmod /data/local/tmp/demo.ko
adb shell su -c "lsmod |grep demo"
adb shell su -c rmmod /data/local/tmp/demo.ko
```
You can obtain an example of the Android driver [here](https://github.com/gmh5225/android-kernel-driver-template/releases)

## Credits
- ``Linux``
- ``Android``
- Some anonymous people

