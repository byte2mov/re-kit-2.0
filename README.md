# [ re-kit 2.0 ] - Reverse Engineering Toolkit

[![Version](https://img.shields.io/badge/version-2.0-blue.svg)](https://github.com/byte2mov/re-kit-2.0)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)

**re-kit 2.0** is a powerful reverse engineering toolkit designed for security researchers and developers. It provides a suite of hooks and patches for debugging, virtual machine detection, and memory protection bypassing, all within a modern, easy-to-use interface.

## Features

- **Create Command Calls Hook**: Hook into command calls for analysis or manipulation.
- **Patch VMP Memory Protection**: Modify memory protection in applications protected by VMProtect.
- **Create `GlobalFindAtomA` Hook**: Hook `GlobalFindAtomA` function calls to monitor usage.
- **Create Anti-Debugger Hooks**: Disable Anti Debug Functions in applications and malware.
- **Create Anti-VM Hooks**: Disable Anti VM in applications and malware
- **Create `FindWindowA` Hook**: Hook into the `FindWindowA` WinAPI call to track window searches, malware tends to use this to detect debuggers.
- **Apply Hooks**: Apply all hooks into the target process.
- **Basic Anti Injection Bypass**: Countering anti injection using basic methods.
- **Basic Anti Malware Techniques**: Preventing forced BSOD's and file execution.
- **RunPE Dumper & Memory Dumper** : Dump the memory the program is trying to write ( DLL, exe, sys, etc ).
- **Request Monitoring** : Ability to Moniter all winhttp requests.
- **Process Mitigation Policy Bypass** : Bypassing mitigation policies set by programs.
- **Full Logging System** : Log all the actions and addresses.
- **Exit**: Safely exit the toolkit interface.
  
Here’s a more professional version for your GitHub credits section:

---

## Credits

The name of this project and the graphical user interface (GUI) design were inspired by [Zer0Condition's ReverseKit](https://github.com/zer0condition/ReverseKit). I greatly admired the structure and aesthetic of ReverseKit, which influenced this project.

Special thanks to Zer0Condition for their exceptional work on ReverseKit.

---



## Contributions


1. To Contribute to re-kit-2.0 please reach out to me via email -> byte2mov@pytguard.com
2. If your work has been put in this repository and not properly credited please contact me via email to get the appropriate credit 0> byte2mov@pytguard.com

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/byte2mov/re-kit-2.0.git
    ```
2. Compile the project using your preferred compiler.
3. Launch the executable and attach it to your desired process.

## Usage

Once attached to the process, select the desired hooks and patches.


## Screenshots


![re-kit 2.0 Main Interface](https://github.com/user-attachments/assets/f052c12e-f6af-4ab3-89a3-1133cbbd069c)

![re-kit 2.0 Hook Application](https://github.com/user-attachments/assets/83231afe-3b61-44a6-b54f-c8ab5bfabaef)

