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
- **Exit**: Safely exit the toolkit interface.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/byte2mov/re-kit-2.0.git
    ```
2. Compile the project using your preferred compiler.
3. Launch the executable and attach it to your desired process.

## Usage

Once attached to the process, select the desired hooks and patches.

