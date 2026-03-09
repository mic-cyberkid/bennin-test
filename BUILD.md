# Build and Compilation Guide

This document provides instructions on how to compile the Windows Modular Implant from source.

---

## 1. Requirements

### Native Windows Build (Recommended)
- **Visual Studio 2022** (with "Desktop development with C++" workload).
- **Windows SDK** (10.0.19041.0 or newer).
- **CMake 3.20+**.

### Cross-Compilation (Ubuntu/Linux)
- **MinGW-w64** toolchain.
- **CMake**.
- **Make**.

---

## 2. Compilation Steps

### Using MSVC (Command Line)
1. Open "x64 Native Tools Command Prompt for VS 2022".
2. Navigate to the project root.
3. Run the following:
```bash
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Using MinGW-w64 (Cross-Compile from Linux)
```bash
mkdir build
cd build
cmake .. -DCMAKE_SYSTEM_NAME=Windows \
         -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
         -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++
make
```

---

## 3. Important Compiler Flags

The `cmake/CompileOptions.cmake` file configures several security-critical flags:

- **`/MT` (Static Runtime)**: Ensures all dependencies are bundled into the executable, avoiding "missing DLL" errors on the target.
- **`/GS-` (Disable Stack Buffer Checks)**: Used to reduce the binary signature and avoid standard CRT checks.
- **`/Os` (Favor Size)**: Minimizes the executable footprint.
- **`/GL` (Whole Program Optimization)**: Enables better obfuscation across translation units.

---

## 4. Troubleshooting

- **"LNK2001: unresolved external symbol"**: Ensure all required Windows libraries are listed in `CMakeLists.txt`. Common ones include `bcrypt`, `advapi32`, `ole32`, `mpr`, and `taskschd`.
- **"C4838: narrowing conversion"**: This usually happens when defining XOR-encoded byte arrays. Use `const wchar_t` or explicit casts to resolve.
- **"MASM" errors**: Ensure the `SYSCALL_STUB` in `CMakeLists.txt` correctly selects `.asm` for MSVC and `.s` for MinGW.
