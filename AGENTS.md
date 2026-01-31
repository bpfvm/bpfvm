# Repository Guidelines

## Project Structure & Module Organization
- `main.cpp`, `insn.cpp`, `syscalls.cpp`, `insn.h`: core VM entry point, instruction handling, and syscall glue.
- `include/`: BPF-facing headers used by the VM and test programs.
- `libc/`, `pdclib/`: C library sources and build artifacts used for BPF targets.
- `dash/`: shell sources for the BPF cross-build.
- `test/`: small BPF test programs (`.c`) and expected outputs (`.out`), built via a local Makefile.
- `testdrivers/`, `test_support/`: PDCLib test drivers and helpers; treat as upstream-style fixtures.
- `build/`: local build outputs (CMake and cross-build artifacts).

## Build, Test, and Development Commands
- `cmake -S . -B build && cmake --build build` — configure and build `bpfvm` and `bpfvm_test`.
- `./build/bpfvm <elf-file>` — run the VM on a BPF ELF file.
- `./build/bpfvm_test` — run the unit test executable (see `insn_test.cpp`).
- `make -C test` — build BPF test programs into `.out` files using `clang` and `bpf-ld`.
- `./build_dash.sh` — build the BPF cross-compiled `dash` binary (requires `clang`, `gcc`, and `libelf`).

## Coding Style & Naming Conventions
- C++20 (`CMAKE_CXX_STANDARD 20`); keep code compatible with `clang`.
- Indentation: 4 spaces; braces on the same line as control statements/functions.
- Names: types use `CamelCase` or existing patterns (e.g., `vmOptions`), functions/variables use `lower_snake_case`, macros/constants use `UPPER_SNAKE_CASE`.
- Keep includes grouped: standard headers, then project headers.

## Testing Guidelines
- Unit tests live in `insn_test.cpp` and are built into `bpfvm_test`.
- BPF test programs live in `test/` and produce `.out` binaries; keep filenames aligned (`test_foo.c` -> `test_foo.out`).
- No coverage requirement is defined; add focused tests for new VM instructions or syscalls.

## Syscall Implementation & C Library Wrappers
- Syscall IDs are defined in `include/bpf_call.h` and encoded via `BPF_CALL_BASE` / `BPF_CALL_ID()`; the VM decodes them in `syscalls.cpp` (`vm::do_syscall`). 
- The VM reads syscall arguments from registers (`r(1)`..`r(5)`), translates guest pointers with `mmu()`, and returns results in `r(0)`; errors are negative `errno` values.
- C library wrappers live in `pdclib/platform/bpf/functions/posix/syscall.c` and map POSIX functions (`open`, `read`, `mmap`, `fork`, etc.) to `BPF_CALL_*` IDs.
- The low-level `syscall()` macro in `pdclib/platform/bpf/include/pdclib/_PDCLIB_config.h` dispatches by casting the call ID to a function pointer with 0–5 args, so the VM sees a direct call to `BPF_CALL_*`.

## Commit & Pull Request Guidelines
- Commit messages are short and action-oriented; recent history uses concise Chinese phrases (e.g., “实现dup2”).
- Keep commits scoped to one change set and mention user-visible behavior when applicable.
- PRs should include a brief description, how you tested (commands + results), and links to relevant issues. Screenshots are only needed for UI changes (rare here).

## Configuration & Dependencies
- Requires `libelf` via `pkg-config` for the VM build.
- BPF toolchain dependencies: `clang`, `bpf-objcopy`, and `bpf-ld` for `test/` programs.

## Known Toolchain Issues
- `bpf-ld` (binutils-bpf 2.44) may mis-merge string literals (off-by-one addresses in `.rodata`).
- Workaround: strip merge flags on `.rodata.str1.1` with `bpf-objcopy --set-section-flags .rodata.str1.1=alloc,readonly,data`.
- Debian bug report: `https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1126689`.

## BPF Architecture Constraints & Developer Guide

### 1. Floating Point Number Support

**Constraint:**
The BPF architecture **does not support floating-point arithmetic** (float, double). There are no hardware floating-point units or registers available.

**Solution:**
*   **Disable Floating Point:** Ensure the compiler does not generate floating-point instructions.
*   **Integer Arithmetic:** All calculations must be performed using integers (`int`, `int64_t`, `uint64_t`, etc.).
*   **Fixed-Point Math:** If fractional precision is required, implement fixed-point arithmetic using integers (e.g., scaling values by 1000 to represent 3 decimal places).

### 2. Function Call Conventions

**Constraint:**
The BPF calling convention has strict limits:
1.  **Argument Count:** A function cannot take more than **5 arguments**.
2.  **Return Values:** A function **cannot return a structure** (struct). It can only return scalar values (integers, pointers) that fit in a register.

**Solution: Force Inline**
For logic that requires more than 5 arguments or needs to return complex data structures, bypass the calling convention by inlining the function.

Use the `always_inline` attribute to force the compiler to expand the function body at the call site:

```c
#define BPF_INLINE __attribute__((always_inline)) inline

// Example: Function with > 5 args
BPF_INLINE void complex_logic(int a, int b, int c, int d, int e, int f) {
    // Implementation gets inlined, avoiding the 5-reg limit
}
```

### 3. Variadic Functions (Varargs)

**Constraint:**
The architecture **does not support standard C variadic functions** (e.g., `void func(const char* fmt, ...)`). The underlying stack layout and register passing mechanisms do not support `va_list`.

**Solution: PDCLIB_MAKE_VA_LIST**
Use the existing `PDCLIB_MAKE_VA_LIST` macro provided by `pdclib` (via `<stdarg.h>`). This macro facilitates the creation of a pseudo-`va_list` by allocating an array on the stack and populating it with arguments.

**PDCLIB Implementation Details:**
*   **`va_list` Structure:** Defined in `_PDCLIB_config.h` as:
    ```c
    typedef struct {
        int pos;
        unsigned long long* data;
    } _PDCLIB_va_list;
    ```
*   **Mechanism:** `PDCLIB_MAKE_VA_LIST(name, args...)` creates a local `uint64_t` array, initializes the `va_list` struct to point to it, and fills the array with the provided arguments.

**Implementation Example:**

```c
#include <stdarg.h>

// Backend function accepting the struct
int my_vprintf(const char *format, va_list ap);

// Macro wrapper
#define my_printf(fmt, ...) \
    ({\
        PDCLIB_MAKE_VA_LIST(ap, ##__VA_ARGS__); \
        my_vprintf(fmt, ap); \
    })
```

## PDCLib Build & Installation

1.  **Cross-Compilation**: Build PDCLib using the built-in BPF toolchain configuration:
    ```bash
    cd pdclib
    cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=bpf-toolchain.cmake
    cmake --build build
    ```

2.  **Installation**: Install the build artifacts to the `build/install` directory:
    ```bash
    cmake --install build --prefix build/install
    ```

3.  **Using the `libc` Symlink**:
The `libc` directory in the project root is a pre-configured symbolic link pointing to `pdclib/build/install`. **Once the installation steps are completed, this symlink becomes active**. BPF compilers (e.g., clang) can then easily reference standard library headers and archives via `-Ilibc/include` and `-Llibc/lib`.
