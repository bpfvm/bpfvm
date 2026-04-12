# Repository Guidelines

## Project Structure & Module Organization
- `main.cpp`: VM entry point, command-line parsing, signal setup.
- `insn.h`: core VM class (`vm`), abstract `SyscallHandler` interface, TLB, and instruction definitions.
- `insn.cpp`: BPF instruction execution (interpreter loop with JIT fallback).
- `posix_syscall.h`, `posix_syscall.cpp`: full POSIX syscall implementation (`PosixSyscall` class), fd management, signal queue, process control.
- `empty_syscall.h`: stub syscall handler (`EmptySyscall`) returning `-ENOSYS`, used for testing.
- `insn_test.cpp`: unit tests for instruction execution, built into `bpfvm_test`.
- `jit.h`: shared JIT data structures and type aliases.
- `jit_compiler.h`, `jit_compiler.cpp`: architecture-independent JIT compiler template and implementation.
- `jit_base_emitter.h`: architecture-independent code emission base class.
- `x86_emitter.h`, `x86_emitter.cpp`: x86_64 JIT code emitter.
- `aarch64_emitter.h`, `aarch64_emitter.cpp`: AArch64 JIT code emitter.
- `include/`: BPF-facing headers (syscall IDs, POSIX types) used by guest programs.
- `cmake/`: CMake helper scripts (e.g., `RunBpfProgram.cmake` for CTest integration).
- `bpf-cc`: BPF compiler wrapper script used by `test/Makefile` and `build_root.sh`.
- `libc/`, `pdclib/`: C library sources and build artifacts used for BPF targets.
- `dash/`: shell sources for the BPF cross-build.
- `sbase/`: sbase coreutils sources for the BPF cross-build.
- `root/`: demo rootfs output directory (binaries installed to `root/bin`).
- `test/`: small BPF test programs (`.c`) and expected outputs (`.out`), built via a local Makefile.
- `pdclib/test_support/`, `pdclib/build/test_support/testdrivers/`: PDCLib test drivers and helpers; treat as upstream-style fixtures.
- `build/`: local build outputs (CMake and cross-build artifacts).

## Build, Test, and Development Commands
- `cmake -S . -B build && cmake --build build` — configure and build `bpfvm` and `bpfvm_test`.
- `./build/bpfvm <elf-file>` — run the VM on a BPF ELF file.
- `./build/bpfvm_test` — run the unit test executable (see `insn_test.cpp`).
- `cd build && ctest` — run all CTest tests (see below).
- `make -C test` — build BPF test programs into `.out` files using `bpf-cc` and `bpf-ld`.
- `./build_root.sh` — build demo rootfs (`dash` + `sbase`) and install to `root/bin` (requires `clang`, `gcc`, and `libelf`).

## Coding Style & Naming Conventions
- C++20 (`CMAKE_CXX_STANDARD 20`); keep code compatible with `clang`.
- Indentation: 4 spaces; braces on the same line as control statements/functions.
- Names: types use `CamelCase` or existing patterns (e.g., `vmOptions`), functions/variables use `lower_snake_case`, macros/constants use `UPPER_SNAKE_CASE`.
- Keep includes grouped: standard headers, then project headers.

## Testing Guidelines
- Unit tests live in `insn_test.cpp` and are built into `bpfvm_test`.
- BPF test programs live in `test/` and produce `.out` binaries; keep filenames aligned (`test_foo.c` -> `test_foo.out`).
- No coverage requirement is defined; add focused tests for new VM instructions or syscalls.

### CTest Cases
CMake registers the following CTest cases under the `BUILD_TESTING` option (run with `cd build && ctest`):

1. **`unit_tests`** — Runs the `bpfvm_test` executable (instruction-level unit tests from `insn_test.cpp`).
2. **`bpf_programs_build`** — Invokes `make -C test` to compile all BPF test programs (`test/*.c` → `test/*.out`). Marked as a fixture (`FIXTURES_SETUP bpf_programs_built`); all subsequent BPF program tests depend on it automatically.
3. **`test_*` series** — Auto-discovered from `test/test_*.c` files. Each test case runs `bpfvm <program>.out` via the `cmake/RunBpfProgram.cmake` script and checks the exit code against the expected value (default 0). Helper programs listed in `BPF_TEST_HELPERS` (e.g., `test_arg`, `test_cloexec_child`) are skipped and do not generate standalone test cases.

**Adding a new BPF test case:** Simply create a `test/test_<name>.c` file; CTest will auto-discover and register it. If the program is a helper (invoked by other tests rather than run independently), add it to the `BPF_TEST_HELPERS` list in `CMakeLists.txt`.

## JIT Compilation & Execution Model

The VM uses a hybrid interpreter/JIT execution model:
- **JIT-first**: hot functions are compiled to native code via `JitCompiler<EmitterT>`, with architecture-specific emitters for x86_64 and AArch64.
- **Interpreter fallback**: single-step execution or JIT errors fall back to the interpreter loop in `insn.cpp`.
- **TLB acceleration**: a software TLB caches guest-to-host address translations; misses go through `mmu_slow()` / `mmu_w_slow()`.
- **CoW support**: memory mappings support copy-on-write semantics (for `fork`); write faults trigger page duplication.
- **Signal-aware frames**: normal call frames are 64 bytes; signal frames are 128 bytes with additional saved state.

### JIT Environment Variables
- `JIT_ENABLE`: set to `0` to disable JIT and force interpreter-only execution; defaults to enabled (any other value or unset enables JIT).
- `JIT_DEBUG`: set to any value to print JIT statistics (instruction counts, hit rate, compilation time) to stderr at VM exit.

## Syscall Implementation & C Library Wrappers
- Syscall handling is decoupled from the VM via the abstract `SyscallHandler` interface (defined in `insn.h`), with `PosixSyscall` (`posix_syscall.cpp`) as the main implementation and `EmptySyscall` (`empty_syscall.h`) as a stub for testing.
- Syscall IDs are defined in `include/bpf_call.h` and encoded via `BPF_CALL_BASE` / `BPF_CALL_ID()`; the VM dispatches them through the `SyscallHandler::syscall()` virtual method.
- The VM reads syscall arguments from registers (`r(1)`..`r(5)`), translates guest pointers with `mmu()`, and returns results in `r(0)`; errors are negative `errno` values.
- Signal handling uses a lock-free multi-producer-single-consumer queue (`MpscQueue`) in `PosixSyscall`, with support for `SIGKILL`/`SIGSTOP`/`SIGCONT` bypassing the queue via direct flags.
- C library wrappers live in `pdclib/platform/bpf/functions/posix/syscall.c` and map POSIX functions (`open`, `read`, `mmap`, `fork`, etc.) to `BPF_CALL_*` IDs.
- The low-level `syscall()` macro in `pdclib/platform/bpf/include/pdclib/_PDCLIB_config.h` dispatches by casting the call ID to a function pointer with 0–5 args, so the VM sees a direct call to `BPF_CALL_*`.

## Commit & Pull Request Guidelines
- Commit messages are short and action-oriented; recent history uses concise Chinese phrases (e.g., “实现dup2”).
- Keep commits scoped to one change set and mention user-visible behavior when applicable.
- PRs should include a brief description, how you tested (commands + results), and links to relevant issues. Screenshots are only needed for UI changes (rare here).

## Configuration & Dependencies
- Requires `libelf` via `pkg-config` for the VM build.
- BPF toolchain dependencies: `clang`, `bpf-objcopy`, and `bpf-ld` for `test/` programs. The `bpf-cc` wrapper script in the project root handles the standard compile flags and post-compilation `bpf-objcopy` workaround.

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
