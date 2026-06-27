# Repository Guidelines

## Project Structure & Module Organization
- `main.cpp`: VM entry point, command-line parsing, signal setup.
- `insn.h`: core VM class (`vm`), abstract `SyscallHandler` interface, TLB, and instruction definitions.
- `insn.cpp`: BPF instruction execution (interpreter loop with JIT fallback).
- `elf_loader.h`, `elf_loader.cpp`: BPF ELF loading and library search (shared by `bpfvm` runtime and `bpfvm-ld`); runtime `.rela.dyn`/`.rela.plt` processing and PIE address allocation.
- `elf_linker.h`, `elf_linker.cpp`: offline BPF linker core (static / shared / dynamic modes); segment layout, relocations, PLT/GOT synthesis.
- `ld_main.cpp`: `bpfvm-ld` CLI (argument parsing, `-l`/`-L` resolution, mode dispatch).
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
- `bpfvm-ld`: BPF linker (replaces `binutils-bpf` `bpf-ld`); see `src/ld_main.cpp`.
- `BpfWideArgs.cpp`: LLVM pass plugin that lifts the BPF limit (loaded via `clang -fpass-plugin=...`).
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
- `make -C test` — build BPF test programs into `.out` files using `clang` and `bpfvm-ld`.
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
- **CoW support**: memory mappings support copy-on-write semantics (for `fork`); write faults trigger segment duplication.
- **Signal-aware frames**: normal call frames are 64 bytes; signal frames are 128 bytes with additional saved state.

### JIT Environment Variables
- `JIT_ENABLE`: set to `0` to disable JIT and force interpreter-only execution; defaults to enabled (any other value or unset enables JIT).
- `BPF_DEBUG`: set to any value to print VM execution statistics (instruction counts, JIT compilation info, timing) to stderr at VM exit. Also enables instruction counting in JIT-compiled code.

### Instruction Budget
- The `--insn-limit N` (`-l N`) command-line option sets an upper bound on the total number of instructions the VM may execute (interpreter + JIT combined). When the limit is reached, the VM sets the `VM_BUDGET_EXCEEDED` flag, prints a diagnostic to stderr, and exits with code 255.
- In JIT code, the budget check is embedded in loop-header safepoints; the loop body size is estimated during compilation and added to `insn_count` at each back-edge.

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
- BPF toolchain: `clang` (>= 19) compiles `.c` → `.o`; `bpfvm-ld` (built from `src/ld_main.cpp`) links `.o` + archives into self-contained ET_EXEC or PIE ET_DYN; `bpfvm` runs the result. No `binutils-bpf` or `bpf-ld`.

## BPF Linker (`bpfvm-ld`)
The project ships its own BPF linker `bpfvm-ld` that fully replaces `binutils-bpf` `bpf-ld`. Three modes (share the same `Linker` core), aligned with standard `ld` defaults:

- **Static** (`-static`): merges `.o` + archives into a self-contained ET_EXEC (fixed address). Example: `bpfvm-ld -static foo.o -l:libpdclib.a -o foo.linked`.
- **Shared library** (`-shared` / `--shared`): builds a `.so` from an archive, exports its GLOBAL symbol table, PIE (p_vaddr=0, loadable at any address). Example: `bpfvm-ld --shared --soname libc.so libpdclib.a -o libc.so`.
- **Dynamic executable** (default): builds a PIE ET_DYN that references `.so` dependencies via `DT_NEEDED`. Cross-module function calls go through PLT/GOT; cross-module data references are recorded in `.rela.dyn`. At runtime `bpfvm` allocates load addresses and applies relocations. Example: `bpfvm-ld foo.o -l libc.so -o foo.linked`.

All three modes emit **three permission-separated `PT_LOAD` segments** (W^X), classified from section flags by `layout_segments` (`src/elf_linker.cpp`):
- `text` (`SHF_EXECINSTR`) → `PF_R|PF_X` (read-only + executable)
- `rodata` (read-only data) → `PF_R`
- `data` + `.bss` (`SHF_WRITE`) → `PF_R|PF_W`; `.bss` is `SHT_NOBITS`, so `p_memsz > p_filesz` and is zero-filled at load

Segments are page-aligned and non-overlapping in the guest address space.

Entry symbol defaults to `_start` (standard `ld` behavior); override with `-e <name>` / `--entry <name>`.

## Historical Note
Earlier versions depended on `binutils-bpf` `bpf-ld`, which had a `.rodata.str1.1` merge bug (Debian #1126689). `bpfvm-ld` makes this workaround unnecessary.

## BPF Architecture Constraints & Developer Guide

### 1. Floating Point Number Support

**Constraint:**
The BPF architecture **does not support floating-point arithmetic** (float, double). There are no hardware floating-point units or registers available.

**Solution:**
*   **Disable Floating Point:** Ensure the compiler does not generate floating-point instructions.
*   **Integer Arithmetic:** All calculations must be performed using integers (`int`, `int64_t`, `uint64_t`, etc.).
*   **Fixed-Point Math:** If fractional precision is required, implement fixed-point arithmetic using integers (e.g., scaling values by 1000 to represent 3 decimal places).

### 2. Function Call Conventions

**Constraint (native BPF ABI):**
The native BPF calling convention has three strict limits:
1.  **Argument Count:** a function cannot take more than **5 arguments** (`"stack arguments are not supported"`).
2.  **Struct Returns:** a function **cannot return a structure** (struct) — the backend rejects the `sret` attribute (`"aggregate returns are not supported"`).
3.  **Variadic Functions:** the backend rejects any variadic function (`isVarArg = true`) at the ISel stage (`"variadic functions are not supported"`, `BPFISelLowering.cpp`). This also covers non-variadic functions that use `va_arg`/`va_copy` intrinsics (e.g. `vfprintf`, which takes a `va_list` parameter).

**Solution: BpfWideArgs pass**
This project ships an LLVM pass plugin (`src/BpfWideArgs.cpp`) that transparently lifts **all three** limits at compile time, so you can write **standard C** with arbitrary numbers of arguments, struct returns, and `...` variadic functions. It is auto-built into `build/libBpfWideArgs.so` when LLVM dev headers are present, and auto-injected by `bpf-toolchain.cmake` / `test/Makefile`.

**How it works** (see `src/BpfWideArgs.cpp`) — the three transforms are independent and composable (e.g. a 6-arg function returning a struct is supported):
*   **>5 arguments:** the pass packs the 5th argument onward into a `__bpf_pack_<func>` struct, passed via a pointer in `r5`. The caller allocates the struct on the stack (re-entrancy/recursive safe); the callee loads the extra args at entry. Thus registers `r1`–`r4` hold the first four scalar args, and `r5` is the pack pointer.
*   **Struct returns:** LLVM already lowers `struct` returns to the `sret` pointer convention (`void f(ptr sret, ...)`); the pass simply strips the `sret` attribute the BPF backend rejects. Semantics are unchanged.
*   **Variadic functions** — clang's native `VoidPtrBuiltinVaList` is used, where `va_list` is a single `void*` pointing at the first vararg:
    *   **Callee rewrite:** `R f(T0..Tn, ...)` → `R f(T0..Tn, ptr __va_base)`. `__va_base` points to a caller-allocated memory region holding the varargs. Function prototypes (declarations) are rewritten the same way.
    *   **Caller rewrite:** each call site allocates a `__bpf_vapack_<func>` struct on the entry stack (packed, each slot sized by `allocSize(T)`), stores the variadic arguments into it, and passes its address as `__va_base`.
    *   **Intrinsic lowering** (applied to *all* functions, not just variadic ones):
        *   `va_start(ap)` → `store __va_base, ap`
        *   `va_arg(ap, T)` → `load T, ptr ap; ap += allocSize(T)`
        *   `va_copy(d, s)` → `*d = *s` (copy the pointer value)
        *   `va_end(ap)` → no-op

### 3. Historical / Optional Alternatives

The approaches below predate or work around the `BpfWideArgs` pass. They are kept for reference and for the case where the pass is disabled (targeting the native BPF ABI directly).

#### Force inline (optional fallback when the pass is off)
Bypass the argument-count / struct-return limits by inlining the function so the call convention is never exercised:

```c
#define BPF_INLINE __attribute__((always_inline)) inline

// Example: function with > 5 args
BPF_INLINE void complex_logic(int a, int b, int c, int d, int e, int f) {
    // Implementation gets inlined, avoiding the 5-reg limit
}
```

#### Hand-built pseudo-`va_list`
Varargs can be emulated entirely in the headers with a pseudo-`va_list` that the caller assembles by hand at each call site. The pass supersedes the technique; this section is kept for reference.

*   **Define `va_list` as a struct**:
    ```c
    typedef struct {
        int pos;
        unsigned long long* data;
    } _va_list;
    ```
    `pos` was a running index and `data` pointed at a caller-allocated `uint64_t[]` array holding the varargs.
*   **Counting the arguments:** the array length and the per-slot fill loop are driven by a preprocessor argument counter (`___bpf_narg`), so the caller never writes the count by hand. It is the classic offset-placeholder trick — a leading dummy argument, then a reverse-numbered list, and `N` lands on the right slot:
    ```c
    #define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
    #define ___bpf_narg(...) \
        ___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
    // ___bpf_narg(a, b)        → 2
    // ___bpf_narg(a, b, c, d)  → 4
    ```
    `___bpf_apply(fn, N)` then selects the matching overload, so `___bpf_fill(arr, a, b, c)` expands to `___bpf_fill3(arr, 0, a, b, c)` (one `___bpf_fillN` overload exists per arity, up to 12). The same counter also sizes the array itself: `unsigned long long data[___bpf_narg(args)]`.
*   **Building a list at the call site:** a helper macro allocates a local `uint64_t[]` (sized by `___bpf_narg`), fills it one argument per slot via `___bpf_fill`, and initialises the struct to point at it. Expanded by hand it looks like:
    ```c
    uint64_t ap_data[2] = { (uint64_t)(uintptr_t)"world", 42 };
    _va_list ap = { .pos = 0, .data = ap_data };
    ```
*   **Access macros** walk the array:
    *   `_va_arg(ap, type)` → `{ ap.pos++; (type)ap.data[ap.pos-1]; }`
    *   `_va_copy(dest, src)` → `dest = src` (struct copy, so both share the array)
    *   `_va_end(ap)` → no-op
    *   `_va_start` was intentionally disabled (BPF had no `...` functions to start from).
*   **Usage pattern:** declare the *backend* function taking a real `va_list`, and wrap it in a statement-expression macro that built the pseudo-`va_list` at each call site:
    ```c
    int my_vprintf(const char *format, va_list ap);   // backend, takes va_list

    #define my_printf(fmt, ...) ({ \
        /* build ap: local uint64_t[] + init _va_list */ \
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
