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
- `jit/`: JIT subsystem (compilers + architecture-specific emitters), compiled into `bpfvm_lib`.
    - `jit.h`: shared JIT data structures and type aliases.
    - `jit_compiler.h`, `jit_compiler.cpp`: architecture-independent JIT compiler template and implementation.
    - `jit_base_emitter.h`: architecture-independent code emission base class.
    - `x86_emitter.h`, `x86_emitter.cpp`: x86_64 JIT code emitter.
    - `aarch64_emitter.h`, `aarch64_emitter.cpp`: AArch64 JIT code emitter.
- `include/`: BPF-facing headers (syscall IDs, POSIX types) used by guest programs.
- `cmake/`: CMake helper scripts (e.g., `RunBpfProgram.cmake` for CTest integration).
- `bpfvm-ld`: BPF linker (replaces `binutils-bpf` `bpf-ld`); see `src/ld_main.cpp`.
- `passes/`: LLVM pass plugins (compiled into `build/lib*.so`, loaded by `clang -fpass-plugin=...`).
    - `BpfWideArgs.cpp`: lifts the BPF limit (5-arg, struct return, variadic).
    - `BpfSoftFp.cpp`: rewrites floating-point IR into soft-float library calls, enabling `float`/`double` support.
- `musl/`: default C library for BPF targets (musl 1.2.6 port); built via `sh musl/build.sh` → `musl/build/install/{include,lib}`.
- `libc/`: symlink → `musl/build/install` (default); exposes headers (`-Ilibc/include`) and archives (`-Llibc/lib`).
- `pdclib/`: alternative C library (optional, not built by default); sources + `bpf-toolchain.cmake` kept for manual builds.
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
- C library wrappers (default musl) live in `musl/arch/bpf/syscall_arch.h` and the musl `src/` tree, mapping POSIX functions (`open`, `read`, `mmap`, `fork`, etc.) to `BPF_CALL_*` IDs. (pdclib's equivalents are in `pdclib/platform/bpf/functions/posix/syscall.c`, used only when building against pdclib.)
- The low-level `syscall()` path dispatches by casting the call ID to a function pointer with 0–5 args, so the VM sees a direct call to `BPF_CALL_*`.

## Commit & Pull Request Guidelines
- Commit messages are short and action-oriented; recent history uses concise Chinese phrases (e.g., “实现dup2”).
- Keep commits scoped to one change set and mention user-visible behavior when applicable.
- PRs should include a brief description, how you tested (commands + results), and links to relevant issues. Screenshots are only needed for UI changes (rare here).

## Configuration & Dependencies
- Requires `libelf` via `pkg-config` for the VM build.
- BPF toolchain: `clang` (>= 19) compiles `.c` → `.o`; `bpfvm-ld` (built from `src/ld_main.cpp`) links `.o` + archives into self-contained ET_EXEC or PIE ET_DYN; `bpfvm` runs the result. No `binutils-bpf` or `bpf-ld`.

## BPF Linker (`bpfvm-ld`)
The project ships its own BPF linker `bpfvm-ld` that fully replaces `binutils-bpf` `bpf-ld`. Three modes (share the same `Linker` core), aligned with standard `ld` defaults:

- **Static** (`-static`): merges `.o` + archives into a self-contained ET_EXEC (fixed address). Example: `bpfvm-ld -static foo.o -l:libc.a -o foo.linked`.
- **Shared library** (`-shared` / `--shared`): builds a `.so` from an archive, exports its GLOBAL symbol table, PIE (p_vaddr=0, loadable at any address). Example: `bpfvm-ld --shared --soname libc.so libc.a -o libc.so`.
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
The BPF architecture has **no hardware floating-point units or registers**. The BPF LLVM backend (`BPFISelLowering.cpp`) rejects any floating-point operation at the ISel stage, reporting e.g. `"A call to built-in function '__adddf3' is not supported"` — and this rejection happens *before* the backend could ever lower the op into a library call, so simply providing `__adddf3` implementations is not enough on its own.

**Solution: a virtual set of floating-point "instructions" encoded as BPF `call`s**

The core idea is to **simulate a batch of floating-point instructions through the BPF `call` mechanism**, and then treat each one as a single instruction everywhere in the pipeline. Concretely, every FP operation is given a stable numeric ID — the `BPF_CALL_FP_*` family in `include/bpf_call.h` (e.g. `BPF_CALL_FP_ADD_D`, `BPF_CALL_FP_D2SI`, `BPF_CALL_FP_CMP_D`) — and ends up in a BPF program as exactly one `call <imm>` with **`src_reg=2` (a dedicated FP channel)**. This deliberately separates FP from syscalls (`src_reg=0`): interpreter and JIT dispatch `src_reg=2` straight to the FP path (`do_softfp` / `emit_call_softfp`), never touching the syscall handler. Each FP instruction is self-contained: read operands (bit patterns in `r1`/`r2`), compute the result with the host's hardware FP, write the bit pattern back to `r0`. There is no function call at runtime, no stack frame, no VM state plumbing between operands and result — it is one instruction that happens to use the `call` opcode as its carrier.

This is split across **three** layers (no guest-side glue):

1. **`BpfSoftFp` LLVM pass** (`src/passes/BpfSoftFp.cpp`, auto-built into `build/libBpfSoftFp.so`, auto-injected by `pdclib/bpf-toolchain.cmake` and `test/Makefile`) — the *IR* stage: rewrites every floating-point IR instruction (`fadd`/`fsub`/`fmul`/`fdiv`/`fneg`/`fcmp`, the fp↔int casts, `fpext`/`fptrunc`, and the `fmuladd`/`fma`/`sqrt` intrinsics) into a call to an `extern __ksym` function `__bpf_fp_<ID>` (section `.ksyms`), where `<ID>` is the decimal `BPF_CALL_FP_*` value. The backend lowers this as a normal unresolved external call: parameters land in `r1`/`r2`/... and the result in `r0` per the BPF calling convention (this is the key stability property — it uses the backend's native call lowering, not an InlineAsm trick whose `"r"`/`"=r"` constraints do not pin physical registers). `fcmp` expands to *two* calls (`CMP` + `UNORD`) so each IEEE-754 predicate is reconstructed exactly.

2. **`bpfvm-ld` linker** — the *bytecode rewrite* stage: clang emits these as `call -1` (`src_reg=1` placeholder) + an `R_BPF_64_32` relocation targeting `__bpf_fp_<ID>`. The linker recognizes the `__bpf_fp_` symbol name, parses `<ID>` from the name (no lookup table — the ID travels in the name itself), and rewrites the instruction to `src_reg=2` + `imm=<ID>`. It also suppresses "undefined symbol" for these names (the VM interprets them at runtime) and skips PLT/GOT synthesis for them (they are not real cross-module calls).

3. **Execution** — both paths resolve the same `BPF_CALL_FP_*` ID (from `imm`) and run the op with the host's hardware FP (operands as `i64` bit patterns, result to `r0`):
   - **Interpreter**: `do_softfp` in `insn.cpp` — reached directly via the `src_reg=2` dispatch branch, also the JIT's fallback.
   - **JIT**: `emit_call_softfp()` recognizes the ID and emits native host FP code inline. Because the JIT keeps all 11 BPF registers resident in physical registers, r1/r2/r0 are already in place (x86: R9/R10/R8; AArch64: X10/X11/X9) — no flush, no VM exit, the op is just one more instruction in the stream. Per-arch details and the encoding gotchas hit during bring-up are commented at each `emit_call_softfp` site. The only architectural difference that matters at this level: **AArch64 has native `FCVTZU`/`UCVTF` and handles every `BPF_CALL_FP_*` natively, whereas x86 lacks unsigned fp↔int conversion (needs AVX-512), so on x86 the unsigned-conversion IDs fall back to `do_softfp`** via `emit_call_softfp_slow` → `helper_do_softfp` (a dedicated FP fallback helper, decoupled from the syscall path).

**ABI details:** Floating-point values are stored as IEEE-754 bit patterns in the 64-bit BPF registers / stack slots — no precision is lost. Varargs like `printf("%f", x)` work through the existing `BpfWideArgs` pass (`va_list` slots are 8 bytes). `printf %f` formatting is provided by the default musl libc (musl's printf handles `%f`/`%e`/`%g` natively); under pdclib it is enabled via the `functions/_PDCLIB/_PDCLIB_print.c` `#if 1` block + `_PDCLIB_print_fp*` sources.

**What still needs care:**
*   `long double` == `double` (64-bit) on this target; code using 128-bit `long double` precision should be converted to `double` (see e.g. `log_10_2` in `_PDCLIB_print_fp_deci.c`).
*   Only `sqrt` is softened among the math intrinsics so far; `fabs`/`copysign`/`floor`/`ceil`/… are trivial to add by extending the `IntrinsicInst` handler in `passes/BpfSoftFp.cpp`.

### 2. Function Call Conventions

**Constraint (native BPF ABI):**
The native BPF calling convention has three strict limits:
1.  **Argument Count:** a function cannot take more than **5 arguments** (`"stack arguments are not supported"`).
2.  **Struct Returns:** a function **cannot return a structure** (struct) — the backend rejects the `sret` attribute (`"aggregate returns are not supported"`).
3.  **Variadic Functions:** the backend rejects any variadic function (`isVarArg = true`) at the ISel stage (`"variadic functions are not supported"`, `BPFISelLowering.cpp`). This also covers non-variadic functions that use `va_arg`/`va_copy` intrinsics (e.g. `vfprintf`, which takes a `va_list` parameter).

**Solution: BpfWideArgs pass**
This project ships an LLVM pass plugin (`src/passes/BpfWideArgs.cpp`) that transparently lifts **all three** limits at compile time, so you can write **standard C** with arbitrary numbers of arguments, struct returns, and `...` variadic functions. It is auto-built into `build/libBpfWideArgs.so` when LLVM dev headers are present, and auto-injected by `bpf-toolchain.cmake` / `test/Makefile`.

**How it works** (see `src/passes/BpfWideArgs.cpp`) — the three transforms are independent and composable (e.g. a 6-arg function returning a struct is supported):
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

## Default C Library (musl) & Optional PDCLib

The default C library for BPF targets is **musl** (`musl/`). Build it with `sh musl/build.sh`; the `libc` symlink at the project root points to `musl/build/install`, so `-Ilibc/include` and `-Llibc/lib` resolve to musl's headers and `libc.a` (with crt merged in, containing `_start`).

### Building musl (default)
```bash
sh musl/build.sh          # → musl/build/install/{include,lib}
./build_root.sh           # also runs build_musl + synthesizes libc.so
```

### Building PDCLib (optional alternative)
PDCLib is kept as an optional C library but is **not built by default**. To use it instead of musl:
1.  **Cross-Compilation**:
    ```bash
    cd pdclib
    cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=bpf-toolchain.cmake
    cmake --build build
    cmake --install build --prefix build/install
    ```
2.  **Switch the `libc` symlink**: `ln -sfn pdclib/build/install libc`
3.  BPF compilers then reference PDCLib via `-Ilibc/include` and `-Llibc/lib64 -l:libpdclib.a`.

## musl Porting (`musl/`)

The project ships a port of musl 1.2.6 as the **default** C library for the BPF target. Build with `sh musl/build.sh` — produces `musl/build/install/lib/libc.a` (with `crt1.o`/`crti.o`/`crtn.o` merged in, so it contains `_start`) + standalone `crt1.o`/`Scrt1.o`/`crti.o`/`crtn.o`, and headers in `musl/build/install/include/`. `test/Makefile` and `build_root.sh` build against this musl directly (static `.out` + dynamic `.linked`).

### musl build (`musl/build.sh`)
- **`--disable-shared`**: musl's `.so` is synthesized from `libc.a` by `bpfvm-ld -shared` (in `build_root.sh`'s `build_libc_bpfso`), not by musl's own build.
- **`-mllvm -bpf-stack-size=16384`**: musl's `crypt_blowfish` (`BF_crypt`) has ~8.5KB local structs; the default 4096 overflows.
- **rcrt1.o skipped**: `make install` compiles `rcrt1.o` (static PIE self-start, depends on `dlstart` dynamic linker logic — BPF can't support it) and fails. The script builds only `crt1`/`crti`/`crtn`/`Scrt1` via per-target `make obj/crt/<name>.o`, then manually copies headers to `install/include/` (generic/bits first, then bpf/bits so BPF-specific overrides win).
- **crt merged into libc.a**: BPF's `_start` lives in `crt1.o` (pure C, `arch/bpf/crt_arch.h`); `crti.o`/`crtn.o` are empty (BPF has no `.init_array`/`.fini_array` framework). The script runs `ar rcs lib/libc.a lib/crt1.o lib/crti.o lib/crtn.o` so `libc.a` carries `_start` itself — like pdclib, linkers only pass `libc.a`/`libc.so` and need no separate crt files or ordering. `Scrt1.o` is not merged (it also defines `_start`, would duplicate).
- **install layout**: `install/{include,lib}` mirrors pdclib's layout so the project-root `libc` symlink abstracts the choice; `install/lib` holds `libc.a` (+ crt), `Scrt1.o`, `crt1.o`/`crti.o`/`crtn.o`.

### Pass rebuild after `.so` changes
**musl (Make, default) and pdclib (CMake, optional) do NOT track `libBpfWideArgs.so`/`libBpfSoftFp.so` timestamp changes** — they only look at `.c` source mtimes. After modifying either pass, force a full rebuild:
- musl (default): `find musl/build/obj -name '*.o' -delete && sh musl/build.sh` (re-runs `make lib/libc.a` + crt + merge crt into libc.a + header/lib install), then `./build_root.sh` to regenerate `libc.so`.
- pdclib (optional): `rm -rf pdclib/build`, then rebuild pdclib + `bpfvm-ld -shared` to regenerate `libc.so`.

Skipping this reuses stale `.o` compiled with the old pass (a past incident: deleting `__va_arg` left old `.o` still referencing it, causing `_va_arg` undefined at link).
