# Repository Guidelines

永远不要使用git checkout, 只能使用git stash作为替代

如果grep报错"指定了互相冲突的匹配器"，那是因为在 zcode 里 `grep` 是一个被重定义过的函数，与标准 GNU grep 行为不同。这时候需要 grep 时改用 `command grep ...`、`/usr/bin/grep ...`，或优先使用专门的搜索工具(rg)。

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
- `cd build && ctest -j4` — run CTest with parallel jobs; tests are independent, so always pass `-j4` to run them concurrently instead of serially.
- `make -C test` — build BPF test programs into `.out` files using `clang` and `bpfvm-ld`.
- `./scripts/build_root.sh` — build demo rootfs (`dash` + `sbase`) and install to `root/bin` (requires `clang`, `gcc`, and `libelf`).
- Disassemble BPF ELF binaries with `bpf-objdump` (from `binutils-bpf`), e.g. `bpf-objdump -d foo.out`. Prefer it over plain `objdump`, which does not understand the BPF target.

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
- `JIT_THRESHOLD`: hot-pc detection threshold (default `100`; `0` disables it, compiling every pc as before). A guest pc must be reached this many times (counted in `compile()`, which `step()` single-stepping and JIT `helper_call_bpf` both drive) before it is JIT-compiled. Loop back-edge targets reach the threshold quickly and get compiled at the loop header — an implicit OSR (the JIT prologue loads `vm->reg[]`, so it can enter at any pc and the interpreter's current state is preserved); cold pcs never reach it and stay in the interpreter, so compile time is not wasted on template-bloat cold code. The threshold trades OSR latency against compile savings: compute-bound programs (large loops) OSR after `threshold` iterations, so `test_compute` is unchanged; `test_stl_filesystem`-style programs (many cold functions) speed up ~25×. Higher values slow OSR (e.g. `test_compute` 0.16s at 100 → 1.0s at 2000).
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

### Debug Info (DWARF)
By default `bpfvm-ld` preserves DWARF debug sections (`.debug_info`, `.debug_line`, `.debug_str`, `.debug_abbrev`, `.debug_addr`, `.debug_frame`, ...) in the output as **non-ALLOC `SHT_PROGBITS`** sections, matching standard `ld` behavior. Compile with `-g` (already on in `test/Makefile`, `scripts/build_root.sh`, `scripts/build_busybox.sh`) and the linked binary carries full source-level debug info:

```bash
bpfvm-ld -static foo.o -l:libc.a -o foo.linked     # .debug_* kept (default)
bpf-objdump -S foo.linked                           # disassembly interleaved with C source
llvm-dwarfdump --verify foo.linked                  # verify DWARF
```

- **Static mode only**: debug-section preservation is currently enabled for `-static` (fixed addresses). PIE modes (`-shared`, default dynamic) skip debug emission because `.debug_addr` references `.text` by absolute address, which is only known after the VM picks a load base at runtime (a future stage can emit position-independent debug info).
- **Strip**: `--strip-debug` (`-S`) drops `.debug_*` only; `-s` / `--strip-all` drops both `.debug_*` and `.symtab`/`.strtab` (matching standard `ld` semantics). `-g` and its variants (`-g2`, `-gdwarf-4`, ...) are accepted as no-ops (debug is already on by default).
- **Relocations**: `.rel.debug_*` relocations are applied at link time and **not** emitted to the output (cleaner; consumers see pre-resolved values). Two address classes are handled: debug→debug references resolve to section-relative offsets, debug→loadable references resolve to the final guest address.
- **Symbol table**: all three modes now emit a static `.symtab`/`.strtab` containing both GLOBAL symbols and `STB_LOCAL` FUNC/OBJECT symbols (so `objdump -d` can label local function boundaries). `sh_info` points at the first GLOBAL per the ELF convention. Runtime symbol resolution still uses `.dynsym` in PIE modes.
- `.BTF`/`.BTF.ext` (BPF kernel metadata) and `.llvm_addrsig` are still dropped (VM has no use for them).

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
*   **Math functions: split between musl libm and VM virtual instructions, with the dividing line = whether the musl body survives `instcombine`.** `floor`/`ceil`/`trunc`/`round` (+ `sin`/`cos`/`exp`/`log`/`pow`/...) come from musl's `src/math/*.c` (generic pure-C; BPF has no arch specialization); the `BpfLibcallLower` pass lowers their *intrinsic* forms (`@llvm.floor`, ...) into plain libcalls (`call @floor`/`floorf`) and lets libcall forms pass through untouched for libc to resolve. `sqrt`/`fabs`/`copysign` stay VM virtual instructions (`BPF_FP_SQRT_*`/`FABS_*`/`COPYSIGN_*`): `sqrt` because the JIT emits a single native hardware instruction (`sqrtsd`/`fsqrt`); `fabs`/`copysign` because their musl bodies are a single bitwise `and`/`or` that `-O1` instcombine folds *back* into the same-name intrinsic (`@llvm.fabs`), so lowering them to `call @fabs` would recurse infinitely (`fabs` calling itself) — keeping them as VM instructions sidesteps the recursion without bespoke inline-bit-twiddling logic in the pass. All three (`sqrt`/`fabs`/`copysign`) have native JIT cases in both `emit_call_softfp` emitters (x86: `sqrtsd`/`andps`/`orps` on xmm; AArch64: `FSQRT`/`FABS` for sqrt/fabs, GPR `and`/`or` bitmask for copysign — it has no single native FP instruction), so they never fall back to the interpreter. Both their intrinsic and libcall forms are intercepted by `BpfSoftFp` and rewritten to the corresponding `BPF_FP_*`. The VM virtual-instruction set thus stays: ISA primitives without a libc counterpart (arithmetic/compare/convert) + `sqrt` + `fabs`/`copysign` + emutls.

### 2. Function Call Conventions

**Constraint (native BPF ABI):**
The native BPF calling convention has three strict limits:
1.  **Argument Count:** a function cannot take more than **5 arguments** (`"stack arguments are not supported"`).
2.  **Struct Returns:** a function **cannot return a structure** (struct) — the backend rejects the `sret` attribute (`"aggregate returns are not supported"`).
3.  **Variadic Functions:** the backend rejects any variadic function (`isVarArg = true`) at the ISel stage (`"variadic functions are not supported"`, `BPFISelLowering.cpp`). This also covers non-variadic functions that use `va_arg`/`va_copy` intrinsics (e.g. `vfprintf`, which takes a `va_list` parameter).

**Solution: BpfWideArgs pass**
This project ships an LLVM pass plugin (`src/passes/BpfWideArgs.cpp`) that transparently lifts **all three** limits at compile time, so you can write **standard C** with arbitrary numbers of arguments, struct returns, and `...` variadic functions. It is auto-built into `build/libBpfWideArgs.so` when LLVM dev headers are present, and auto-injected by `bpf-toolchain.cmake` / `test/Makefile`.

**How it works** (see `src/passes/BpfWideArgs.cpp`) — the four transforms are independent and composable (e.g. a 6-arg function returning a struct is supported):
*   **>5 arguments:** the pass packs the 5th argument onward into a `__bpf_pack_<func>` struct, passed via a pointer in `r5`. The caller allocates the struct on the stack (re-entrancy/recursive safe); the callee loads the extra args at entry. Thus registers `r1`–`r4` hold the first four scalar args, and `r5` is the pack pointer.
*   **Struct returns:** LLVM already lowers `struct` returns to the `sret` pointer convention (`void f(ptr sret, ...)`); the pass simply strips the `sret` attribute the BPF backend rejects. Semantics are unchanged.
*   **By-value struct parameters:** clang lowers C++ by-value aggregate parameters in two ways, and `lowerAggregateParams` normalizes both to a plain `ptr` (1 register each):
    *   **Large aggregates (≥3 words, e.g. `std::string` 24B):** clang already emits `ptr byval(%T) align N` — the caller memcpys the argument into a stack temporary and passes its pointer, the callee uses it as a plain pointer (`getelementptr`/`load`). The BPF backend rejects the `byval` attribute ("pass by value not supported"), so the pass strips `byval` from every function signature and call site (covering direct/indirect calls and external callees). No type/body change — the parameter is already a pointer.
    *   **Small aggregates (≤2 words, e.g. `std::pair`=`{i64,i64}`, `__bit_iterator`=`[2 x i64]`, `i128`):** clang uses the aggregate **value type** directly as the parameter type (no `byval`). The BPF backend expands this into multiple registers per element/field, so `f(__bit_iterator, __bit_iterator, value, proj)` = 2+2+1+1 = 6 registers > the 5-register limit → "too many arguments". The pass rebuilds the signature to a plain `ptr`, moves the body, inserts an entry `load`, and at each call site stores the aggregate argument into a fresh entry-block alloca and passes its pointer.
    Semantics are unchanged either way (by-value = caller hands callee an independent copy); the per-call-site copy is preserved (the optimizer can't prove the callee won't write through the now-unattributed pointer, so it conservatively keeps it). This unlocks `f(std::string)` / `f(std::vector)` / `f(std::pair)` / any by-value aggregate — previously rejected.
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

### 4. C++ Support (Language Subset)

The BPF VM supports a **C++ language subset**: programs compiled with `clang++ -target bpf -fno-exceptions -frtti`, using musl's C runtime via `extern "C"` and **libc++** (`libcxx.a`/`libcxx.so`) for the C++ standard library. Verified end-to-end by `test/test_cpp_lang.cpp` (5 ctest variants: static/dynamic × JIT/interp + host); STL coverage by the `test/test_stl_*.cpp` suite.

**What works without a C++ runtime** (bare language subset):
- Templates, classes/structs, constructors/destructors, single inheritance, virtual functions (vtable dispatch).
- Namespaces, `constexpr`, function overloading, references, `auto`, lambdas (with capture).
- `operator new` / `operator delete` backed by musl `malloc`/`free` (define them in the `.cpp`; mangles to `_Znwm`/`_ZdlPv`, resolves without a C++ runtime library).

**STL via libc++** (`libcxx.a`/`libcxx.so`, built by `scripts/build_libcxx.sh`): the standard library works, including RTTI (`typeid`/`dynamic_cast`) and `<thread>`/`<mutex>`/`<future>` (libc++ pthread backend over musl pthread).

**Verified compile-time limitations** (clang 19, `-target bpf -fno-exceptions -frtti`):
- `throw` / `try`: `error: cannot use 'throw'/'try' with exceptions disabled`. RTTI **is** enabled, so `dynamic_cast` and `typeid` work (see `test/test_stl_rtti.cpp`); only reference-`dynamic_cast` failure (`bad_cast`) is unavailable because it requires exceptions.

**Hard constraints to respect when writing C++ for this target**:
- **No exceptions**: `throw`/`try` rejected at compile time (no `__cxa_throw`/`__cxa_personality`/libunwind ported). RTTI is enabled; `typeid`/`dynamic_cast` are available.
- **`thread_local` via `address_space(256)`** (see "Emulated TLS" below): the C++ `thread_local` keyword is rejected by clang's Sema for the BPF target (cannot be bypassed with `-femulated-tls`); use the `__mythread` macro instead.
- **No `&thread_local_var`**: taking the address of an emutls variable is a compile error (different address spaces); access the variable directly.

**Global ctors/dtors**: supported via the `.init_array`/`.fini_array` framework in `bpfvm-ld` (see `src/elf_linker.cpp`). Global objects with non-trivial constructors/destructors work: ctors run before `main` (in definition order), dtors run at `exit` (reverse order, via `__cxa_atexit` registered in `_GLOBAL__sub_I_*`). Verified by `test/test_cpp_ctor.cpp`.

**Build integration** (see `test/Makefile`):
- `test/test_cpp_*.cpp` is auto-discovered; the `CXX_FLAGS` mirror the C `CC_FLAGS` (same target/CPU/stack-size/isystem/pass-plugin flags) plus `-std=c++23 -nostdinc++ -fno-exceptions -frtti` and libc++ bypass macros (`-D_LIBCPP_HAS_THREAD_API_PTHREAD -D_LIBCPP_HAS_MUSL_LIBC -D_LIBCPP_HAS_NO_INT128 ...`). The C++ pass plugins (`libBpfWideArgs.so`/`libBpfSoftFp.so`/`libBpfLibcallLower.so`/`libBpfEmutls.so`) are injected alongside the C ones.
- C++ tests link `libcxx.a` (static `.out`) or `libcxx.so` (dynamic `.linked`), both produced by `scripts/build_root.sh`'s `build_libcxx` (`scripts/build_libcxx.sh` → `libcxx.a`; `bpfvm-ld -shared` → `libcxx.so`, `DT_NEEDED libc.so`). C tests stay free of any libcxx dependency.
- C++ tests run the same 5 ctest variants as C tests via `cmake/RunBpfProgram.cmake`.
- musl `libc.a` provides **no** C++ ABI symbols (only C-style `__cxa_atexit`/`__cxa_finalize`); the C++ runtime — `operator new`/`delete`, libc++abi typeinfo vtables + `__dynamic_cast` + `__cxa_*`, and the libc++ library itself — comes from `libcxx.a`/`libcxx.so`.

#### Emulated TLS (emutls) via `address_space(256)`

Per-thread storage is supported through a macro + an LLVM pass + a VM runtime, reusing the FP virtual-instruction channel (`src_reg=2`).

**Usage**:
```cpp
#ifdef __BPF__
#define __mythread __attribute__((address_space(256)))
#else
#define __mythread thread_local   // host baseline
#endif

__mythread int counter = 0;          // zero-init
__mythread int init_val = 42;        // non-zero init (template-copied on first access)
__mythread int arr[4] = {1,2,3,4};   // arrays (GEP access supported)
struct Point { int x; int y; };
__mythread Point pt = {1, 2};        // structs (field access supported)
```
On the host, `__mythread` expands to real `thread_local`, so the same source serves as a baseline in the `host` ctest variant.

**Mechanism** (mirrors the `BpfSoftFp` architecture; see `src/passes/BpfEmutls.cpp`):
1. clang emits `addrspace(256)` globals + `load/store/GEP ... ptr addrspace(256)` — this completely bypasses Sema's `thread_local` rejection (BPF.h: `TLSSupported=false`) and the BPF backend's `GlobalTLSAddress` ISel crash.
2. The `BpfEmutls` pass (loaded via `-fpass-plugin=libBpfEmutls.so`, runs at `PipelineStartEPCallback`) rewrites every access to an `addrspace(256)` global into:
   - a control block `@__emutls_v.<name> = { i64 size, i64 align, i64 index, ptr value }` (init template pointer is null for zero-init, else points to a copied `@__emutls_t.<name>` template);
   - a call `__bpf_fp_<EMUTLS_ID>(i64 ctrl_ptr)` returning the per-thread address (the call is emitted as `extern __ksym`, section `.ksyms`).
3. The linker needs **no change**: `__bpf_fp_<ID>` is already recognized by `is_fp_ksym`, which rewrites the call to `src_reg=2` + `imm=<ID>`. `BPF_FP_EMUTLS_GET_ADDR` is the ID (in `include/bpf_call.h`, appended to `bpf_fp_op`).
4. `vm::do_softfp` dispatches `BPF_FP_EMUTLS_GET_ADDR` (`src/insn.cpp`): reads the control block from `r1`, lazily allocates a per-thread slot in `vm::emutls_slots_` (each slot is a fresh `mmap` registered as a `memmap` in the guest address space), copies the init template on first access, and returns the guest address in `r0`. Each VM (= each thread) has its own `emutls_slots_`, so isolation is automatic — no `pthread_key` needed.
5. JIT: `emit_call_softfp` returns false for `BPF_FP_EMUTLS_GET_ADDR`, falling back to `emit_call_softfp_slow` → `helper_do_softfp` → `do_softfp`. No JIT emitter change needed.

**Limitations**:
- Trivially-destructible types only (no `__cxa_thread_atexit` for `thread_local` destructors yet).
- `&var` is a compile error (address-space mismatch); access the variable directly.
- Each TLS variable currently allocates a full 4 KiB page (no slab/arena yet).
- TLS variables must be defined and used within a single translation unit; cross-TU `extern __mythread` is not supported (the control block `__emutls_v.<name>` uses internal linkage).

**Fork semantics**: a child created via `fork()` (clone without `CLONE_VM`) inherits the parent's current TLS values (the parent's `emutls_slots_` is copied; each slot's guest page is CoW-shared, so writes by either side trigger CoW and diverge). Threads (`pthread_create`, clone with `CLONE_VM`) each get independent slots (no inheritance — standard `thread_local` semantics).

**Roadmap** (gated, each stage widens what's usable):
1. ✅ Language subset (this section).
2. ✅ Emulated TLS via `address_space(256)` (this subsection; `test/test_cpp_tls.cpp`).
3. ✅ Global ctors/dtors via `.init_array`/`.fini_array` (this subsection; `test/test_cpp_ctor.cpp`).
4. ✅ STL via libc++ + `libcxx.a`/`libcxx.so` (the `test/test_stl_*.cpp` suite). The standard library works (containers, algorithms, `<iostream>`, `<regex>`, `<thread>`/`<mutex>`/`<future>`, `<filesystem>`, RTTI). Mechanism: `lowerAggregateParams` (by-value aggregate params → ptr) + `BpfAtomicLowerPass` (lower plain atomic load/store — eBPF ISA has only RMW atomics; unlocks static guards in locale/iostream) + `BpfByvalTmpPass` (≤8B by-value unique_ptr double-free fix; LLVM bug workaround, see §5) + `BpfLibcallLower` (memcpy/memmove/memset/trap + floor/ceil/trunc/round → musl calls) + libc++ pthread backend over musl pthread + `uncaught_exceptions` stub override.

#### Global ctors/dtors via `.init_array`/`.fini_array`

Global objects with non-trivial constructors/destructors are supported through linker-synthesized symbols, reusing musl's existing `__libc_start_init` / `__libc_exit_fini` loops — **no loader/VM change**.

**Mechanism** (see `src/elf_linker.cpp`):
1. clang emits `.init_array` (SHT_INIT_ARRAY) holding function pointers (`_GLOBAL__sub_I_*`), each of which constructs one global object and registers its destructor via `__cxa_atexit(dtor, obj, __dso_handle)`.
2. `bpfvm-ld` collects `.init_array`/`.fini_array` sections into SEG_DATA (kept contiguous within the segment), and synthesizes four boundary symbols: `__init_array_start/end`, `__fini_array_start/end` (stored in `synthetic_globals_`, emitted to both `.symtab` and `.dynsym` as `SHN_ABS`). It also synthesizes `__dso_handle`.
3. Static mode: function pointers in `.init_array` are patched at link time (R_BPF_64_ABS64). PIE mode: left as `.rela.dyn` entries, resolved by the loader at runtime (`_GLOBAL__sub_I_*` is a defined symbol in the main program, collected into `exports_`).
4. musl's `__libc_start_main` → `__libc_start_init` iterates `[__init_array_start, __init_array_end)` calling each ctor; `exit` → `__libc_exit_fini` iterates `[__fini_array_start, __fini_array_end)` in reverse, plus the `__cxa_atexit` chain.

**Ordering**: ctors run in definition order within a TU; dtors run in reverse order (LIFO), interleaved with `__cxa_atexit`-registered dtors. Cross-TU order follows link order (standard `ld` semantics, no guarantee).

### 5. Known LLVM BPF backend bugs (workarounds in this repo)

The BPF backend in upstream LLVM has several defects this project works around. The detailed mechanism for each is below (symptom → root cause → workaround → upstream issue). Other sections reference this one rather than repeating the details. (The 5-arg / no-FP / no-varargs limits in §1–2 are by-design architecture constraints, not bugs.)

- **Conditional branch into a zero-instruction successor → silent miscompile.** A conditional branch whose target lowers to zero instructions (an `unreachable` block, or a `barrier()`-only MBB that `MachineBlockPlacement` tail-duplicates with no terminator) gets an offset computed against that empty block's address, so it lands past the function end (or on the preceding instruction). Triggers in a ~13-instruction function; reproduces on clang 19/21/23 trunk; distinct from the 16-bit-offset overflow issues (#48509 etc.). **Hit by**: busybox `ash.c` `ash_main` (inlines `INT_ON`; the miscompiled branch forms an `exitreset`↔`INT_ON` loop → Ctrl+C exits the shell instead of returning to the prompt). **Workaround**: `scripts/build_busybox.sh` marks `popstackmark` `__attribute__((noinline))` (idempotent `perl` patch) so the trailing-barrier block is not inlined. **Upstream**: [#208984](https://github.com/llvm/llvm-project/issues/208984).

- **`-g` mangles member-function `declare`: `this` promoted to value, aggregate params lost ([#208141](https://github.com/llvm/llvm-project/issues/208141)).** With debug info, clang rewrites the `declare` of certain member functions so the `this` pointer becomes a value type and later by-value aggregate parameters disappear from the declaration, while the `call` keeps the right arg count → declare/call mismatch (clang 19/20 miscompile, 21/22 crash). Manifests on libc++ `<filesystem>` (`path::__compare(string_view)`). **Status**: no workaround in this repo currently needed — `test/test_stl_filesystem.cpp` compiles cleanly on clang 19 with `-g` (the trigger path is narrow); revisit if the test starts hitting the miscompiled `path` comparison. **Upstream**: [#208141](https://github.com/llvm/llvm-project/issues/208141), OPEN.

- **≤8B by-value non-trivially-destructible parameters double-free ([#207686](https://github.com/llvm/llvm-project/issues/207686)).** The BPF backend lowers a ≤8B non-trivially-destructible by-value parameter (e.g. `std::unique_ptr`, 8B) directly to `i64`, bypassing byval; clang's caller still emits a backup temporary and destroys it after the call, but the callee (receiving the value, not a pointer) can't null the temp → double-free. Silent. **Workaround**: `BpfByvalTmpPass` in `src/passes/BpfWideArgs.cpp` (runs at OptimizerLastEP) inserts `store null, %tmp` before the destructor of identified backup temporaries (≤8B, has a load, C++ dtor/reset call shape). Detailed mechanism in the pass comments. **Upstream**: [#207686](https://github.com/llvm/llvm-project/issues/207686), OPEN.

- **`binutils-bpf` `bpf-ld` `.rodata.str1.1` merge bug (Debian [#1126689](https://bugs.debian.org/1126689)).** The historical `bpf-ld` mis-merged `.rodata.str1.1`, corrupting string constants. **Workaround**: this project ships its own linker `bpfvm-ld` (see "BPF Linker" above), fully replacing `bpf-ld`; the bug is no longer reachable. No source-level patch needed.

## Default C Library (musl) & Optional PDCLib

The default C library for BPF targets is **musl** (`musl/`). Build it with `sh musl/build.sh`; the `libc` symlink at the project root points to `musl/build/install`, so `-Ilibc/include` and `-Llibc/lib` resolve to musl's headers and `libc.a` (with crt merged in, containing `_start`).

### Building musl (default)
```bash
sh musl/build.sh          # → musl/build/install/{include,lib}
./scripts/build_root.sh           # also runs build_musl + synthesizes libc.so (= ld-bpf.so, single binary; see below)
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

The project ships a port of musl 1.2.6 as the **default** C library for the BPF target. Build with `sh musl/build.sh` — produces `musl/build/install/lib/libc.a` (with `crt1.o`/`crti.o`/`crtn.o` merged in, so it contains `_start`) + standalone `crt1.o`/`Scrt1.o`/`crti.o`/`crtn.o`, and headers in `musl/build/install/include/`. `test/Makefile` and `scripts/build_root.sh` build against this musl directly (static `.out` + dynamic `.linked`).

### musl build (`musl/build.sh`)
- **`--disable-shared`**: musl's `.so` is synthesized from `libc.a` by `bpfvm-ld -shared` (in `scripts/build_root.sh`'s `build_libc_bpfso`), not by musl's own build.
- **`-mllvm -bpf-stack-size=16384`**: musl's `crypt_blowfish` (`BF_crypt`) has ~8.5KB local structs; the default 4096 overflows.
- **rcrt1.o / crti.o / crtn.o / Scrt1.o skipped**: `make install` compiles `rcrt1.o` (static PIE self-start, depends on `dlstart` dynamic linker logic — BPF can't support it; `_start_c` signature mismatch + `GETFUNCSYM` has no forward decl) and fails. The script builds **only `crt1.o`** via per-target `make obj/crt/crt1.o`. The other crt objects are unnecessary on BPF: `crti.o`/`crtn.o` compile to empty `.o` (BPF has no `.init_array`/`.fini_array` framework), and `Scrt1.o` is identical to `crt1.o` on BPF (clang always emits relocations for address refs, so `-fPIC` doesn't change the output). Headers are copied manually to `install/include/` (generic/bits first, then bpf/bits so BPF-specific overrides win).
- **crt1 merged into libc.a**: BPF's `_start` lives in `crt1.o` (pure C, `arch/bpf/crt_arch.h`). The script runs `ar rcs lib/libc.a lib/crt1.o` so `libc.a` carries `_start` itself — like pdclib, linkers only pass `libc.a`/`libc.so` and need no separate crt files or ordering. `crt1.o` covers both static and PIE/.so modes (BPF `-fPIC` doesn't change crt1's output).
- **ldso objects (`dlstart.lo`/`dynlink.lo`) built separately; merged with libc into one binary**: standard musl puts ldso code (`ldso/dlstart.c`, `ldso/dynlink.c`) into `libc.so`, not `libc.a` (statically-linked programs don't need a dynamic linker). Since BPF's `libc.so` is synthesized from `libc.a` by `bpfvm-ld -shared` (not by musl's build), these objects would otherwise be lost. The script builds them via `make obj/ldso/dlstart.lo obj/ldso/dynlink.lo` and installs them alongside `libc.a`.
- **`libc.so` == `ld-bpf.so` (single binary, mirrors upstream musl `libc.so` == `ld.so`)**: the ldso must function before any other library is relocated, so the libc it depends on (`malloc`/`memcpy`/TLS setup/`__libc_start_main`/...) must be linked into it — it cannot import these from a separate `libc.so`. `scripts/build_root.sh`'s `build_libc_bpfso` therefore builds **one** binary from `libc.a + dlstart.lo + dynlink.lo`, `--soname libc.so`, entry `_dlstart` (`-e _dlstart`), output to `libc/lib/libc.so`. `root/lib/libc.so` and `root/lib/ld-bpf.so` are both symlinks to this single file. This is not wasteful duplication: at runtime `load_library("libc.so")` hits the `is_self` short-circuit in musl's ldso (`ldso.name` is hardcoded to `"libc.so"` in `__dls2`, and `"libc"` is in the reserved-name table), so a program's `DT_NEEDED libc.so` reuses the already-mapped ldso rather than opening the file — a separate on-disk `libc.so` would be dead weight. The single file serves three paths: link-time (`-l:libc.so` reads its dynsym + `DT_SONAME=libc.so`), `DT_NEEDED libc.so` (→ `is_self`), and `PT_INTERP=/lib/ld-bpf.so` (VM loader resolves `ld-bpf.so`, entry = `load_base + e_entry` → `_dlstart`). ldso does its own stage-1 self-relocation (`_dlstart_c` in `dlstart.c`); the VM loader only mmaps segments + sets up auxv.
- **install layout**: `install/{include,lib}` mirrors pdclib's layout so the project-root `libc` symlink abstracts the choice; `install/lib` holds `libc.a` (with crt1 merged), `crt1.o`, and the ldso objects `dlstart.lo`/`dynlink.lo`.

### Pass rebuild after `.so` changes
**musl (Make, default) and pdclib (CMake, optional) do NOT track `libBpfWideArgs.so`/`libBpfSoftFp.so` timestamp changes** — they only look at `.c` source mtimes. After modifying either pass, force a full rebuild:
- musl (default): `find musl/build/obj -name '*.o' -delete && sh musl/build.sh` (re-runs `make lib/libc.a` + crt + merge crt into libc.a + ldso objects + header/lib install), then `./scripts/build_root.sh` to regenerate the merged `libc.so` (= `ld-bpf.so`) and its `root/lib/` symlinks.
- pdclib (optional): `rm -rf pdclib/build`, then rebuild pdclib + `bpfvm-ld -shared` to regenerate `libc.so`.

Skipping this reuses stale `.o` compiled with the old pass (a past incident: deleting `__va_arg` left old `.o` still referencing it, causing `_va_arg` undefined at link).
