# patches/

Out-of-tree patches for upstream dependencies that this repo needs but cannot
fix in-tree. Each patch is a unified diff applicable with `patch -p1` (or
`git apply`) from the top of the upstream source tree.

## cpython-3.13.1-bpfvm.patch

**What**: CPython 3.13.1 的 bpfvm 移植 patch,11 个文件,每处均带
"bpfvm port" 注释:

- `Include/pyport.h` — `__BPF__` 分支:clang 拒绝 BPF 目标的全部 TLS 关键字,
  引用侧 TU 不定义 `_Py_thread_local`(`HAVE_THREAD_LOCAL` 被 undef),tstate
  经 `_PyThreadState_GetCurrent()` 回退读取;定义侧 pystate.c 由
  build_root.sh 的 Makefile 追加规则注入 `-Dthread_local=annotate("emutls")`
  + `-DBPFVM_EMUTLS_TSTATE` 走 emutls。
- `_PyArg_UnpackStack` 定参化(`pycore_modsupport.h`/`getargs.c`/
  `bltinmodule.c`)— 5 定参 + vararg 经 BpfWideArgs vararg 路径改写后达 6 个
  直传参数,超出 BPF 5 寄存器上限;改为显式双指针输出(p1 可 NULL)。
- `PyErr_WarnExplicitFormat` 定参化(`warnings.h`/`_warnings.c`)— 同上,
  单 long long 格式化参数。
- `Python/import.c` — 无 TLS 回退路径的锁原语修正(上游 bug:EXTENSIONS.mutex
  已是 PyMutex 仍调 PyThread_acquire_lock)。
- `Misc/platform_triplet.c` — `__BPF__` 分支 → `bpf-linux-musl`(否则
  `$CPP` 按 host 预处理误判 x86_64,perf trampoline 误开)。
- `Modules/selectmodule.c` — `__BPF__` 强制 `SELECT_USES_HEAP`:3 组
  `fd2obj[FD_SETSIZE+1]` 栈数组 ~49KB,超出 BPF st/ld 16 位帧偏移范围,LLVM
  会把越界负偏移回卷成正偏移(miscompile,见 bpfvm 仓库 AGENTS.md 的
  LLVM 已知 bug 清单);改走上游堆分配路径。
- `Python/pathconfig.c` — `_PyPathConfig_ComputeSysPath0` 的
  fullpath/link/path0copy 三缓冲(~64KB 栈帧,同一 16 位回卷 miscompile 的
  另一受害者)改为单块 `PyMem_RawMalloc` 堆分配,退出点统一释放。
- `Lib/ctypes/util.py` — `find_library` 追加 musl 式回退:guest 无
  ldconfig 缓存也无 gcc/ld,最后按 `/lib`/`/usr/local/lib`/`/usr/lib`
  glob `lib<name>.so*` 返回首个 soname(配合本项目 ffi-bpf 的 `_ctypes`)。

**Apply** (从解包后的源码根):

```sh
tar xf cpython-3.13.1.tar.gz && cd cpython-3.13.1
patch -p1 < /path/to/bpfvm/patches/cpython-3.13.1-bpfvm.patch
```

或由 `./scripts/build_root.sh python` 自动完成(build_python 检测 thirdparty/cpython/ 缺失时
git clone v3.13.1 并应用,幂等)。

**小版本更新(3.13.x)**:换新 tarball 重新解包,直接 `patch -p1` 重放;
上下文漂移导致 hunk 失败时按 "bpfvm port" 注释手工对齐(每处改动都很小
且局部),再从新旧干净源码树 diff 重新生成 patch:

```sh
diff -u pristine/Python/getargs.c thirdparty/cpython/Python/getargs.c | \
    sed '1s|.*|--- a/Python/getargs.c|;2s|.*|+++ b/Python/getargs.c|'
```

**Regenerate**: patch 由 11 个文件的 `diff -u`(干净 tarball 解包 vs
仓库 thirdparty/cpython/)拼合生成,排除 `__pycache__` 等构建噪声;文件清单见 patch 内
`--- a/` 行。

## gdb-bpf-ptr-bit.patch

**Fixes**: Two defects in GDB's BPF target (`gdb/bpf-tdep.c`):

1. **Register-cache assertion after `backtrace`.** GDB crashes with
   `raw_read: Assertion 'dst.size () == m_descr->sizeof_register[regnum]' failed`
   the first time the register cache is touched after a `backtrace` (e.g.
   `bt` then `info registers`).

   **Root cause**: `bpf_gdbarch_init` never calls `set_gdbarch_ptr_bit` /
   `set_gdbarch_long_bit` / `set_gdbarch_int_bit` (every other target does).
   With `ptr_bit` defaulting to 32, `bpf_register_type` returns
   `builtin_data_ptr` / `builtin_func_ptr` (4 bytes) for r10/pc, but frame
   unwinders read SP/PC with an 8-byte buffer → size mismatch → assertion.
   BPF is a 64-bit ISA (r0..r10 are all 64-bit), so these settings are simply
   missing.

2. **`bt` only shows frame #0** (no stack walk). **Root cause**: BPF's
   `bpf_frame_unwind` is a stub — `bpf_frame_this_id` is empty (defaults the
   frame to "outermost"), and `bpf_frame_unwind_stop_reason` returns
   `UNWIND_OUTERMOST`. `bpf_gdbarch_init` only registers this stub; it never
   calls `dwarf2_append_unwinders`, so the DWARF CFI unwinder (which reads
   `.debug_frame` synthesized by `bpfvm-ld`) is never consulted and backtrace
   never walks past the current frame. The patch adds
   `dwarf2_append_unwinders (gdbarch)` *before* the stub, so frames with CFI
   use the DWARF unwinder and frames without fall through to the stub.

3. **`catch syscall` rejected with "not supported on this architecture yet".**
   GDB gates the feature on `gdbarch_get_syscall_number_p()` in
   `catch_syscall_command` (break-catch-syscall.c); bpf-tdep never set the
   hook, so the feature was refused before the remote stub was ever queried —
   even though bpfvm's stub already advertises `QCatchSyscalls+` and reports
   `syscall_entry`/`syscall_return` stop reasons carrying the syscall number.
   The patch adds `bpf_get_syscall_number` and registers it. On the remote
   path GDB takes the syscall number from the stop reply, not from this hook,
   so the returned value (r1) is only a placeholder that satisfies the
   feature gate. A side fix sets
   `set_gdbarch_xml_syscall_file(gdbarch, "bpf-linux.xml")` (a nonexistent
   file): with a NULL xml file + the now-enabled syscall catch, GDB's
   `xml_fetch_content_from_file` opens the datadir as a file, `ftell` returns
   a bogus length, and it aborts with `std::length_error: cannot create
   std::vector larger than max_size`. A real-looking name makes `gdb_fopen`
   fail cleanly (file not found), and catch syscall works with numbers only
   (BPF uses its own `BPF_CALL_*` IDs, not Linux numbers, so no upstream
   XML applies anyway). Bpfvm's sysno in `catch syscall N` is
   `BPF_CALL_TO_ID(call)` (e.g. `BPF_SYS_clock_gettime` = 38).

**Applies to**: upstream GDB 16.3 (and HEAD as of 2026-07-25, commit 1fba9bb3 —
the bug has never been fixed). Applies cleanly via `patch -p1` from the gdb
source root.

**Build a patched GDB** (reusing the system gdb datadir + Python so no extra
files are needed beyond the binary):

```sh
apt source gdb=16.3-1          # or: tar xf gdb-16.3.orig.tar.xz
cd gdb-16.3
patch -p1 < /path/to/bpfvm/patches/gdb-bpf-ptr-bit.patch
CFLAGS="-O2" CXXFLAGS="-O2" ./configure \
    --disable-gdbserver --disable-sim --disable-werror \
    --with-gdb-datadir=/usr/share/gdb --with-python=/usr \
    --enable-targets=all
make -j"$(nproc)" all-gdb
# The binary is at gdb/gdb; copy it wherever you like.
```

Then use it to debug bpfvm programs:

```sh
bpfvm --gdb 12345 ./busybox/busybox.linked cat   # terminal 1
gdb/gdb                                          # terminal 2
(gdb) set architecture bpf
(gdb) file ./busybox/busybox.linked
(gdb) target remote 127.0.0.1:12345
```

Note: `bpfvm`'s RSP server sends a 96-byte `g` packet (r0..r10 + pc, all 8
bytes) matching this patched layout, so it requires the patched GDB — an
unpatched `gdb-multiarch` will reject the packet (`too long: expected 88, got
96`).

**Upstream status**: bug report pending on sourceware Bugzilla (product=gdb,
component=bpf). Link to be added here once filed.
