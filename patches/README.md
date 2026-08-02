# patches/

Out-of-tree patches for upstream dependencies that this repo needs but cannot
fix in-tree. Each patch is a unified diff applicable with `patch -p1` (or
`git apply`) from the top of the upstream source tree.

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
