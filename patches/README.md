# patches/

Out-of-tree patches for upstream dependencies that this repo needs but cannot
fix in-tree. Each patch is a unified diff applicable with `patch -p1` (or
`git apply`) from the top of the upstream source tree.

## gdb-bpf-ptr-bit.patch

**Fixes**: GDB's BPF target crashes with an internal assertion
`raw_read: Assertion 'dst.size () == m_descr->sizeof_register[regnum]' failed`
the first time the register cache is touched after a `backtrace` (e.g.
`bt` then `info registers`).

**Root cause**: `gdb/bpf-tdep.c`'s `bpf_gdbarch_init` never calls
`set_gdbarch_ptr_bit` / `set_gdbarch_long_bit` / `set_gdbarch_int_bit`
(every other target does). With `ptr_bit` defaulting to 32,
`bpf_register_type` returns `builtin_data_ptr` / `builtin_func_ptr` (4 bytes)
for r10/pc, but frame unwinders read SP/PC with an 8-byte buffer → size
mismatch → assertion. BPF is a 64-bit ISA (r0..r10 are all 64-bit), so these
settings are simply missing.

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
