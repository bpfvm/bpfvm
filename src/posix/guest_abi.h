#ifndef POSIX_GUEST_ABI_H__
#define POSIX_GUEST_ABI_H__

// guest(asm-generic UAPI) fcntl 常量与宿主位布局互转。
//
// guest 程序的 O_* 值来自内核 asm-generic ABI（musl 的 arch/generic/bits/fcntl.h
// 转写，未加 arch/bpf 特化覆盖）。x86_64 宿主与 asm-generic 全同值；aarch64 宿主
// 上 O_DIRECT 与 O_DIRECTORY、O_LARGEFILE 与 O_NOFOLLOW 两对互换。guest 侧 flag
// 判断一律用 BPF_O_* 字面常量；进宿主 syscall 前经 guest_open_flags() 置换，宿主
// F_GETFL 结果经 host_fgetfl_to_guest() 反向置换，可置位 flag 子集（pipe2/F_SETFL）
// 经 guest_setfl_flags() 置换——其中只有 O_DIRECT 会错位。

#include <fcntl.h>

// —— guest(asm-generic) open flag 位布局互转（唯一存在错位的家族）——

static_assert(O_CREAT    == 00000100, "host O_CREAT must match asm-generic");
static_assert(O_EXCL     == 00000200, "host O_EXCL must match asm-generic");
static_assert(O_NOCTTY   == 00000400, "host O_NOCTTY must match asm-generic");
static_assert(O_TRUNC    == 00001000, "host O_TRUNC must match asm-generic");
static_assert(O_APPEND   == 00002000, "host O_APPEND must match asm-generic");
static_assert(O_NONBLOCK == 00004000, "host O_NONBLOCK must match asm-generic");
static_assert(O_DSYNC    == 00010000, "host O_DSYNC must match asm-generic");
static_assert(O_CLOEXEC  == 02000000, "host O_CLOEXEC must match asm-generic");
#ifdef O_ASYNC
static_assert(O_ASYNC    == 00020000, "host O_ASYNC must match asm-generic");
#endif
#ifdef O_NOATIME
static_assert(O_NOATIME  == 01000000, "host O_NOATIME must match asm-generic");
#endif

// guest(asm-generic) open(2) flag 值。与宿主宏同名的四位在 aarch64 上错位，
// 见文件头注释；其余与宿主同值。（BPF_ 前缀命名，全局作用域。）
inline constexpr unsigned BPF_O_RDONLY    = 00000000;
inline constexpr unsigned BPF_O_WRONLY    = 00000001;
inline constexpr unsigned BPF_O_RDWR      = 00000002;
inline constexpr unsigned BPF_O_CREAT     = 00000100;
inline constexpr unsigned BPF_O_EXCL      = 00000200;
inline constexpr unsigned BPF_O_NOCTTY    = 00000400;
inline constexpr unsigned BPF_O_TRUNC     = 00001000;
inline constexpr unsigned BPF_O_APPEND    = 00002000;
inline constexpr unsigned BPF_O_NONBLOCK  = 00004000;
inline constexpr unsigned BPF_O_DSYNC     = 00010000;
inline constexpr unsigned BPF_O_ASYNC     = 00020000;
inline constexpr unsigned BPF_O_DIRECT    = 00040000;
inline constexpr unsigned BPF_O_LARGEFILE = 00100000;
inline constexpr unsigned BPF_O_DIRECTORY = 00200000;
inline constexpr unsigned BPF_O_NOFOLLOW  = 00400000;
inline constexpr unsigned BPF_O_NOATIME   = 01000000;
inline constexpr unsigned BPF_O_CLOEXEC   = 02000000;

// guest open(2) flags -> 宿主位布局：错位四位置换（结果独立累加，错位位互换
// 也正确），O_LARGEFILE 仅剥不映射（64 位宿主本就默认 largefile）。
// x86_64 宿主上折叠为恒等。
inline int guest_open_flags(unsigned g) {
    unsigned h = g & ~(BPF_O_DIRECTORY | BPF_O_NOFOLLOW | BPF_O_DIRECT | BPF_O_LARGEFILE);
    if(g & BPF_O_DIRECTORY) h |= O_DIRECTORY;
    if(g & BPF_O_NOFOLLOW)  h |= O_NOFOLLOW;
    if(g & BPF_O_DIRECT)    h |= O_DIRECT;
    return static_cast<int>(h);
}

// 宿主 F_GETFL 返回值 -> guest 位布局（反向置换）。可回传的 flag 里
// O_DIRECTORY/O_NOFOLLOW/O_DIRECT 错位，host O_LARGEFILE 在 guest 无意义剥掉。
inline int host_fgetfl_to_guest(int rc) {
    unsigned g = static_cast<unsigned>(rc) & ~(O_DIRECTORY | O_NOFOLLOW | O_DIRECT);
#ifdef O_LARGEFILE
    g &= ~static_cast<unsigned>(O_LARGEFILE);
#endif
    if(rc & O_DIRECTORY) g |= BPF_O_DIRECTORY;
    if(rc & O_NOFOLLOW)  g |= BPF_O_NOFOLLOW;
    if(rc & O_DIRECT)    g |= BPF_O_DIRECT;
    return static_cast<int>(g);
}

// pipe2 / fcntl(F_SETFL) 可置位 flag 子集 guest -> 宿主：其中只有 O_DIRECT
// 会错位（aarch64），其余同值。
inline int guest_setfl_flags(unsigned g) {
    unsigned h = g & ~BPF_O_DIRECT;
    if(g & BPF_O_DIRECT) h |= O_DIRECT;
    return static_cast<int>(h);
}

#endif
