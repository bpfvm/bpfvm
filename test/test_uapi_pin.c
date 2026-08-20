/* guest 侧（musl arch/generic/bits 对 asm-generic ABI 的转写）
 * 与宿主侧（glibc）的常量钉在字面值上，升级 musl 或宿主 glibc 时若转写/取值
 * 漂移，在编译期报错，而不是运行期静默错位。
 *
 * fcntl 家族：glibc 与 asm-generic 有值差（如 O_LARGEFILE
 * 在 glibc 为 0），不能两侧共用
 *
 * 通过标准：编译通过即全部生效（_Static_assert），运行直接退出 0。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sched.h>

#if defined(__BPF__)

/* —— fcntl：guest 链 —— */

/* 访问模式（musl 的 O_ACCMODE 含 O_SEARCH 语义，不钉） */
_Static_assert(O_RDONLY == 00000000, "asm-generic O_RDONLY");
_Static_assert(O_WRONLY == 00000001, "asm-generic O_WRONLY");
_Static_assert(O_RDWR   == 00000002, "asm-generic O_RDWR");

/* 创建/状态 flag：asm-generic 与 x86_64/aarch64 宿主同值 */
_Static_assert(O_CREAT    == 00000100, "asm-generic O_CREAT");
_Static_assert(O_EXCL     == 00000200, "asm-generic O_EXCL");
_Static_assert(O_NOCTTY   == 00000400, "asm-generic O_NOCTTY");
_Static_assert(O_TRUNC    == 00001000, "asm-generic O_TRUNC");
_Static_assert(O_APPEND   == 00002000, "asm-generic O_APPEND");
_Static_assert(O_NONBLOCK == 00004000, "asm-generic O_NONBLOCK");
_Static_assert(O_DSYNC    == 00010000, "asm-generic O_DSYNC");
_Static_assert(O_ASYNC    == 00020000, "asm-generic O_ASYNC");
_Static_assert(O_NOATIME  == 01000000, "asm-generic O_NOATIME");
_Static_assert(O_CLOEXEC  == 02000000, "asm-generic O_CLOEXEC");

/* 四个错位位：aarch64 宿主与 asm-generic 不同（VM 按此置换，见 guest_abi.h）*/
_Static_assert(O_DIRECT    == 00040000, "asm-generic O_DIRECT");
_Static_assert(O_LARGEFILE == 00100000, "asm-generic O_LARGEFILE");
_Static_assert(O_DIRECTORY == 00200000, "asm-generic O_DIRECTORY");
_Static_assert(O_NOFOLLOW  == 00400000, "asm-generic O_NOFOLLOW");

/* fcntl cmd：全架构统一，VM 直接用宿主宏 */
_Static_assert(F_GETLK  == 5, "asm-generic F_GETLK");
_Static_assert(F_SETLK  == 6, "asm-generic F_SETLK");
_Static_assert(F_SETLKW == 7, "asm-generic F_SETLKW");

/* struct stat：musl 回落 generic/bits/stat.h（内核新 64 位架构 aarch64/riscv64
 * 共用的 asm-generic 布局；nlink_t/blksize_t 均为 64 位）。stat 走 statx，
 * struct stat 纯 guest 内部结构，钉偏移防误改回 x86_64 布局或类型宽度漂移。 */
_Static_assert(sizeof(struct stat) == 144, "generic LP64 struct stat layout");
_Static_assert(offsetof(struct stat, st_mode) == 16, "generic stat st_mode");
_Static_assert(offsetof(struct stat, st_nlink) == 24, "generic stat st_nlink");
_Static_assert(offsetof(struct stat, st_rdev) == 40, "generic stat st_rdev");
_Static_assert(offsetof(struct stat, st_blksize) == 64, "generic stat st_blksize");
_Static_assert(offsetof(struct stat, st_blocks) == 80, "generic stat st_blocks");
_Static_assert(offsetof(struct stat, st_atim) == 88, "generic stat st_atim");
_Static_assert(offsetof(struct stat, __unused) == 136, "generic stat __unused");

#endif /* __BPF__ */

/* —— 两侧同值家族（musl == glibc == asm-generic 字面值）——
 * VM 用宿主宏直接比较/直传 guest 值所依赖的前提。 */

/* VM 按宿主 struct flock 布局读写 guest 内存（do_fcntl F_GETLK/F_SETLK），
 * 两侧 LP64 布局须一致 */
_Static_assert(sizeof(struct flock) == 32, "LP64 struct flock layout");

/* memory.cpp 直传 host mmap */
_Static_assert(MAP_PRIVATE == 0x02 && MAP_FIXED == 0x10 && MAP_ANONYMOUS == 0x20,
               "generic MAP_*");
_Static_assert(PROT_READ == 0x1 && PROT_WRITE == 0x2 && PROT_EXEC == 0x4,
               "generic PROT_*");

/* socket.cpp 比较 */
_Static_assert(SOCK_CLOEXEC == 02000000 && SOCK_NONBLOCK == 04000,
               "generic SOCK_*");
_Static_assert(EPOLL_CLOEXEC == 02000000, "generic EPOLL_CLOEXEC");

/* filesystem/fs/process 比较 */
_Static_assert(AT_FDCWD == -100 && AT_SYMLINK_NOFOLLOW == 0x100
                   && AT_EMPTY_PATH == 0x1000, "generic AT_*");
_Static_assert(CLONE_VM == 0x00000100 && CLONE_THREAD == 0x00010000,
               "generic CLONE_*");

/* process.cpp waitid 选项 */
_Static_assert(WNOHANG == 1 && WUNTRACED == 2 && WCONTINUED == 8
                   && WEXITED == 4 && WSTOPPED == 2 && WNOWAIT == 0x1000000,
               "generic wait options");

int main(void) {
    return 0;
}
