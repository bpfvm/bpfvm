//
// Created by chouryzhou on 24-11-1.
//

#ifndef BPF_CALL_H
#define BPF_CALL_H

#include <stdint.h>

#define BPF_CALL_BASE 0x10000u
#define BPF_CALL_ID(id) (BPF_CALL_BASE + (uint32_t)(id))
#define BPF_CALL_TO_ID(call) ((uint32_t)(call) - BPF_CALL_BASE)

enum bpf_syscall_id {
    BPF_SYS_MMAP = 1,
    BPF_SYS_MUNMAP,
    BPF_SYS_EXIT,
    BPF_SYS_OPENAT,
    BPF_SYS_READ,
    BPF_SYS_WRITE,
    BPF_SYS_LSEEK,
    BPF_SYS_CLOSE,
    BPF_SYS_UNLINKAT,
    BPF_SYS_RENAMEAT2,
    BPF_SYS_READLINKAT,
    BPF_SYS_EXECVE,
    BPF_SYS_CLONE,
    BPF_SYS_GETPID,
    BPF_SYS_GETPPID,
    BPF_SYS_WAITPID,
    BPF_SYS_KILL,
    BPF_SYS_SIGACTION,
    BPF_SYS_DUP3,
    BPF_SYS_PIPE2,
    BPF_SYS_FCHDIR,
    BPF_SYS_GETCWD,
    BPF_SYS_DUP,
    BPF_SYS_FCNTL,
    BPF_SYS_IOCTL,
    BPF_SYS_STATX,
    BPF_SYS_FCHMODAT,
    BPF_SYS_UTIMENSAT,
    BPF_SYS_FACCESSAT,
    BPF_SYS_UMASK,
    BPF_SYS_MKDIRAT,
    BPF_SYS_SYMLINKAT,
    BPF_SYS_LINKAT,
    BPF_SYS_SIGSETJMP,
    BPF_SYS_SIGLONGJMP,
    BPF_SYS_NANOSLEEP,
    BPF_SYS_CLOCK_GETTIME,
    BPF_SYS_TRUNCATE,
    BPF_SYS_FTRUNCATE,
    BPF_SYS_MPROTECT,       // mprotect(addr, len, prot)
    BPF_SYS_READV,          // readv(fd, iov, iovcnt)
    BPF_SYS_WRITEV,         // writev(fd, iov, iovcnt)
    BPF_SYS_PREAD,          // pread(fd, buf, count, off)
    BPF_SYS_PWRITE,         // pwrite(fd, buf, count, off)
    BPF_SYS_GETRANDOM,      // getrandom(buf, buflen, flags)
    BPF_SYS_GETDENTS64,     // 64 位目录项读取，musl readdir 走此路
    BPF_SYS_SET_TID_ADDRESS,// set_tid_address(tidptr) — 后续 futex/线程退出清零点
    BPF_SYS_EXIT_GROUP,     // 进程退出（无线程时等价于 exit）
    BPF_SYS_MADVISE,        // madvise — 不实现，返回 -ENOSYS
    BPF_SYS_SCHED_YIELD,    // sched_yield() — 让出执行（JIT 安全点）
    BPF_SYS_GETTID,         // gettid()
    BPF_SYS_SET_TLS,        // set_thread_area(tp) — 设置 thread pointer（musl __init_tp 启动必需）
    BPF_SYS_GET_TLS,        // 读取 thread pointer（guest __get_tp 用；单线程 TLS 模拟）
    BPF_SYS_SETPGID,        // setpgid(pid, pgrp)
    BPF_SYS_GETPGID,        // getpgid(pid)
    BPF_SYS_GETPGRP,        // getpgrp() == getpgid(0)
    BPF_SYS_SETSID,         // setsid()
    BPF_SYS_GETSID,         // getsid(pid)
    BPF_SYS_FUTEX,          // futex(uaddr, op, val, timeout, uaddr2) — 第 6 参 val3 走 r0
    BPF_SYS_TKILL,          // tkill(tid, sig)
    BPF_SYS_TGKILL,         // tgkill(tgid, tid, sig)
    BPF_SYS_SIGPROCMASK,    // rt_sigprocmask(how, set, old, sigsetsize)
    BPF_SYS_ALLOCA,         // alloca(inc) — 当前栈帧 alloca 区增量调整；返回调整后下界
    BPF_SYS_POLL,           // poll(pollfd*, nfds_t, int timeout_ms)
};

#define BPF_CALL_MMAP      BPF_CALL_ID(BPF_SYS_MMAP)
#define BPF_CALL_MUNMAP    BPF_CALL_ID(BPF_SYS_MUNMAP)
#define BPF_CALL_EXIT      BPF_CALL_ID(BPF_SYS_EXIT)
#define BPF_CALL_OPENAT    BPF_CALL_ID(BPF_SYS_OPENAT)
#define BPF_CALL_READ      BPF_CALL_ID(BPF_SYS_READ)
#define BPF_CALL_WRITE     BPF_CALL_ID(BPF_SYS_WRITE)
#define BPF_CALL_LSEEK     BPF_CALL_ID(BPF_SYS_LSEEK)
#define BPF_CALL_CLOSE     BPF_CALL_ID(BPF_SYS_CLOSE)
#define BPF_CALL_UNLINKAT  BPF_CALL_ID(BPF_SYS_UNLINKAT)
#define BPF_CALL_RENAMEAT2 BPF_CALL_ID(BPF_SYS_RENAMEAT2)
#define BPF_CALL_READLINKAT BPF_CALL_ID(BPF_SYS_READLINKAT)
#define BPF_CALL_EXECVE    BPF_CALL_ID(BPF_SYS_EXECVE)
#define BPF_CALL_KILL      BPF_CALL_ID(BPF_SYS_KILL)
#define BPF_CALL_SIGACTION BPF_CALL_ID(BPF_SYS_SIGACTION)
#define BPF_CALL_GETPID    BPF_CALL_ID(BPF_SYS_GETPID)
#define BPF_CALL_GETPPID   BPF_CALL_ID(BPF_SYS_GETPPID)
#define BPF_CALL_WAITPID   BPF_CALL_ID(BPF_SYS_WAITPID)
#define BPF_CALL_DUP3      BPF_CALL_ID(BPF_SYS_DUP3)
#define BPF_CALL_PIPE2     BPF_CALL_ID(BPF_SYS_PIPE2)
#define BPF_CALL_FCHDIR    BPF_CALL_ID(BPF_SYS_FCHDIR)
#define BPF_CALL_GETCWD    BPF_CALL_ID(BPF_SYS_GETCWD)
#define BPF_CALL_DUP       BPF_CALL_ID(BPF_SYS_DUP)
#define BPF_CALL_FCNTL     BPF_CALL_ID(BPF_SYS_FCNTL)
#define BPF_CALL_IOCTL     BPF_CALL_ID(BPF_SYS_IOCTL)
#define BPF_CALL_STATX     BPF_CALL_ID(BPF_SYS_STATX)
#define BPF_CALL_FCHMODAT  BPF_CALL_ID(BPF_SYS_FCHMODAT)
#define BPF_CALL_UTIMENSAT BPF_CALL_ID(BPF_SYS_UTIMENSAT)
#define BPF_CALL_FACCESSAT BPF_CALL_ID(BPF_SYS_FACCESSAT)
#define BPF_CALL_UMASK     BPF_CALL_ID(BPF_SYS_UMASK)
#define BPF_CALL_MKDIRAT   BPF_CALL_ID(BPF_SYS_MKDIRAT)
#define BPF_CALL_SYMLINKAT BPF_CALL_ID(BPF_SYS_SYMLINKAT)
#define BPF_CALL_LINKAT    BPF_CALL_ID(BPF_SYS_LINKAT)
#define BPF_CALL_SIGSETJMP  BPF_CALL_ID(BPF_SYS_SIGSETJMP)
#define BPF_CALL_SIGLONGJMP BPF_CALL_ID(BPF_SYS_SIGLONGJMP)
#define BPF_CALL_NANOSLEEP BPF_CALL_ID(BPF_SYS_NANOSLEEP)
#define BPF_CALL_CLOCK_GETTIME BPF_CALL_ID(BPF_SYS_CLOCK_GETTIME)
#define BPF_CALL_TRUNCATE  BPF_CALL_ID(BPF_SYS_TRUNCATE)
#define BPF_CALL_FTRUNCATE BPF_CALL_ID(BPF_SYS_FTRUNCATE)
#define BPF_CALL_MPROTECT  BPF_CALL_ID(BPF_SYS_MPROTECT)
#define BPF_CALL_READV     BPF_CALL_ID(BPF_SYS_READV)
#define BPF_CALL_WRITEV    BPF_CALL_ID(BPF_SYS_WRITEV)
#define BPF_CALL_PREAD     BPF_CALL_ID(BPF_SYS_PREAD)
#define BPF_CALL_PWRITE    BPF_CALL_ID(BPF_SYS_PWRITE)
#define BPF_CALL_GETRANDOM BPF_CALL_ID(BPF_SYS_GETRANDOM)
#define BPF_CALL_GETDENTS64 BPF_CALL_ID(BPF_SYS_GETDENTS64)
#define BPF_CALL_SET_TID_ADDRESS BPF_CALL_ID(BPF_SYS_SET_TID_ADDRESS)
#define BPF_CALL_EXIT_GROUP BPF_CALL_ID(BPF_SYS_EXIT_GROUP)
#define BPF_CALL_MADVISE   BPF_CALL_ID(BPF_SYS_MADVISE)
#define BPF_CALL_SCHED_YIELD BPF_CALL_ID(BPF_SYS_SCHED_YIELD)
#define BPF_CALL_GETTID    BPF_CALL_ID(BPF_SYS_GETTID)
#define BPF_CALL_SET_TLS   BPF_CALL_ID(BPF_SYS_SET_TLS)
#define BPF_CALL_GET_TLS   BPF_CALL_ID(BPF_SYS_GET_TLS)
#define BPF_CALL_SETPGID   BPF_CALL_ID(BPF_SYS_SETPGID)
#define BPF_CALL_GETPGID   BPF_CALL_ID(BPF_SYS_GETPGID)
#define BPF_CALL_GETPGRP   BPF_CALL_ID(BPF_SYS_GETPGRP)
#define BPF_CALL_SETSID    BPF_CALL_ID(BPF_SYS_SETSID)
#define BPF_CALL_GETSID    BPF_CALL_ID(BPF_SYS_GETSID)
#define BPF_CALL_CLONE     BPF_CALL_ID(BPF_SYS_CLONE)
#define BPF_CALL_FUTEX     BPF_CALL_ID(BPF_SYS_FUTEX)
#define BPF_CALL_TKILL     BPF_CALL_ID(BPF_SYS_TKILL)
#define BPF_CALL_TGKILL    BPF_CALL_ID(BPF_SYS_TGKILL)
#define BPF_CALL_SIGPROCMASK BPF_CALL_ID(BPF_SYS_SIGPROCMASK)
#define BPF_CALL_ALLOCA      BPF_CALL_ID(BPF_SYS_ALLOCA)
#define BPF_CALL_POLL        BPF_CALL_ID(BPF_SYS_POLL)

// ===========================================================================
// 虚拟浮点指令（src_reg=2）
// ===========================================================================
// BPF 无硬件浮点。本工程给每个浮点运算分配一个稳定编号，在 BPF 程序里编成一条
// `call <imm>`（src_reg=2）。FP 与 syscall 走不同的 src_reg，编号
// 解释器与 JIT 都把它当作一条自包含指令执行：r1/r2 是操作数的 IEEE754 位模式，
// 用宿主硬件浮点算出结果，位模式写回 r0——没有运行期函数调用、栈帧或 vm 状态搬运。
//   编码：BpfSoftFp pass（把浮点 IR 改成对 extern __ksym __bpf_fp_<ID> 的调用）→
//         bpfvm-ld（识别符号、改写 src_reg=2、imm=<ID>）→
//   执行：do_softfp（解释器 / JIT 回退）、emit_call_softfp（JIT 原生）。
enum bpf_fp_op {
    // 二元算术（i64 a, i64 b) -> i64
    BPF_FP_ADD_F = 1,   // float    a + b
    BPF_FP_SUB_F,       // float    a - b
    BPF_FP_MUL_F,       // float    a * b
    BPF_FP_DIV_F,       // float    a / b
    BPF_FP_ADD_D,       // double   a + b
    BPF_FP_SUB_D,       // double   a - b
    BPF_FP_MUL_D,       // double   a * b
    BPF_FP_DIV_D,       // double   a / b
    // 一元（i64 a) -> i64
    BPF_FP_NEG_F,       // float    -a
    BPF_FP_NEG_D,       // double   -a
    BPF_FP_SQRT_F,      // float    sqrt(a)
    BPF_FP_SQRT_D,      // double   sqrt(a)
    // fp -> int
    BPF_FP_F2SI,        // float  -> int32   (fixsfsi)
    BPF_FP_F2DI,        // float  -> int64   (fixsfdi)
    BPF_FP_F2USI,       // float  -> uint32  (fixunssfsi)
    BPF_FP_F2UDI,       // float  -> uint64  (fixunssfdi)
    BPF_FP_D2SI,        // double -> int32   (fixdfsi)
    BPF_FP_D2DI,        // double -> int64   (fixdfdi)
    BPF_FP_D2USI,       // double -> uint32  (fixunsdfsi)
    BPF_FP_D2UDI,       // double -> uint64  (fixunsdfdi)
    // int -> fp
    BPF_FP_SI2F,        // int32  -> float  (floatsisf)
    BPF_FP_DI2F,        // int64  -> float  (floatdisf)
    BPF_FP_USI2F,       // uint32 -> float  (floatunsisf)
    BPF_FP_UDI2F,       // uint64 -> float  (floatundisf)
    BPF_FP_SI2D,        // int32  -> double (floatsidf)
    BPF_FP_DI2D,        // int64  -> double (floatdidf)
    BPF_FP_USI2D,       // uint32 -> double (floatunsidf)
    BPF_FP_UDI2D,       // uint64 -> double (floatundidf)
    // 类型转换
    BPF_FP_EXTEND,      // float  -> double (extendsfdf2)
    BPF_FP_TRUNC,       // double -> float  (truncdfsf2)
    // 比较 (i64 a, i64 b) -> i64：负=小于,0=相等,正=大于；按 GCC 软浮点约定
    BPF_FP_CMP_F,       // float  比较（ltdf2 风格）
    BPF_FP_CMP_D,       // double 比较
    // 无序判定 (i64 a, i64 b) -> i64：任一操作数为 NaN 返回 1，否则 0（__unordXX2）。
    //   单一三态 CMP 丢失了 NaN 信息，无法区分"相等"与"NaN 无法比较"，故 oeq/ueq
    //   等谓词必须配合 UNORD 才能精确还原 IEEE754 比较（见 BpfSoftFp 的 fcmp 处理）。
    BPF_FP_UNORD_F,     // float  无序判定（__unordsf2）
    BPF_FP_UNORD_D,     // double 无序判定（__unorddf2）
};

#endif //BPF_CALL_H
