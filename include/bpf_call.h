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
    BPF_SYS_RENAMEAT,
    BPF_SYS_READLINK,
    BPF_SYS_EXECVE,
    BPF_SYS_FORK,
    BPF_SYS_GETPID,
    BPF_SYS_GETPPID,
    BPF_SYS_WAITPID,
    BPF_SYS_KILL,
    BPF_SYS_SIGACTION,
    BPF_SYS_DUP2,
    BPF_SYS_PIPE2,
    BPF_SYS_FCHDIR,
    BPF_SYS_GETCWD,
    BPF_SYS_DUP,
    BPF_SYS_FCNTL,
    BPF_SYS_IOCTL,
    BPF_SYS_FSTATAT,
    BPF_SYS_FCHMODAT,
    BPF_SYS_UTIMENSAT,
    BPF_SYS_FACCESSAT,
    BPF_SYS_UMASK,
    BPF_SYS_MKDIR,
    BPF_SYS_RMDIR,
    BPF_SYS_SYMLINKAT,
    BPF_SYS_LINKAT,
    BPF_SYS_SETJMP,
    BPF_SYS_LONGJMP,
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

    /* —— 虚拟浮点指令：每个浮点运算一条 `call <imm>`（src_reg=0）——
       BPF 无硬件浮点。本工程给每个浮点运算分配一个稳定编号（BPF_CALL_FP_*），
       在 BPF 程序里编成一条 syscall 形式的 call。解释器与 JIT 都把它当作一条
       自包含指令执行：r1/r2 是操作数的 IEEE754 位模式，用宿主硬件浮点算出
       结果，位模式写回 r0——没有运行期函数调用、栈帧或 vm 状态搬运。
         编码：BpfSoftFp pass（把浮点 IR 改成这条 call）
         执行：do_softfp（解释器 / JIT 回退）、emit_call_softfp（JIT 原生） */
    BPF_SYS_FP_BASE = 0x1000,
    // 二元算术（i64 a, i64 b) -> i64
    BPF_SYS_FP_ADD_F = 0x1000,   // float    a + b
    BPF_SYS_FP_SUB_F,            // float    a - b
    BPF_SYS_FP_MUL_F,            // float    a * b
    BPF_SYS_FP_DIV_F,            // float    a / b
    BPF_SYS_FP_ADD_D,            // double   a + b
    BPF_SYS_FP_SUB_D,            // double   a - b
    BPF_SYS_FP_MUL_D,            // double   a * b
    BPF_SYS_FP_DIV_D,            // double   a / b
    // 一元（i64 a) -> i64
    BPF_SYS_FP_NEG_F,            // float    -a
    BPF_SYS_FP_NEG_D,            // double   -a
    BPF_SYS_FP_SQRT_F,           // float    sqrt(a)
    BPF_SYS_FP_SQRT_D,           // double   sqrt(a)
    // fp -> int
    BPF_SYS_FP_F2SI,             // float  -> int32   (fixsfsi)
    BPF_SYS_FP_F2DI,             // float  -> int64   (fixsfdi)
    BPF_SYS_FP_F2USI,            // float  -> uint32  (fixunssfsi)
    BPF_SYS_FP_F2UDI,            // float  -> uint64  (fixunssfdi)
    BPF_SYS_FP_D2SI,             // double -> int32   (fixdfsi)
    BPF_SYS_FP_D2DI,             // double -> int64   (fixdfdi)
    BPF_SYS_FP_D2USI,            // double -> uint32  (fixunsdfsi)
    BPF_SYS_FP_D2UDI,            // double -> uint64  (fixunsdfdi)
    // int -> fp
    BPF_SYS_FP_SI2F,             // int32  -> float  (floatsisf)
    BPF_SYS_FP_DI2F,             // int64  -> float  (floatdisf)
    BPF_SYS_FP_USI2F,            // uint32 -> float  (floatunsisf)
    BPF_SYS_FP_UDI2F,            // uint64 -> float  (floatundisf)
    BPF_SYS_FP_SI2D,             // int32  -> double (floatsidf)
    BPF_SYS_FP_DI2D,             // int64  -> double (floatdidf)
    BPF_SYS_FP_USI2D,            // uint32 -> double (floatunsidf)
    BPF_SYS_FP_UDI2D,            // uint64 -> double (floatundidf)
    // 类型转换
    BPF_SYS_FP_EXTEND,           // float  -> double (extendsfdf2)
    BPF_SYS_FP_TRUNC,            // double -> float  (truncdfsf2)
    // 比较 (i64 a, i64 b) -> i64：负=小于,0=相等,正=大于；按 GCC 软浮点约定
    BPF_SYS_FP_CMP_F,            // float  比较（ltdf2 风格）
    BPF_SYS_FP_CMP_D,            // double 比较
    // 无序判定 (i64 a, i64 b) -> i64：任一操作数为 NaN 返回 1，否则 0（__unordXX2）。
    //   单一三态 CMP 丢失了 NaN 信息，无法区分"相等"与"NaN 无法比较"，故 oeq/ueq
    //   等谓词必须配合 UNORD 才能精确还原 IEEE754 比较（见 BpfSoftFp 的 fcmp 处理）。
    BPF_SYS_FP_UNORD_F,          // float  无序判定（__unordsf2）
    BPF_SYS_FP_UNORD_D,          // double 无序判定（__unorddf2）
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
#define BPF_CALL_RENAMEAT  BPF_CALL_ID(BPF_SYS_RENAMEAT)
#define BPF_CALL_READLINK  BPF_CALL_ID(BPF_SYS_READLINK)
#define BPF_CALL_EXECVE    BPF_CALL_ID(BPF_SYS_EXECVE)
#define BPF_CALL_FORK      BPF_CALL_ID(BPF_SYS_FORK)
#define BPF_CALL_KILL      BPF_CALL_ID(BPF_SYS_KILL)
#define BPF_CALL_SIGACTION BPF_CALL_ID(BPF_SYS_SIGACTION)
#define BPF_CALL_GETPID    BPF_CALL_ID(BPF_SYS_GETPID)
#define BPF_CALL_GETPPID   BPF_CALL_ID(BPF_SYS_GETPPID)
#define BPF_CALL_WAITPID   BPF_CALL_ID(BPF_SYS_WAITPID)
#define BPF_CALL_DUP2      BPF_CALL_ID(BPF_SYS_DUP2)
#define BPF_CALL_PIPE2     BPF_CALL_ID(BPF_SYS_PIPE2)
#define BPF_CALL_FCHDIR    BPF_CALL_ID(BPF_SYS_FCHDIR)
#define BPF_CALL_GETCWD    BPF_CALL_ID(BPF_SYS_GETCWD)
#define BPF_CALL_DUP       BPF_CALL_ID(BPF_SYS_DUP)
#define BPF_CALL_FCNTL     BPF_CALL_ID(BPF_SYS_FCNTL)
#define BPF_CALL_IOCTL     BPF_CALL_ID(BPF_SYS_IOCTL)
#define BPF_CALL_FSTATAT   BPF_CALL_ID(BPF_SYS_FSTATAT)
#define BPF_CALL_FCHMODAT  BPF_CALL_ID(BPF_SYS_FCHMODAT)
#define BPF_CALL_UTIMENSAT BPF_CALL_ID(BPF_SYS_UTIMENSAT)
#define BPF_CALL_FACCESSAT BPF_CALL_ID(BPF_SYS_FACCESSAT)
#define BPF_CALL_UMASK     BPF_CALL_ID(BPF_SYS_UMASK)
#define BPF_CALL_MKDIR     BPF_CALL_ID(BPF_SYS_MKDIR)
#define BPF_CALL_RMDIR     BPF_CALL_ID(BPF_SYS_RMDIR)
#define BPF_CALL_SYMLINKAT BPF_CALL_ID(BPF_SYS_SYMLINKAT)
#define BPF_CALL_LINKAT    BPF_CALL_ID(BPF_SYS_LINKAT)
#define BPF_CALL_SETJMP    BPF_CALL_ID(BPF_SYS_SETJMP)
#define BPF_CALL_LONGJMP   BPF_CALL_ID(BPF_SYS_LONGJMP)
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

// —— 虚拟浮点指令的 call 编号（与上方 BPF_SYS_FP_* 一一对应）——
#define BPF_CALL_FP_ADD_F  BPF_CALL_ID(BPF_SYS_FP_ADD_F)
#define BPF_CALL_FP_SUB_F  BPF_CALL_ID(BPF_SYS_FP_SUB_F)
#define BPF_CALL_FP_MUL_F  BPF_CALL_ID(BPF_SYS_FP_MUL_F)
#define BPF_CALL_FP_DIV_F  BPF_CALL_ID(BPF_SYS_FP_DIV_F)
#define BPF_CALL_FP_ADD_D  BPF_CALL_ID(BPF_SYS_FP_ADD_D)
#define BPF_CALL_FP_SUB_D  BPF_CALL_ID(BPF_SYS_FP_SUB_D)
#define BPF_CALL_FP_MUL_D  BPF_CALL_ID(BPF_SYS_FP_MUL_D)
#define BPF_CALL_FP_DIV_D  BPF_CALL_ID(BPF_SYS_FP_DIV_D)
#define BPF_CALL_FP_NEG_F  BPF_CALL_ID(BPF_SYS_FP_NEG_F)
#define BPF_CALL_FP_NEG_D  BPF_CALL_ID(BPF_SYS_FP_NEG_D)
#define BPF_CALL_FP_SQRT_F BPF_CALL_ID(BPF_SYS_FP_SQRT_F)
#define BPF_CALL_FP_SQRT_D BPF_CALL_ID(BPF_SYS_FP_SQRT_D)
#define BPF_CALL_FP_F2SI   BPF_CALL_ID(BPF_SYS_FP_F2SI)
#define BPF_CALL_FP_F2DI   BPF_CALL_ID(BPF_SYS_FP_F2DI)
#define BPF_CALL_FP_F2USI  BPF_CALL_ID(BPF_SYS_FP_F2USI)
#define BPF_CALL_FP_F2UDI  BPF_CALL_ID(BPF_SYS_FP_F2UDI)
#define BPF_CALL_FP_D2SI   BPF_CALL_ID(BPF_SYS_FP_D2SI)
#define BPF_CALL_FP_D2DI   BPF_CALL_ID(BPF_SYS_FP_D2DI)
#define BPF_CALL_FP_D2USI  BPF_CALL_ID(BPF_SYS_FP_D2USI)
#define BPF_CALL_FP_D2UDI  BPF_CALL_ID(BPF_SYS_FP_D2UDI)
#define BPF_CALL_FP_SI2F   BPF_CALL_ID(BPF_SYS_FP_SI2F)
#define BPF_CALL_FP_DI2F   BPF_CALL_ID(BPF_SYS_FP_DI2F)
#define BPF_CALL_FP_USI2F  BPF_CALL_ID(BPF_SYS_FP_USI2F)
#define BPF_CALL_FP_UDI2F  BPF_CALL_ID(BPF_SYS_FP_UDI2F)
#define BPF_CALL_FP_SI2D   BPF_CALL_ID(BPF_SYS_FP_SI2D)
#define BPF_CALL_FP_DI2D   BPF_CALL_ID(BPF_SYS_FP_DI2D)
#define BPF_CALL_FP_USI2D  BPF_CALL_ID(BPF_SYS_FP_USI2D)
#define BPF_CALL_FP_UDI2D  BPF_CALL_ID(BPF_SYS_FP_UDI2D)
#define BPF_CALL_FP_EXTEND BPF_CALL_ID(BPF_SYS_FP_EXTEND)
#define BPF_CALL_FP_TRUNC  BPF_CALL_ID(BPF_SYS_FP_TRUNC)
#define BPF_CALL_FP_CMP_F  BPF_CALL_ID(BPF_SYS_FP_CMP_F)
#define BPF_CALL_FP_CMP_D  BPF_CALL_ID(BPF_SYS_FP_CMP_D)
#define BPF_CALL_FP_UNORD_F BPF_CALL_ID(BPF_SYS_FP_UNORD_F)
#define BPF_CALL_FP_UNORD_D BPF_CALL_ID(BPF_SYS_FP_UNORD_D)

#endif //BPF_CALL_H
