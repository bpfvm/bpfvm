#ifndef POSIX_INTERNAL_H__
#define POSIX_INTERNAL_H__

// posix/ 内部共享头：仅被 posix/*.cpp 引用，不暴露给 main.cpp / insn_test.cpp。
// 承载所有拆出 .cpp 共用的 include 组与参数转换辅助函数，避免每个文件重复一大段。

#include "guest_abi.h"

#include "posix_syscall.h"
#include "include/bpf_syscall.h"

namespace bpf{

// guest 内核态 sigaction 布局（4 x 8B）：musl 经 __libc_sigaction 把用户态
// struct sigaction 转成此布局再调 syscall。mask 是单 u64，musl 侧为
// unsigned mask[2]，二进制兼容。
struct sigaction {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
};

// guest siginfo_t 镜像（musl include/signal.h，LP64 无 __SI_SWAP_ERRNO_CODE 布局，
// 共 128B）。只列出 VM 写入的成员，union 其余成员以 __reserved 占位锁总大小；
// si_value 与 SIGCHLD 的 si_status 在 @24 同偏移复用（musl __si_common.__second）。
struct guest_siginfo {
    int32_t si_signo;   // @0
    int32_t si_errno;   // @4
    int32_t si_code;    // @8
    int32_t __pad;      // @12：union 成员 8B 对齐的空隙
    int32_t si_pid;     // @16
    int32_t si_uid;     // @20
    union {
        uint64_t si_value;         // @24：kill 来源为 0
        struct {
            int32_t si_status;     // @24：SIGCHLD 有效
            int32_t __pad2;
            uint64_t si_utime;     // @32
            uint64_t si_stime;     // @40
        } sigchld;
    };
    uint8_t __reserved[128 - 48];
};

// guest ucontext_t 镜像（musl arch/bpf/bits/signal.h 自有形状，共 264B）。
// gregs[12] = r0..r10 + pc（REG_SP=10、REG_PC=11），无 FPU 上下文；uc_sigmask 是
// musl sigset_t（128B，低 8B 按 bit(sig-1) 编码，高 120B 恒 0）。SA_SIGINFO 投递
// 时 build_siginfo 在信号帧上构造本结构，sigreturn 按（可能被 handler 改写过的）
// gregs/uc_sigmask 恢复现场。与 musl 侧（arch/bpf/bits/signal.h 的注释约定）
// 由下方 static_assert 双向锁死，勿单边改动。
struct guest_ucontext {
    uint64_t uc_flags;
    uint64_t uc_link;
    struct {
        void* ss_sp;
        int32_t ss_flags;
        int32_t __pad;
        uint64_t ss_size;
    } uc_stack;
    uint64_t gregs[12];
    uint8_t uc_sigmask[128];
};

typedef union epoll_data {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

// guest epoll_event：musl 仅对 __x86_64__ packed，BPF 目标为自然对齐 16B。
// 显式 _pad 字段名带下划线避免误用。
struct epoll_event {
    uint32_t events;
    uint32_t _pad;
    epoll_data_t data;
};  // 16B

}

#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <memory>
#include <chrono>
#include <time.h>
#include <string.h>
#include <cstring>
#include <unistd.h>
#include <filesystem>
#include <signal.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <linux/futex.h>

#undef sa_handler
#undef sa_sigaction
// musl（嵌套构建 bpfvm-on-bpfvm 的宿主 libc）把 siginfo_t 的 union 成员定义为
// 宏，展开会破坏下方镜像结构体的 offsetof；下方 static_assert 需先剥掉。
#undef si_pid
#undef si_uid
#undef si_value
#undef si_status

// —— guest siginfo_t/ucontext_t 镜像布局锁（勿单边改动，见 struct 注释）——
static_assert(sizeof(bpf::guest_siginfo) == 128);
static_assert(sizeof(bpf::guest_ucontext) == 264);
static_assert(offsetof(bpf::guest_siginfo, si_pid) == 16);
static_assert(offsetof(bpf::guest_siginfo, si_value) == 24);
static_assert(offsetof(bpf::guest_siginfo, sigchld) == 24);
static_assert(offsetof(bpf::guest_ucontext, uc_stack) == 16);
static_assert(offsetof(bpf::guest_ucontext, gregs) == 40);
static_assert(offsetof(bpf::guest_ucontext, uc_sigmask) == 136);
// 与 insn.h 的 SA_SIGINFO 信号帧布局互锁：帧偏移增量须等于镜像结构大小。
static_assert(SIGINFO_FRAME_UC_OFF - SIGINFO_FRAME_SI_OFF == sizeof(bpf::guest_siginfo));
static_assert(SIGNAL_FRAME_SIGINFO_SIZE - SIGINFO_FRAME_UC_OFF == sizeof(bpf::guest_ucontext));

// —— futex 子系统对外封装（实现在 futex.cpp）——
// g_futex_mutex / g_futex_table 是 futex.cpp 内部 file-static，不暴露；
// 仅通过下面两个函数 + PosixSyscall::futex_wait/futex_wake 访问。
// clear-child-tid 路径：持锁清零 *ctid（已由调用方 mmu_w 取得 host 指针），
// 再从 tid_address 的等待桶摘一个等待者唤醒。封装进 futex.cpp 是为了把 futex
// 表的访问集中在一处（fini 在 posix_syscall.cpp，看不到 futex.cpp 的 static 表）。
void futex_child_tid_clear(ThreadGroup* tg, int* ctid, uint64_t tid_address);

// —— procfs 虚拟文件系统（实现在 procfs.cpp）——
// open/readlink/statx 三类"按路径"操作经 ResolvePath->Path 虚方法统一入口（按 /proc|/dev|host 前缀分发），
// lookup 与节点类型（FileGen/DirGen/LinkGen/NoneGen，经 Gen 包装）都是 procfs.cpp 的内部细节。
// 经 PosixSyscall 的 public 进程标识字段（pid/ppid/tg/...）与 *_of 静态转发读 vm 内部。
// comm = basename(path) 截断 15 字节（Linux TASK_COMM_LEN-1）。do_execveat / init 共用。
std::string make_comm(const std::string& path);

// 把 64 位寄存器实参按有符号/无符号/大小解释。各 do_* 普遍使用。
static inline int32_t arg_s32(uint64_t v) {
    return static_cast<int32_t>(v);
}

static inline uint32_t arg_u32(uint64_t v) {
    return static_cast<uint32_t>(v);
}

static inline size_t arg_size(uint64_t v) {
    return static_cast<size_t>(v);
}

static inline bool handler_is_default(uint64_t handler) {
    return handler == static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_DFL));
}
static inline bool handler_is_ignored(uint64_t handler) {
    return handler == static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_IGN));
}

#endif
