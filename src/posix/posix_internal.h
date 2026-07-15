#ifndef POSIX_INTERNAL_H__
#define POSIX_INTERNAL_H__

// posix/ 内部共享头：仅被 posix/*.cpp 引用，不暴露给 main.cpp / insn_test.cpp。
// 承载所有拆出 .cpp 共用的 include 组与参数转换辅助函数，避免每个文件重复一大段。

#include "posix_syscall.h"
#include "include/bpf_call.h"

namespace bpf{
    #define BPF_NO_SYSCALL
#ifdef __unused
    #undef __unused
#endif
    #include "include/signal.h"
    #include "include/sys/epoll.h"
}

#include <errno.h>
#include <stdio.h>
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

// —— futex 子系统对外封装（实现在 futex.cpp）——
// g_futex_mutex / g_futex_table 是 futex.cpp 内部 file-static，不暴露；
// 仅通过下面两个函数 + PosixSyscall::futex_wait/futex_wake 访问。
// clear-child-tid 路径：持锁清零 *ctid（已由调用方 mmu_w 取得 host 指针），
// 再从 tid_address 的等待桶摘一个等待者唤醒。封装进 futex.cpp 是为了把 futex
// 表的访问集中在一处（fini 在 posix_syscall.cpp，看不到 futex.cpp 的 static 表）。
void futex_child_tid_clear(ThreadGroup* tg, int* ctid, uint64_t tid_address);

// —— procfs 虚拟文件系统（实现在 procfs.cpp）——
// open/readlink/statx 三类"按路径"操作经 ResolvePath→Path 虚方法统一入口（按 /proc|/dev|host 前缀分发），
// lookup 与节点类型（ProcFile/ProcDir/ProcLink）都是 procfs.cpp 的内部细节。
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
