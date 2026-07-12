#ifndef SYS_EPOLL_H
#define SYS_EPOLL_H

// BPF arch 的 epoll uapi（与 Linux uapi 同级定位）。
//
// 仅放 BPF 特有类型：epoll_event 在 BPF arch 下是「非 packed 16B」布局（events 4B
// + 4B padding + data 8B），与 host x86_64（packed 12B）不同 → 这正是要单独定义、
// 且 VM 在 epoll_ctl/wait 时必须逐元素转换布局的根本原因。epoll_data_t 一并定义，
// 让 epoll_event 完全由本头自洽（host 与 musl 的 epoll_data_t 都是 8B 同布局 union，
// 但为了 uapi 自洽、避免对 host 头的隐式依赖，这里显式定义）。
//
// 常量（EPOLLIN/EPOLL_CTL_*/EPOLL_CLOEXEC 等）值与 arch 无关，由 host <sys/epoll.h>
// 提供，不在本头重复。

#include <stdint.h>

typedef union epoll_data {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

// BPF arch 布局：非 packed（16B）。显式 _pad 字段名带下划线避免误用。
struct epoll_event {
    uint32_t events;
    uint32_t _pad;
    epoll_data_t data;
};  // 16B

#ifndef BPF_NO_SYSCALL
// 与 include/signal.h 同一开关：host 侧（posix_internal.h 用 bpf:: 包裹时）
// #define BPF_NO_SYSCALL 跳过函数原型，只留类型定义。
int epoll_create(int);
int epoll_create1(int);
int epoll_ctl(int, int, int, struct epoll_event *);
int epoll_wait(int, struct epoll_event *, int, int);
// sigset_t 由 bpf/signal 侧提供；此处用 void* 占位，避免本头依赖 sigset_t 定义。
int epoll_pwait(int, struct epoll_event *, int, int, const void *);
#endif

#endif
