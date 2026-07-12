#ifndef SIGNAL_H
#define SIGNAL_H

#include <stdint.h>
#include <sys/types.h>

#ifndef SIGHUP
#define SIGHUP 1
#endif
#ifndef SIGINT
#define SIGINT 2
#endif
#ifndef SIGQUIT
#define SIGQUIT 3
#endif
#ifndef SIGILL
#define SIGILL 4
#endif
#ifndef SIGBUS
#define SIGBUS 7
#endif
#ifndef SIGABRT
#define SIGABRT 6
#endif
#ifndef SIGFPE
#define SIGFPE 8
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef SIGSEGV
#define SIGSEGV 11
#endif
#ifndef SIGPIPE
#define SIGPIPE 13
#endif
#ifndef SIGUSR1
#define SIGUSR1 10
#endif
#ifndef SIGUSR2
#define SIGUSR2 12
#endif
#ifndef SIGTERM
#define SIGTERM 15
#endif
#ifndef SIGALRM
#define SIGALRM 14
#endif
#ifndef SIGCHLD
#define SIGCHLD 17
#endif
#ifndef SIGCONT
#define SIGCONT 18
#endif
#ifndef SIGSTOP
#define SIGSTOP 19
#endif
#ifndef SIGTSTP
#define SIGTSTP 20
#endif
#ifndef SIGTTIN
#define SIGTTIN 21
#endif
#ifndef SIGTTOU
#define SIGTTOU 22
#endif
#ifndef SIGURG
#define SIGURG 23
#endif
#ifndef NSIG
#define NSIG 32
#endif

#ifndef SIG_DFL
#define SIG_DFL (void (*)(int))0
#endif
#ifndef SIG_ERR
#define SIG_ERR (void (*)(int))-1
#endif
#ifndef SIG_IGN
#define SIG_IGN (void (*)(int))1
#endif

typedef int sig_atomic_t;

// sigaction 内核布局（rt_sigaction syscall 契约）。guest（musl）经 __libc_sigaction
// 把用户态 struct sigaction 转成本布局（musl/arch/bpf/ksigaction.h，复制自 x86_64）
// 再调 syscall，VM 的 do_sigaction 按此布局解析 guest 内存。
//   offset 0  handler  (8B)
//   offset 8  flags    (8B)
//   offset 16 restorer (8B)
//   offset 24 mask     (8B)
// 注：mask 用 uint64_t（VM 侧）；musl 端是 unsigned mask[2]（2×4B），二者二进制兼容
// （总大小均 32B）。
struct sigaction {
    uint64_t handler;
    uint64_t flags;
    uint64_t restorer;
    uint64_t mask;
};

#ifndef SIG_SETMASK
#define SIG_SETMASK 2
#endif

#endif
