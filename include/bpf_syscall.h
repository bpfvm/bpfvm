//
// bpf_syscall.h — BPF syscall ABI 编号（src_reg=0）
//

#ifndef BPF_SYSCALL_H
#define BPF_SYSCALL_H

#include <stdint.h>


// 新增 syscall：在下方 BPF_SYS_ 段与 BPF_CALL_ 段末尾各加一行同名条目（id 取下一
// 个连续值），两段同名的 NAME 一一对应。

#define BPF_SYS_MMAP             1   /* mmap(addr, len, prot, flags, fd, off) */
#define BPF_SYS_MUNMAP           2   /* munmap(addr, len) */
#define BPF_SYS_EXIT             3   /* exit(status) — 线程退出 */
#define BPF_SYS_OPENAT           4   /* openat(dirfd, path, flags, mode) — open() 复用 */
#define BPF_SYS_READ             5
#define BPF_SYS_WRITE            6
#define BPF_SYS_LSEEK            7
#define BPF_SYS_CLOSE            8
#define BPF_SYS_UNLINKAT         9
#define BPF_SYS_RENAMEAT2       10
#define BPF_SYS_READLINKAT      11
#define BPF_SYS_EXECVEAT        12  /* execveat(dirfd, path, argv, envp, flags) — fexecve 走 AT_EMPTY_PATH */
#define BPF_SYS_CLONE           13
#define BPF_SYS_GETPID          14
#define BPF_SYS_GETPPID         15
#define BPF_SYS_WAIT4           16
#define BPF_SYS_WAITID          17  /* waitid(idtype, id, siginfo*, options) — 独立 ABI，与 wait4 不兼容 */
#define BPF_SYS_KILL            18
#define BPF_SYS_SIGACTION       19
#define BPF_SYS_DUP3            20
#define BPF_SYS_PIPE2           21
#define BPF_SYS_FCHDIR          22
#define BPF_SYS_GETCWD          23
#define BPF_SYS_DUP             24
#define BPF_SYS_FCNTL           25
#define BPF_SYS_IOCTL           26
#define BPF_SYS_STATX           27
#define BPF_SYS_FCHMODAT        28
#define BPF_SYS_UTIMENSAT       29
#define BPF_SYS_FACCESSAT       30
#define BPF_SYS_UMASK           31
#define BPF_SYS_MKDIRAT         32
#define BPF_SYS_SYMLINKAT       33
#define BPF_SYS_LINKAT          34
#define BPF_SYS_SIGSETJMP       35
#define BPF_SYS_SIGLONGJMP      36
#define BPF_SYS_NANOSLEEP       37
#define BPF_SYS_CLOCK_GETTIME   38
#define BPF_SYS_TRUNCATE        39
#define BPF_SYS_FTRUNCATE       40
#define BPF_SYS_MPROTECT        41  /* mprotect(addr, len, prot) */
#define BPF_SYS_READV           42  /* readv(fd, iov, iovcnt) */
#define BPF_SYS_WRITEV          43  /* writev(fd, iov, iovcnt) */
#define BPF_SYS_PREAD           44  /* pread(fd, buf, count, off) */
#define BPF_SYS_PWRITE          45  /* pwrite(fd, buf, count, off) */
#define BPF_SYS_GETRANDOM       46  /* getrandom(buf, buflen, flags) */
#define BPF_SYS_GETDENTS64      47  /* 64 位目录项读取，musl readdir 走此路 */
#define BPF_SYS_SET_TID_ADDRESS 48  /* set_tid_address(tidptr) — 后续 futex/线程退出清零点 */
#define BPF_SYS_EXIT_GROUP      49  /* 进程退出（无线程时等价于 exit）*/
#define BPF_SYS_MADVISE         50  /* madvise — 不实现，返回 -ENOSYS */
#define BPF_SYS_SCHED_YIELD     51  /* sched_yield() — 让出执行（JIT 安全点）*/
#define BPF_SYS_GETTID          52
#define BPF_SYS_SET_TLS         53  /* set_thread_area(tp) — 设置 thread pointer（musl __init_tp 启动必需）*/
#define BPF_SYS_GET_TLS         54  /* 读取 thread pointer（guest __get_tp 用；单线程 TLS 模拟）*/
#define BPF_SYS_SETPGID         55  /* setpgid(pid, pgrp) */
#define BPF_SYS_GETPGID         56  /* getpgid(pid) */
#define BPF_SYS_GETPGRP         57  /* getpgrp() == getpgid(0) */
#define BPF_SYS_SETSID          58  /* setsid() */
#define BPF_SYS_GETSID          59  /* getsid(pid) */
#define BPF_SYS_FUTEX           60  /* futex(uaddr, op, val, timeout, uaddr2) — 第 6 参 val3 走 r0 */
#define BPF_SYS_TKILL           61  /* tkill(tid, sig) */
#define BPF_SYS_TGKILL          62  /* tgkill(tgid, tid, sig) */
#define BPF_SYS_SIGPROCMASK     63  /* rt_sigprocmask(how, set, old, sigsetsize) */
#define BPF_SYS_ALLOCA          64  /* alloca(inc) — 当前栈帧 alloca 区增量调整；返回调整后下界 */
#define BPF_SYS_POLL            65  /* poll(pollfd*, nfds_t, int timeout_ms) */
#define BPF_SYS_SOCKET          66  /* socket(domain, type, protocol) */
#define BPF_SYS_SOCKETPAIR      67  /* socketpair(domain, type, protocol, int sv[2]) */
#define BPF_SYS_BIND            68  /* bind(fd, sockaddr*, addrlen) */
#define BPF_SYS_LISTEN          69  /* listen(fd, backlog) */
#define BPF_SYS_CONNECT         70  /* connect(fd, sockaddr*, addrlen) */
#define BPF_SYS_ACCEPT4         71  /* accept4(fd, sockaddr*, socklen_t*, flags) — musl accept() 覆盖后也走此号 */
#define BPF_SYS_SENDTO          72  /* sendto(...) — send() 复用 */
#define BPF_SYS_RECVFROM        73  /* recvfrom(...) — recv() 复用 */
#define BPF_SYS_SENDMSG         74  /* sendmsg(fd, msghdr*, flags) — 含 SCM_RIGHTS fd 传递 */
#define BPF_SYS_RECVMSG         75  /* recvmsg(fd, msghdr*, flags) — 含 SCM_RIGHTS fd 接收 */
#define BPF_SYS_SHUTDOWN        76  /* shutdown(fd, how) */
#define BPF_SYS_SETSOCKOPT      77  /* setsockopt(fd, level, optname, optval, optlen) */
#define BPF_SYS_GETSOCKOPT      78  /* getsockopt(fd, level, optname, optval, socklen_t*) */
#define BPF_SYS_GETSOCKNAME     79  /* getsockname(fd, sockaddr*, socklen_t*) */
#define BPF_SYS_GETPEERNAME     80  /* getpeername(fd, sockaddr*, socklen_t*) */
#define BPF_SYS_EPOLL_CREATE1   81  /* epoll_create1(flags) — epoll_create() 复用 */
#define BPF_SYS_EPOLL_CTL       82  /* epoll_ctl(epfd, op, fd, epoll_event*) */
#define BPF_SYS_EPOLL_PWAIT     83  /* epoll_pwait(...) — epoll_wait() 复用；第 6 参 sigsetsize 走 r0 */
#define BPF_SYS_SIGNALFD4       84  /* signalfd4(fd, sigset*, sigsetsize, flags) — signalfd() 复用 */
#define BPF_SYS_PSELECT6        85  /* pselect6(n, fd_set* r, w, e, timespec* ts, sigmask_data*) — select() 复用 */
#define BPF_SYS_GETUID          86  /* getuid() — bpfvm 单用户 uid=0，供 OPENSSL_issetugid 等查询 */
#define BPF_SYS_GETEUID         87  /* geteuid() */
#define BPF_SYS_GETGID          88  /* getgid() */
#define BPF_SYS_GETEGID         89  /* getegid() */
#define BPF_SYS_GETGROUPS       90  /* getgroups(size, gid_t list[]) — bpfvm 无补充组，返回 0 */

#define BPF_CALL_BASE 0x10000u
#define BPF_CALL_ID(id) (BPF_CALL_BASE + (uint32_t)(id))
#define BPF_CALL_TO_ID(call) ((uint32_t)(call) - BPF_CALL_BASE)

// ===========================================================================
// 编码后的 call 立即数（= BPF_CALL_BASE + id），由 BPF_SYS_* 机械派生
// ===========================================================================
// 顺序与上方 BPF_SYS_ 段一致；NAME 一一对应。修改任一段时务必同步另一段。
#define BPF_CALL_MMAP             BPF_CALL_ID(BPF_SYS_MMAP)
#define BPF_CALL_MUNMAP           BPF_CALL_ID(BPF_SYS_MUNMAP)
#define BPF_CALL_EXIT             BPF_CALL_ID(BPF_SYS_EXIT)
#define BPF_CALL_OPENAT           BPF_CALL_ID(BPF_SYS_OPENAT)
#define BPF_CALL_READ             BPF_CALL_ID(BPF_SYS_READ)
#define BPF_CALL_WRITE            BPF_CALL_ID(BPF_SYS_WRITE)
#define BPF_CALL_LSEEK            BPF_CALL_ID(BPF_SYS_LSEEK)
#define BPF_CALL_CLOSE            BPF_CALL_ID(BPF_SYS_CLOSE)
#define BPF_CALL_UNLINKAT         BPF_CALL_ID(BPF_SYS_UNLINKAT)
#define BPF_CALL_RENAMEAT2        BPF_CALL_ID(BPF_SYS_RENAMEAT2)
#define BPF_CALL_READLINKAT       BPF_CALL_ID(BPF_SYS_READLINKAT)
#define BPF_CALL_EXECVEAT         BPF_CALL_ID(BPF_SYS_EXECVEAT)
#define BPF_CALL_CLONE            BPF_CALL_ID(BPF_SYS_CLONE)
#define BPF_CALL_GETPID           BPF_CALL_ID(BPF_SYS_GETPID)
#define BPF_CALL_GETPPID          BPF_CALL_ID(BPF_SYS_GETPPID)
#define BPF_CALL_WAIT4            BPF_CALL_ID(BPF_SYS_WAIT4)
#define BPF_CALL_WAITID           BPF_CALL_ID(BPF_SYS_WAITID)
#define BPF_CALL_KILL             BPF_CALL_ID(BPF_SYS_KILL)
#define BPF_CALL_SIGACTION        BPF_CALL_ID(BPF_SYS_SIGACTION)
#define BPF_CALL_DUP3             BPF_CALL_ID(BPF_SYS_DUP3)
#define BPF_CALL_PIPE2            BPF_CALL_ID(BPF_SYS_PIPE2)
#define BPF_CALL_FCHDIR           BPF_CALL_ID(BPF_SYS_FCHDIR)
#define BPF_CALL_GETCWD           BPF_CALL_ID(BPF_SYS_GETCWD)
#define BPF_CALL_DUP              BPF_CALL_ID(BPF_SYS_DUP)
#define BPF_CALL_FCNTL            BPF_CALL_ID(BPF_SYS_FCNTL)
#define BPF_CALL_IOCTL            BPF_CALL_ID(BPF_SYS_IOCTL)
#define BPF_CALL_STATX            BPF_CALL_ID(BPF_SYS_STATX)
#define BPF_CALL_FCHMODAT         BPF_CALL_ID(BPF_SYS_FCHMODAT)
#define BPF_CALL_UTIMENSAT        BPF_CALL_ID(BPF_SYS_UTIMENSAT)
#define BPF_CALL_FACCESSAT        BPF_CALL_ID(BPF_SYS_FACCESSAT)
#define BPF_CALL_UMASK            BPF_CALL_ID(BPF_SYS_UMASK)
#define BPF_CALL_MKDIRAT          BPF_CALL_ID(BPF_SYS_MKDIRAT)
#define BPF_CALL_SYMLINKAT        BPF_CALL_ID(BPF_SYS_SYMLINKAT)
#define BPF_CALL_LINKAT           BPF_CALL_ID(BPF_SYS_LINKAT)
#define BPF_CALL_SIGSETJMP        BPF_CALL_ID(BPF_SYS_SIGSETJMP)
#define BPF_CALL_SIGLONGJMP       BPF_CALL_ID(BPF_SYS_SIGLONGJMP)
#define BPF_CALL_NANOSLEEP        BPF_CALL_ID(BPF_SYS_NANOSLEEP)
#define BPF_CALL_CLOCK_GETTIME    BPF_CALL_ID(BPF_SYS_CLOCK_GETTIME)
#define BPF_CALL_TRUNCATE         BPF_CALL_ID(BPF_SYS_TRUNCATE)
#define BPF_CALL_FTRUNCATE        BPF_CALL_ID(BPF_SYS_FTRUNCATE)
#define BPF_CALL_MPROTECT         BPF_CALL_ID(BPF_SYS_MPROTECT)
#define BPF_CALL_READV            BPF_CALL_ID(BPF_SYS_READV)
#define BPF_CALL_WRITEV           BPF_CALL_ID(BPF_SYS_WRITEV)
#define BPF_CALL_PREAD            BPF_CALL_ID(BPF_SYS_PREAD)
#define BPF_CALL_PWRITE           BPF_CALL_ID(BPF_SYS_PWRITE)
#define BPF_CALL_GETRANDOM        BPF_CALL_ID(BPF_SYS_GETRANDOM)
#define BPF_CALL_GETDENTS64       BPF_CALL_ID(BPF_SYS_GETDENTS64)
#define BPF_CALL_SET_TID_ADDRESS  BPF_CALL_ID(BPF_SYS_SET_TID_ADDRESS)
#define BPF_CALL_EXIT_GROUP       BPF_CALL_ID(BPF_SYS_EXIT_GROUP)
#define BPF_CALL_MADVISE          BPF_CALL_ID(BPF_SYS_MADVISE)
#define BPF_CALL_SCHED_YIELD      BPF_CALL_ID(BPF_SYS_SCHED_YIELD)
#define BPF_CALL_GETTID           BPF_CALL_ID(BPF_SYS_GETTID)
#define BPF_CALL_SET_TLS          BPF_CALL_ID(BPF_SYS_SET_TLS)
#define BPF_CALL_GET_TLS          BPF_CALL_ID(BPF_SYS_GET_TLS)
#define BPF_CALL_SETPGID          BPF_CALL_ID(BPF_SYS_SETPGID)
#define BPF_CALL_GETPGID          BPF_CALL_ID(BPF_SYS_GETPGID)
#define BPF_CALL_GETPGRP          BPF_CALL_ID(BPF_SYS_GETPGRP)
#define BPF_CALL_SETSID           BPF_CALL_ID(BPF_SYS_SETSID)
#define BPF_CALL_GETSID           BPF_CALL_ID(BPF_SYS_GETSID)
#define BPF_CALL_FUTEX            BPF_CALL_ID(BPF_SYS_FUTEX)
#define BPF_CALL_TKILL            BPF_CALL_ID(BPF_SYS_TKILL)
#define BPF_CALL_TGKILL           BPF_CALL_ID(BPF_SYS_TGKILL)
#define BPF_CALL_SIGPROCMASK      BPF_CALL_ID(BPF_SYS_SIGPROCMASK)
#define BPF_CALL_ALLOCA           BPF_CALL_ID(BPF_SYS_ALLOCA)
#define BPF_CALL_POLL             BPF_CALL_ID(BPF_SYS_POLL)
#define BPF_CALL_SOCKET           BPF_CALL_ID(BPF_SYS_SOCKET)
#define BPF_CALL_SOCKETPAIR       BPF_CALL_ID(BPF_SYS_SOCKETPAIR)
#define BPF_CALL_BIND             BPF_CALL_ID(BPF_SYS_BIND)
#define BPF_CALL_LISTEN           BPF_CALL_ID(BPF_SYS_LISTEN)
#define BPF_CALL_CONNECT          BPF_CALL_ID(BPF_SYS_CONNECT)
#define BPF_CALL_ACCEPT4          BPF_CALL_ID(BPF_SYS_ACCEPT4)
#define BPF_CALL_SENDTO           BPF_CALL_ID(BPF_SYS_SENDTO)
#define BPF_CALL_RECVFROM         BPF_CALL_ID(BPF_SYS_RECVFROM)
#define BPF_CALL_SENDMSG          BPF_CALL_ID(BPF_SYS_SENDMSG)
#define BPF_CALL_RECVMSG          BPF_CALL_ID(BPF_SYS_RECVMSG)
#define BPF_CALL_SHUTDOWN         BPF_CALL_ID(BPF_SYS_SHUTDOWN)
#define BPF_CALL_SETSOCKOPT       BPF_CALL_ID(BPF_SYS_SETSOCKOPT)
#define BPF_CALL_GETSOCKOPT       BPF_CALL_ID(BPF_SYS_GETSOCKOPT)
#define BPF_CALL_GETSOCKNAME      BPF_CALL_ID(BPF_SYS_GETSOCKNAME)
#define BPF_CALL_GETPEERNAME      BPF_CALL_ID(BPF_SYS_GETPEERNAME)
#define BPF_CALL_EPOLL_CREATE1    BPF_CALL_ID(BPF_SYS_EPOLL_CREATE1)
#define BPF_CALL_EPOLL_CTL        BPF_CALL_ID(BPF_SYS_EPOLL_CTL)
#define BPF_CALL_EPOLL_PWAIT      BPF_CALL_ID(BPF_SYS_EPOLL_PWAIT)
#define BPF_CALL_SIGNALFD4        BPF_CALL_ID(BPF_SYS_SIGNALFD4)
#define BPF_CALL_GETUID           BPF_CALL_ID(BPF_SYS_GETUID)
#define BPF_CALL_GETEUID          BPF_CALL_ID(BPF_SYS_GETEUID)
#define BPF_CALL_GETGID           BPF_CALL_ID(BPF_SYS_GETGID)
#define BPF_CALL_GETEGID          BPF_CALL_ID(BPF_SYS_GETEGID)
#define BPF_CALL_GETGROUPS        BPF_CALL_ID(BPF_SYS_GETGROUPS)
#define BPF_CALL_PSELECT6         BPF_CALL_ID(BPF_SYS_PSELECT6)

#endif //BPF_SYSCALL_H
