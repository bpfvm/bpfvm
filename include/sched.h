#ifndef SCHED_H
#define SCHED_H

#include <sys/types.h>

#ifndef BPF_NO_SYSCALL
int sched_yield(void);
#endif

/*
 * Linux clone(2) flags（UAPI 常量）。与内核 <linux/sched.h>、glibc/musl 的 <sched.h>
 * 同值。这里作为 VM 宿主与 BPF guest 的共享权威定义：VM（posix_syscall.cpp）解析
 * guest 传入的 clone flags，guest 程序（非 musl 时）也从此处获得常量。
 *
 * 每个 #ifndef 守护避免与系统 <sched.h>（glibc 在 _GNU_SOURCE 下、musl 在 _GNU_SOURCE 下
 * 均定义）及 musl 自带 sched.h 重复定义冲突——三者数值完全一致，#ifndef 让先定义者生效。
 */
#ifdef _GNU_SOURCE
#ifndef CLONE_VM
#define CLONE_VM		0x00000100
#endif
#ifndef CLONE_FS
#define CLONE_FS		0x00000200
#endif
#ifndef CLONE_FILES
#define CLONE_FILES		0x00000400
#endif
#ifndef CLONE_SIGHAND
#define CLONE_SIGHAND		0x00000800
#endif
#ifndef CLONE_THREAD
#define CLONE_THREAD		0x00010000
#endif
#ifndef CLONE_SETTLS
#define CLONE_SETTLS		0x00080000
#endif
#ifndef CLONE_PARENT_SETTID
#define CLONE_PARENT_SETTID	0x00100000
#endif
#ifndef CLONE_CHILD_CLEARTID
#define CLONE_CHILD_CLEARTID	0x00200000
#endif
#ifndef CLONE_CHILD_SETTID
#define CLONE_CHILD_SETTID	0x01000000
#endif
#endif /* _GNU_SOURCE */

#endif
