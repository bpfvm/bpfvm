/* linux/vt.h — BPF stub。
 * musl 的 <bits/vt.h> 和 busybox init.c（#ifdef __linux__）会 #include <linux/vt.h>。
 * init.c 实际用的 VT_GETMODE/VT_ACTIVATE 等常量，运行时由 VM ioctl 处理；
 * 这里提供空的（init applet 第一阶段被禁用，其他引用者只 #include 不用内容）。
 * 若未来需要，可按需补 VT_* 常量。 */
#ifndef _BPF_LINUX_VT_H
#define _BPF_LINUX_VT_H
#endif
