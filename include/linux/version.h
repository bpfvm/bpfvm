/* linux/version.h — BPF stub。
 * busybox libbb/loop.c 用 LINUX_VERSION_CODE/KERNEL_VERSION 做 API 版本判断：
 *   >= 2.6 -> #include <linux/loop.h>（BPF 无此内核头）
 *   < 2.6  -> 自定义常量/struct（不依赖内核头，可独立编译）
 * 故刻意设成 2.4.x，让 loop.c 走 else 分支独立编译。运行时 loop 设备由
 * VM ioctl 处理，这里只决定编译期代码路径。 */
#ifndef _BPF_LINUX_VERSION_H
#define _BPF_LINUX_VERSION_H

#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
/* 2.4.0：让 #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) 为假，走 else */
#define LINUX_VERSION_CODE KERNEL_VERSION(2,4,0)

#endif
