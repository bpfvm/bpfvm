/* linux/kd.h — BPF stub.
 * musl 的 <bits/kd.h> 仅 #include <linux/kd.h>；busybox 的 get_console.c
 * 等自己用 enum 定义了 KDGKBTYPE 等常量，不依赖本头内容。
 * 提供空文件让 #include 不报错即可。 */
#ifndef _BPF_LINUX_KD_H
#define _BPF_LINUX_KD_H
#endif
