#ifndef FUTEX_H
#define FUTEX_H

/*
 * Linux futex(2) op 常量（UAPI 值）。VM 宿主（posix_syscall.cpp 的 do_futex）解析
 * guest 传入的 op；guest 程序也从此处获得常量——musl 把 FUTEX_* 放在内部头
 * (src/internal/futex.h，不随安装暴露)，guest 无法从公开头拿到，故在此补齐缺口。
 *
 * 数值与内核 <linux/futex.h>、musl 内部头一致。注意：内核 UAPI 的私有标志名为
 * FUTEX_PRIVATE_FLAG(128)，这里沿用 musl/本项目的 FUTEX_PRIVATE 命名，二者不冲突。
 * FUTEX2_PRIVATE 是新版 futex2 API 的同名常量（= FUTEX_PRIVATE_FLAG，内核 <linux/futex.h>
 * 定义），本项目 do_futex 用它剥离 op 的私有标志。
 *
 * #ifndef 守护避免与系统 <linux/futex.h>（若被引入）或 musl 内部头重复定义冲突。
 */
#ifndef FUTEX_WAIT
#define FUTEX_WAIT		0
#endif
#ifndef FUTEX_WAKE
#define FUTEX_WAKE		1
#endif
#ifndef FUTEX_REQUEUE
#define FUTEX_REQUEUE		3
#endif
#ifndef FUTEX_PRIVATE
#define FUTEX_PRIVATE		128
#endif
#ifndef FUTEX2_PRIVATE
#define FUTEX2_PRIVATE		FUTEX_PRIVATE
#endif

#endif
