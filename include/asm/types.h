/* asm/types.h — BPF stub.
 * busybox 的 fix_u32.h 会 #include <asm/types.h> 与 <linux/types.h>，
 * 但本身在下方已有 __u32 等类型的 fallback 定义，因此这里只需提供
 * 一个空的、可安全重复包含的头文件即可。
 * 真正的类型由 fix_u32.h 末尾用 bb_hack_* 自行 typedef。 */
#ifndef _BPF_ASM_TYPES_H
#define _BPF_ASM_TYPES_H
#endif
