/* linux/types.h — BPF stub. 见 asm/types.h 的说明：fix_u32.h 自带
 * __u32 等的 fallback typedef，这里只需可安全包含即可。
 * vendored 的 asm-generic/fcntl.h（内核 uapi 原件）的 struct f_owner_ex/
 * flock/flock64 用 __kernel_* 类型名，LP64 下与 musl 的对应类型同宽。 */
#ifndef _BPF_LINUX_TYPES_H
#define _BPF_LINUX_TYPES_H

#include <asm-generic/types.h>
#include <asm-generic/posix_types.h>

#endif
