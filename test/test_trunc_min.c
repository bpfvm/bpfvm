#include <stdio.h>
#include <stdint.h>

/* 测试1：经过 union 栈存取 */
__attribute__((noinline))
static uint64_t via_union(uint64_t v) {
    union { uint64_t i; } u;
    u.i = v;            /* 存栈 */
    u.i = u.i >> 4;     /* 读改存 */
    return u.i;         /* 读栈返回 */
}

/* 测试2：不经过栈，纯寄存器 */
__attribute__((noinline))
static uint64_t pure_reg(uint64_t v) {
    return v >> 4;
}

int main() {
    uint64_t v = 0xc00d99999999999aULL;
    printf("via_union(0x%llx)=0x%llx (exp 0x0c00d99999999999)\n",
        (unsigned long long)v, (unsigned long long)via_union(v));
    printf("pure_reg(0x%llx)=0x%llx (exp 0x0c00d99999999999)\n",
        (unsigned long long)v, (unsigned long long)pure_reg(v));
    return 0;
}
