/*
 * test_frame_slot.c — 函数入口帧槽（frame_slot.h）：每个 guest call 只烧被调函数
 * 的编译期真实帧大小，而非全局 -S。20000 层互递归 × 每层(64B 帧记录 + ~32B 局部)
 * 约 2-4MB；固定 -S 模型下同样的深度要烧 20000 × 16KB = 320MB（栈溢出退出）。
 * 互递归（ra<->rb）是必须的：LLVM 的尾递归消除能把自递归（含"加法在调用之后"
 * 的累加形式）改写成循环，函数体里不再有 call 指令，测试就退化为单帧循环。
 * 期望退出码 0。
 */
#include <stdint.h>

volatile uint64_t sink;

__attribute__((noinline)) static uint64_t rb(uint64_t n);
__attribute__((noinline)) static uint64_t ra(uint64_t n) {
    uint64_t x = n ^ (n << 3);
    if (n == 0) return 1;
    return x + rb(n - 1);
}
__attribute__((noinline)) static uint64_t rb(uint64_t n) {
    uint64_t x = n ^ (n >> 2);
    if (n == 0) return 2;
    return x + ra(n - 1);
}

int main(void) {
    sink = ra(20000);
    return sink != 0 ? 0 : 1;
}
