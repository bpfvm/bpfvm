/*
 * bench_callcost.c — 测量 BPF->BPF 直接调用（emit_call_bpf fast path）的 JIT 额外开销。
 *
 * 两个等价循环，唯一差别是每次迭代是否经过一次函数调用：
 *   inline_loop : 运算直接写在循环里（leaf 被 JIT 内联，无 call）
 *   call_loop   : 每次迭代调用叶子函数 leaf() 做相同运算
 *
 * 通过 BPF_DEBUG 取指令数 + 计时，反算每次 call 的额外成本。
 * leaf() 体刻意做与 inline 版完全相同的几条 ALU，使指令数差异
 * 主要来自调用机制（push_frame / pop_frame / cache / .cont）本身。
 *
 * leaf 用 noinline 阻止内联；call_loop 直接用名字调用 leaf，
 * 生成 BPF 相对 call（走 emit_call_bpf fast path，与 genrsa 的 BN 调用同路径）。
 *
 * 用法：bpfvm bench_callcost.out [inline|call|both]
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define ITERS 200000000ULL  /* 2 亿迭代：让 JIT 充分预热，单次 call 成本可积 */

/* 叶子函数：与 inline_loop 循环体相同的运算。noinline 强制单独成函数。 */
__attribute__((noinline))
static uint64_t leaf(uint64_t x) {
    x ^= (x << 3);
    x += 0x9E3779B97F4A7C15ULL;
    x ^= (x >> 7);
    return x;
}

/* 版本 A：内联循环，无函数调用。循环体与 leaf() 体逐条相同。 */
static uint64_t inline_loop(uint64_t iters) {
    uint64_t x = 1;
    for (uint64_t i = 0; i < iters; i++) {
        x ^= (x << 3);
        x += 0x9E3779B97F4A7C15ULL;
        x ^= (x >> 7);
    }
    return x;
}

/* 版本 B：每次迭代直接调用 leaf()（编译期已知目标 -> BPF 相对 call -> fast path）。 */
static uint64_t call_loop(uint64_t iters) {
    uint64_t x = 1;
    for (uint64_t i = 0; i < iters; i++) {
        x = leaf(x);
    }
    return x;
}

int main(int argc, char **argv) {
    /* argv[1] 选择模式：inline / call / both（默认 both）。便于分别计时。 */
    const char *mode = (argc > 1) ? argv[1] : "both";
    uint64_t a = 0, b = 0;
    if (strcmp(mode, "inline") == 0 || strcmp(mode, "both") == 0) a = inline_loop(ITERS);
    if (strcmp(mode, "call") == 0 || strcmp(mode, "both") == 0) b = call_loop(ITERS);
    /* leaf 体与循环体运算相同，inline 与 call 应得同值 */
    if (strcmp(mode, "both") == 0 && a != b) {
        printf("MISMATCH a=0x%llx b=0x%llx\n", (unsigned long long)a, (unsigned long long)b);
        return 1;
    }
    printf("mode=%s a=0x%llx b=0x%llx\n", mode, (unsigned long long)a, (unsigned long long)b);
    return 0;
}
