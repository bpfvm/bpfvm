/*
 * bench_call_steps.c — 定量拆解 BPF->BPF call 各步骤代价。
 *
 * 方法：线性回归。生成一组 leaf 函数，体大小递增（0/5/10/20/40/80 条 ALU），
 * 每个 leaf 配一个调用它的循环。固定迭代次数 ITERS，测各变体耗时：
 *
 *   耗时(leaf_k) = ITERS * (T_call_fixed + k * T_per_insn)
 *
 *   T_call_fixed = 纯调用机制开销（push_frame/pop_frame/cache/check，与 leaf 大小无关）
 *   T_per_insn   = JIT 执行单条 BPF ALU 指令的时间（斜率）
 *
 * ALU 组刻意用纯寄存器、无大立即数运算（避免 lddw 占 2 槽引入非线性），
 * 且保持数据依赖链式（防乱序掩盖延迟）。
 *
 * 用法：bpfvm bench_call_steps.out [k]   k = 0/5/10/20/40/80
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ITERS 200000000ULL  /* 2 亿 */

/* 一组 ALU = 5 条纯寄存器运算（add/rsh/xor/lsh/xor），数据依赖链式，无立即数 */
#define ALU1 do {                       \
        x = x + x;                      \
        x = x ^ (x >> 1);               \
        x = x ^ (x << 1);               \
    } while (0)
#define ALU2   ALU1; ALU1
#define ALU4   ALU2; ALU2
#define ALU8   ALU4; ALU4
#define ALU16  ALU8; ALU8
#define ALU32  ALU16; ALU16

/* leaf 最小：x^0x12345（1 条运算），不可被消除 */
__attribute__((noinline)) static uint64_t leaf_1(uint64_t x)  { return x ^ 0x12345ULL; }
__attribute__((noinline)) static uint64_t leaf_5(uint64_t x)  { ALU1; return x; }
__attribute__((noinline)) static uint64_t leaf_10(uint64_t x) { ALU2; return x; }
__attribute__((noinline)) static uint64_t leaf_20(uint64_t x) { ALU4; return x; }
__attribute__((noinline)) static uint64_t leaf_40(uint64_t x) { ALU8; return x; }
__attribute__((noinline)) static uint64_t leaf_80(uint64_t x) { ALU16; return x; }

/* 双层：leaf_80 体内再调 leaf_1（多一层调用机制）。测"每多嵌套一层"的增量开销。 */
__attribute__((noinline)) static uint64_t leaf80_then_1(uint64_t x) { ALU16; return leaf_1(x); }
static uint64_t call_loop_nest2(uint64_t iters) { uint64_t x=1; for(uint64_t i=0;i<iters;i++) x=leaf80_then_1(x); return x; }

/* 内联基线：与 leaf_80 体相同，但不经调用 */
static uint64_t inline_80(uint64_t iters) {
    uint64_t x = 1;
    for (uint64_t i = 0; i < iters; i++) { ALU16; }
    return x;
}

static uint64_t call_loop_1(uint64_t iters)  { uint64_t x=1; for(uint64_t i=0;i<iters;i++) x=leaf_1(x);  return x; }
static uint64_t call_loop_5(uint64_t iters)  { uint64_t x=1; for(uint64_t i=0;i<iters;i++) x=leaf_5(x);  return x; }
static uint64_t call_loop_10(uint64_t iters) { uint64_t x=1; for(uint64_t i=0;i<iters;i++) x=leaf_10(x); return x; }
static uint64_t call_loop_20(uint64_t iters) { uint64_t x=1; for(uint64_t i=0;i<iters;i++) x=leaf_20(x); return x; }
static uint64_t call_loop_40(uint64_t iters) { uint64_t x=1; for(uint64_t i=0;i<iters;i++) x=leaf_40(x); return x; }
static uint64_t call_loop_80(uint64_t iters) { uint64_t x=1; for(uint64_t i=0;i<iters;i++) x=leaf_80(x); return x; }

int main(int argc, char **argv) {
    const char *k = (argc > 1) ? argv[1] : "80";
    /* volatile sink 防优化 */
    volatile uint64_t sink = 0;
    if      (!strcmp(k, "inline80")) sink = inline_80(ITERS);
    else if (!strcmp(k, "1"))  sink = call_loop_1(ITERS);
    else if (!strcmp(k, "5"))  sink = call_loop_5(ITERS);
    else if (!strcmp(k, "10")) sink = call_loop_10(ITERS);
    else if (!strcmp(k, "20")) sink = call_loop_20(ITERS);
    else if (!strcmp(k, "40")) sink = call_loop_40(ITERS);
    else if (!strcmp(k, "80")) sink = call_loop_80(ITERS);
    else if (!strcmp(k, "nest2")) sink = call_loop_nest2(ITERS);
    else { fprintf(stderr, "unknown size %s\n", k); return 2; }
    printf("k=%s sink=0x%llx\n", k, (unsigned long long)sink);
    return 0;
}
