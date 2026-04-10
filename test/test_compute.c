/*
 * test_compute.c — 计算密集型 benchmark，验证寄存器分配优化效果。
 *
 * 包含多个纯算术循环，尽量不做 syscall / 内存访问，
 * 让 JIT 生成的代码在两次 helper call 之间执行大量 ALU 指令。
 *
 * 每个子测试计算一个已知结果，与预期值比对。
 * 全部通过则 exit(0)，否则 exit(1)。
 */
#include <stdio.h>
#include <stdint.h>

/* ===================================================================
 * 1. Fibonacci（第 70 项，用 uint64_t 防溢出）
 * 覆盖：寄存器间 ADD、MOV、循环回边、条件跳转
 * =================================================================== */
static uint64_t fib(int n) {
    uint64_t a = 0, b = 1;
    for (int i = 0; i < n; i++) {
        uint64_t t = a + b;
        a = b;
        b = t;
    }
    return a;
}

/* ===================================================================
 * 2. 累加 + 位运算混合
 * 覆盖：ADD/SUB/XOR/AND/OR/LSH/RSH，立即数和寄存器两种形式
 * =================================================================== */
static uint64_t bitops_loop(int n) {
    uint64_t acc = 0;
    for (int i = 1; i <= n; i++) {
        acc += (uint64_t)i;
        acc ^= (acc << 3);
        acc &= 0x0FFFFFFFFFFFFFFF;
        acc |= ((uint64_t)i << 1);
        acc -= (uint64_t)(i >> 1);
        acc ^= (acc >> 7);
    }
    return acc;
}

/* ===================================================================
 * 3. 32-bit 算术密集循环
 * 覆盖：ALU32 指令（add32, sub32, mul32, lsh32, rsh32）
 * =================================================================== */
static uint32_t alu32_loop(int n) {
    uint32_t a = 1, b = 2, c = 3;
    for (int i = 0; i < n; i++) {
        a = a + b;
        b = b ^ (c << 5);
        c = (c * 7) + (a >> 3);
        a = a - (c & 0xFF);
        b = b + (a | c);
    }
    return a ^ b ^ c;
}

/* ===================================================================
 * 4. 多寄存器同时活跃（r0-r9 全部使用）
 * 覆盖：寄存器分配压力，测试 callee-saved / caller-saved 映射
 * =================================================================== */
static uint64_t multi_reg(int n) {
    uint64_t r0 = 1, r1 = 2, r2 = 3, r3 = 5;
    uint64_t r4 = 7, r5 = 11, r6 = 13, r7 = 17;
    for (int i = 0; i < n; i++) {
        r0 = r0 + r1;
        r1 = r1 ^ r2;
        r2 = r2 + r3;
        r3 = r3 ^ r4;
        r4 = r4 + r5;
        r5 = r5 ^ r6;
        r6 = r6 + r7;
        r7 = r7 ^ r0;
    }
    return r0 + r1 + r2 + r3 + r4 + r5 + r6 + r7;
}

/* ===================================================================
 * 5. DIV/MOD 密集（走 helper call，测试 spill/restore 开销）
 * =================================================================== */
static uint64_t divmod_loop(int n) {
    uint64_t acc = 1000000;
    for (int i = 1; i <= n; i++) {
        acc = acc + (uint64_t)i;
        uint64_t d = (uint64_t)(i | 1);  /* 确保非零且为奇数 */
        acc = (acc / d) + (acc % d);
    }
    return acc;
}

/* ===================================================================
 * 6. Collatz 猜想迭代（条件跳转密集）
 * 覆盖：大量条件分支 + ALU 混合
 * =================================================================== */
static uint64_t collatz_total_steps(uint64_t start, uint64_t count) {
    uint64_t total = 0;
    for (uint64_t n = start; n < start + count; n++) {
        uint64_t x = n;
        while (x != 1) {
            if (x & 1)
                x = 3 * x + 1;
            else
                x = x >> 1;
            total++;
        }
    }
    return total;
}

/* ===================================================================
 * 7. 数组遍历求和 + 位运算（内存访问 + ALU 混合）
 * 覆盖：LDX/STX + ALU 交织，测试寄存器映射在内存访问路径的效果
 * =================================================================== */
static uint64_t array_compute(void) {
    uint64_t buf[256];
    /* 初始化 */
    for (int i = 0; i < 256; i++) {
        buf[i] = (uint64_t)(i * 7 + 3);
    }
    /* 多轮迭代：读取-计算-写回 */
    for (int round = 0; round < 100000; round++) {
        for (int i = 0; i < 256; i++) {
            uint64_t v = buf[i];
            v = v ^ (v << 3);
            v = v + (uint64_t)(i + round);
            v = v ^ (v >> 7);
            v = v & 0x0FFFFFFFFFFFFFFF;
            buf[i] = v;
        }
    }
    /* 求和 */
    uint64_t sum = 0;
    for (int i = 0; i < 256; i++) {
        sum += buf[i];
    }
    return sum;
}

/* ===================================================================
 * 主函数：运行所有子测试，验证结果
 * =================================================================== */
int main(void) {
    int ok = 1;

    /* 1. Fibonacci */
    {
        uint64_t r = fib(70);
        /* fib(70) = 190392490709135 */
        printf("fib(70) = %lu\n", r);
        ok &= (r == 190392490709135ULL);
    }

    /* 2. Bitops (10M 次迭代) */
    {
        uint64_t r = bitops_loop(10000000);
        printf("bitops(10M) = %lu\n", r);
        ok &= (r == 2393173702422460ULL);
    }

    /* 3. ALU32 (5M 次迭代) */
    {
        uint32_t r = alu32_loop(5000000);
        printf("alu32(5M) = %u\n", r);
        ok &= (r == 3655653932U);
    }

    /* 4. Multi-register (10M 次迭代) */
    {
        uint64_t r = multi_reg(10000000);
        printf("multi_reg(10M) = %lu\n", r);
        ok &= (r == 18360034627886528466ULL);
    }

    /* 5. Divmod (1M 次迭代) */
    {
        uint64_t r = divmod_loop(1000000);
        printf("divmod(1M) = %lu\n", r);
        ok &= (r == 500000ULL);
    }

    /* 6. Collatz (从 2 开始的 10000 个数) */
    {
        uint64_t r = collatz_total_steps(2, 10000);
        printf("collatz(2..10001) = %lu\n", r);
        ok &= (r == 849845ULL);
    }

    /* 7. Array compute (256 元素 x 100K 轮) */
    {
        uint64_t r = array_compute();
        printf("array_compute = %lu\n", r);
        /* 先用 native 计算得到预期值 */
        ok &= (r == 5391422162037253290ULL);
    }

    printf("compute: %s\n", ok ? "ok" : "FAILED");
    return ok ? 0 : 1;
}
