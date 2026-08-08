/*
 * test_i128_shift.c — 验证 __int128 的【变量】移位(shl/lshr)支持。
 *
 * 触发链路(无 pass 时):
 *   (u128)x << K / >> K  (K 是运行时变量,非编译期常量)
 *   → IR: shl/lshr i128 by i8/i16/...
 *   → BPF 后端 lower 成 __ashlti3 / __lshrti3 调用 → ISel 拒绝。
 *
 * BpfSoftFp pass 把 i128 变量移位拆成 (lo,hi) 两半,按 K<64 / K>=64 两分支
 * 用原生 64 位变量移位实现,再组装回 i128。
 *
 * 重点边界(对照 x86 原生 __int128 结果,逐个核对):
 *   - K = 0   : 64-k 会等于 64,lshr/shl i64 by 64 是 poison(本测试的核心)
 *   - K = 1   : 小分支正常
 *   - K = 63  : 小分支边界(64-k=1)
 *   - K = 64  : 跨半边界(大分支,k-64=0)
 *   - K = 65..127 : 大分支
 *
 * volatile 移位量防常量折叠,强制走变量移位路径(常量移位后端原生支持,
 * pass 不改写,测不到目标代码)。全部断言通过则 exit(0),任一失败 exit(1)。
 */
#include <stdio.h>
#include <stdint.h>

static int fails = 0;

/* 变量左移 __int128:K 是 volatile,防折叠成常量移位。 */
static uint64_t vshl_lo(uint64_t xlo, uint64_t xhi, unsigned k) {
    volatile unsigned vk = k;
    unsigned __int128 x = ((unsigned __int128)xhi << 64) | xlo;
    unsigned __int128 r = x << vk;
    return (uint64_t)r;
}
static uint64_t vshl_hi(uint64_t xlo, uint64_t xhi, unsigned k) {
    volatile unsigned vk = k;
    unsigned __int128 x = ((unsigned __int128)xhi << 64) | xlo;
    unsigned __int128 r = x << vk;
    return (uint64_t)(r >> 64);
}

/* 变量逻辑右移 __int128(无符号,等价 OpenSSL 域运算里 >> 的语义)。 */
static uint64_t vlshr_lo(uint64_t xlo, uint64_t xhi, unsigned k) {
    volatile unsigned vk = k;
    unsigned __int128 x = ((unsigned __int128)xhi << 64) | xlo;
    unsigned __int128 r = x >> vk;
    return (uint64_t)r;
}
static uint64_t vlshr_hi(uint64_t xlo, uint64_t xhi, unsigned k) {
    volatile unsigned vk = k;
    unsigned __int128 x = ((unsigned __int128)xhi << 64) | xlo;
    unsigned __int128 r = x >> vk;
    return (uint64_t)(r >> 64);
}

#define CHECK(expr, expect, label) do { \
    uint64_t _got = (expr); \
    if (_got != (uint64_t)(expect)) { \
        printf("FAIL %s: got=0x%016llx expect=0x%016llx\n", \
               label, (unsigned long long)_got, (unsigned long long)(expect)); \
        fails++; \
    } \
} while (0)

int main(void) {
    /* 选一组有代表性的操作数:低/高半都非零,移位后两半都会变化。 */
    uint64_t lo = 0x123456789ABCDEF0ULL;
    uint64_t hi = 0xFEDCBA9876543210ULL;

    /* === K = 0(本测试核心:64-k=64 的 poison 边界)=== */
    CHECK(vshl_lo(lo, hi, 0),  lo, "shl K=0 lo");
    CHECK(vshl_hi(lo, hi, 0),  hi, "shl K=0 hi");
    CHECK(vlshr_lo(lo, hi, 0), lo, "lshr K=0 lo");
    CHECK(vlshr_hi(lo, hi, 0), hi, "lshr K=0 hi");

    /* === K = 1(小分支正常路径)== */
    CHECK(vshl_lo(lo, hi, 1),  (lo << 1), "shl K=1 lo");
    CHECK(vshl_hi(lo, hi, 1),  (hi << 1) | (lo >> 63), "shl K=1 hi");
    CHECK(vlshr_lo(lo, hi, 1), (lo >> 1) | (hi << 63), "lshr K=1 lo");
    CHECK(vlshr_hi(lo, hi, 1), (hi >> 1), "lshr K=1 hi");

    /* === K = 63(小分支边界,64-k=1)== */
    CHECK(vshl_lo(lo, hi, 63), (lo << 63), "shl K=63 lo");
    CHECK(vshl_hi(lo, hi, 63), (hi << 63) | (lo >> 1), "shl K=63 hi");
    CHECK(vlshr_lo(lo, hi, 63), (lo >> 63) | (hi << 1), "lshr K=63 lo");
    CHECK(vlshr_hi(lo, hi, 63), (hi >> 63), "lshr K=63 hi");

    /* === K = 64(跨半边界,大分支 k-64=0)== */
    CHECK(vshl_lo(lo, hi, 64),  0,   "shl K=64 lo");
    CHECK(vshl_hi(lo, hi, 64),  lo,  "shl K=64 hi");
    CHECK(vlshr_lo(lo, hi, 64), hi,  "lshr K=64 lo");
    CHECK(vlshr_hi(lo, hi, 64), 0,   "lshr K=64 hi");

    /* === K = 65(大分支正常路径)== */
    CHECK(vshl_lo(lo, hi, 65),  0,          "shl K=65 lo");
    CHECK(vshl_hi(lo, hi, 65),  lo << 1,    "shl K=65 hi");
    CHECK(vlshr_lo(lo, hi, 65), hi >> 1,    "lshr K=65 lo");
    CHECK(vlshr_hi(lo, hi, 65), 0,          "lshr K=65 hi");

    /* === K = 96(大分支,对称)== */
    CHECK(vshl_lo(lo, hi, 96),  0,            "shl K=96 lo");
    CHECK(vshl_hi(lo, hi, 96),  lo << 32,     "shl K=96 hi");
    CHECK(vlshr_lo(lo, hi, 96), hi >> 32,     "lshr K=96 lo");
    CHECK(vlshr_hi(lo, hi, 96), 0,            "lshr K=96 hi");

    /* === 全 1 操作数 + K=0(再压一次 poison 边界,all-ones 让进位错位更明显)=== */
    {
        uint64_t f = 0xFFFFFFFFFFFFFFFFULL;
        CHECK(vshl_lo(f, f, 0),  f, "shl allones K=0 lo");
        CHECK(vshl_hi(f, f, 0),  f, "shl allones K=0 hi");
        CHECK(vlshr_lo(f, f, 0), f, "lshr allones K=0 lo");
        CHECK(vlshr_hi(f, f, 0), f, "lshr allones K=0 hi");
        CHECK(vshl_lo(f, f, 1),  0xFFFFFFFFFFFFFFFEULL, "shl allones K=1 lo");
        CHECK(vshl_hi(f, f, 1),  0xFFFFFFFFFFFFFFFFULL, "shl allones K=1 hi");
        CHECK(vlshr_lo(f, f, 1), 0xFFFFFFFFFFFFFFFFULL, "lshr allones K=1 lo");
        CHECK(vlshr_hi(f, f, 1), 0x7FFFFFFFFFFFFFFFULL, "lshr allones K=1 hi");
    }

    if (fails == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURES\n", fails);
    return 1;
}
