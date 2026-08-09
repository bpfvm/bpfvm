/*
 * test_i128_ret.c — 验证【返回 __int128 的函数】支持（caller + callee）。
 *
 * 触发链路(无 pass 时):
 *   __int128 foo(...) { ...; return val; }   →  IR: ret i128
 *   → BPF 后端 LowerReturn 只支持单 64 位返回寄存器 r0 →
 *     fatal error: "unable to allocate function return" 崩溃。
 *
 * BpfWideArgs pass 的 lowerI128Returns 把 i128 返回值降级成 sret 风格:
 *   i128 foo(args)  →  void foo(ptr %agg.result, args)
 *   callee: ret i128 %v  →  store %v, %agg.result; ret void
 *   caller: x = call i128 foo(args)  →  alloca; call void foo(ptr, args); load
 *
 * mul128 不走这条路径:它由 BpfSoftFp 改写成单输出 BPF_FP_UMULH（只回 r0=高半，
 * 低半由调用方用原生 mul i64 另算），针对的是【i128 乘法指令】；本 pass 针对的是
 * 【返回 i128 的普通函数】，两者层面不同。i128 返回值只能用 sret 改写（把返回值
 * 搬出 ret）。
 *
 * 覆盖点(对照 host 原生 __int128):
 *   - 基本返回 + 取低半/高半
 *   - 多次调用(caller 侧 alloca 复用/覆盖)
 *   - 返回值作另一函数的参数(链式)
 *   - 返回值被忽略(不取结果)
 *   - 带提前 return(多个 ret 分支)
 *
 * 全部断言通过则 exit(0),任一失败 exit(1)。
 */
#include <stdio.h>
#include <stdint.h>

static int fails = 0;

/* 返回 __int128 的函数 —— 触发 lowerI128Returns。 */
static __int128 make_i128(uint64_t lo, uint64_t hi) {
    return ((__int128)hi << 64) | lo;
}

/* 多分支返回(提前 return):每个 ret i128 都要被改写。 */
static __int128 select_i128(int which, uint64_t lo, uint64_t hi) {
    __int128 v = ((__int128)hi << 64) | lo;
    if (which == 0) return 0;                 /* ret 0 */
    if (which == 1) return v;                  /* ret v */
    return v + 1;                              /* ret v+1 */
}

/* 接收 __int128 返回值作参数(链式:返回值传给另一个函数)。 */
static uint64_t extract_lo(__int128 v) {
    return (uint64_t)v;
}
static uint64_t extract_hi(__int128 v) {
    return (uint64_t)(v >> 64);
}

/* 返回值被忽略的 caller 模式。 */
static __int128 side_effect_i128(uint64_t lo, uint64_t hi) {
    return ((__int128)hi << 64) | lo;
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
    uint64_t lo = 0x123456789ABCDEF0ULL;
    uint64_t hi = 0xFEDCBA9876543210ULL;

    /* === 基本返回:取低半/高半 === */
    CHECK(extract_lo(make_i128(lo, hi)), lo, "ret lo");
    CHECK(extract_hi(make_i128(lo, hi)), hi, "ret hi");

    /* === 多次调用(caller alloca 反复覆写)=== */
    {
        __int128 a = make_i128(lo, hi);
        __int128 b = make_i128(hi, lo);     /* 不同值,覆盖同一 alloca */
        CHECK(extract_lo(a), lo, "reuse call1 lo");
        CHECK(extract_hi(a), hi, "reuse call1 hi");
        CHECK(extract_lo(b), hi, "reuse call2 lo");
        CHECK(extract_hi(b), lo, "reuse call2 hi");
    }

    /* === 多分支返回 === */
    CHECK(extract_lo(select_i128(0, lo, hi)), 0,  "select which=0");
    CHECK(extract_lo(select_i128(1, lo, hi)), lo, "select which=1");
    CHECK(extract_lo(select_i128(2, lo, hi)), (uint64_t)(lo + 1), "select which=2");
    CHECK(extract_hi(select_i128(0, lo, hi)), 0,  "select which=0 hi");

    /* === 返回值被忽略(仍要建 alloca 让 callee 写)=== */
    side_effect_i128(lo, hi);   /* 不取结果,不应崩 */

    /* === 大值(两半都非零,跨半边界)=== */
    {
        __int128 big = make_i128(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);
        CHECK(extract_lo(big), 0xFFFFFFFFFFFFFFFFULL, "big lo");
        CHECK(extract_hi(big), 0xFFFFFFFFFFFFFFFFULL, "big hi");
    }

    if (fails == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURES\n", fails);
    return 1;
}
