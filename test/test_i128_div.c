/*
 * test_i128_div.c — 验证 __int128 的除法和取模支持（udiv/sdiv/urem/srem i128）。
 *
 * 触发链路(无 pass 时):
 *   (u128)a / b, a % b, (__int128)a / b ...  (a, b 是运行时值)
 *   -> IR: udiv/sdiv/urem/srem i128
 *   -> BPF 后端 ISel lower 成 __udivti3 / __divti3 / __umodti3 / __modti3 调用
 *     并在 ISel 阶段拒绝（IR pass 管不到 ISel 自行生成的 libcall）。
 *
 * BpfSoftFp pass 把两个 i128 操作数各拆成 (lo,hi)，调
 *   i64 __bpf_fp_<ID>(ptr out_hi, i64 aLo, i64 aHi, i64 bLo, i64 bHi)
 * （5 参占满 r1-r5）：VM 解释器 do_softfp 用宿主 __int128 算出 128 位结果，
 * 低半回 r0、高半写入 out_hi 指向的 8 字节。caller 只 load 一次高半组装回 i128。
 * JIT 无原生 lowering，经 emit_call_softfp_slow 逐条回退到解释器。
 *
 * 重点边界(对照 x86 原生 __int128 结果,逐个核对):
 *   - 无符号商跨半(>2^64)  : hi!=0 的除法结果
 *   - 小商(被除数<除数)     : 商=0, 余数=被除数
 *   - 整除                 : 余数=0
 *   - 有符号负数操作数      : 符号影响商和余数(C 的 / 和 % 截断向零,与 LLVM sdiv/srem 一致)
 *   - 除零                 : 返回 0(不崩溃 host)
 *
 * volatile 操作数防常量折叠,强制走运行时除法路径(常量除法 clang 编译期算掉,
 * 不发 sdiv i128,测不到目标代码)。全部断言通过则 exit(0),任一失败 exit(1)。
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;

/* 无符号除法 __int128,操作数 volatile 防折叠。返回商的两半。 */
static uint64_t udiv_lo(uint64_t alo, uint64_t ahi, uint64_t blo, uint64_t bhi) {
    volatile unsigned __int128 a = ((unsigned __int128)ahi << 64) | alo;
    volatile unsigned __int128 b = ((unsigned __int128)bhi << 64) | blo;
    unsigned __int128 r = a / b;
    return (uint64_t)r;
}
static uint64_t udiv_hi(uint64_t alo, uint64_t ahi, uint64_t blo, uint64_t bhi) {
    volatile unsigned __int128 a = ((unsigned __int128)ahi << 64) | alo;
    volatile unsigned __int128 b = ((unsigned __int128)bhi << 64) | blo;
    unsigned __int128 r = a / b;
    return (uint64_t)(r >> 64);
}
/* 无符号取模。 */
static uint64_t urem_lo(uint64_t alo, uint64_t ahi, uint64_t blo, uint64_t bhi) {
    volatile unsigned __int128 a = ((unsigned __int128)ahi << 64) | alo;
    volatile unsigned __int128 b = ((unsigned __int128)bhi << 64) | blo;
    unsigned __int128 r = a % b;
    return (uint64_t)r;
}
static uint64_t urem_hi(uint64_t alo, uint64_t ahi, uint64_t blo, uint64_t bhi) {
    volatile unsigned __int128 a = ((unsigned __int128)ahi << 64) | alo;
    volatile unsigned __int128 b = ((unsigned __int128)bhi << 64) | blo;
    unsigned __int128 r = a % b;
    return (uint64_t)(r >> 64);
}
/* 有符号除法/取模。符号位在最高位,用 __int128 的有符号运算。 */
static uint64_t sdiv_lo(uint64_t alo, uint64_t ahi, uint64_t blo, uint64_t bhi) {
    volatile __int128 a = ((__int128)(int64_t)ahi << 64) | (uint64_t)alo;
    volatile __int128 b = ((__int128)(int64_t)bhi << 64) | (uint64_t)blo;
    __int128 r = a / b;
    return (uint64_t)r;
}
static uint64_t sdiv_hi(uint64_t alo, uint64_t ahi, uint64_t blo, uint64_t bhi) {
    volatile __int128 a = ((__int128)(int64_t)ahi << 64) | (uint64_t)alo;
    volatile __int128 b = ((__int128)(int64_t)bhi << 64) | (uint64_t)blo;
    __int128 r = a / b;
    return (uint64_t)((unsigned __int128)r >> 64);
}
static uint64_t srem_lo(uint64_t alo, uint64_t ahi, uint64_t blo, uint64_t bhi) {
    volatile __int128 a = ((__int128)(int64_t)ahi << 64) | (uint64_t)alo;
    volatile __int128 b = ((__int128)(int64_t)bhi << 64) | (uint64_t)blo;
    __int128 r = a % b;
    return (uint64_t)r;
}
static uint64_t srem_hi(uint64_t alo, uint64_t ahi, uint64_t blo, uint64_t bhi) {
    volatile __int128 a = ((__int128)(int64_t)ahi << 64) | (uint64_t)alo;
    volatile __int128 b = ((__int128)(int64_t)bhi << 64) | (uint64_t)blo;
    __int128 r = a % b;
    return (uint64_t)((unsigned __int128)r >> 64);
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
    /* === 无符号:商跨半(被除数大,除数小,商 > 2^64)=== */
    {
        uint64_t alo = 0, ahi = 1;           /* a = 2^64 */
        uint64_t blo = 1, bhi = 0;           /* b = 1 */
        CHECK(udiv_lo(alo,ahi,blo,bhi), 0,            "udiv cross lo");
        CHECK(udiv_hi(alo,ahi,blo,bhi), 1,            "udiv cross hi");
        CHECK(urem_lo(alo,ahi,blo,bhi), 0,            "urem cross lo");
        CHECK(urem_hi(alo,ahi,blo,bhi), 0,            "urem cross hi");
    }
    /* === 无符号:小商(被除数 < 除数 -> 商 0,余数=被除数)=== */
    {
        uint64_t alo = 5, ahi = 0;           /* a = 5 */
        uint64_t blo = 7, bhi = 0;           /* b = 7 */
        CHECK(udiv_lo(alo,ahi,blo,bhi), 0,            "udiv small lo");
        CHECK(udiv_hi(alo,ahi,blo,bhi), 0,            "udiv small hi");
        CHECK(urem_lo(alo,ahi,blo,bhi), 5,            "urem small lo");
        CHECK(urem_hi(alo,ahi,blo,bhi), 0,            "urem small hi");
    }
    /* === 无符号:整除 + 余数非零(常见除数)=== */
    {
        uint64_t alo = 0x123456789ABCDEF0ULL, ahi = 0xFEDCBA9876543210ULL;
        uint64_t blo = 3, bhi = 0;
        unsigned __int128 a = ((unsigned __int128)ahi << 64) | alo;
        unsigned __int128 q = a / 3, rem = a % 3;
        CHECK(udiv_lo(alo,ahi,blo,bhi), (uint64_t)q,         "udiv div3 lo");
        CHECK(udiv_hi(alo,ahi,blo,bhi), (uint64_t)(q >> 64), "udiv div3 hi");
        CHECK(urem_lo(alo,ahi,blo,bhi), (uint64_t)rem,        "urem div3 lo");
        CHECK(urem_hi(alo,ahi,blo,bhi), (uint64_t)(rem >> 64),"urem div3 hi");
    }
    /* === 无符号:大除数(两半都非零)=== */
    {
        uint64_t alo = 0xFEDCBA9876543210ULL, ahi = 0x123456789ABCDEF0ULL;
        uint64_t blo = 0x13579BDF2468ACE0ULL, bhi = 0x0FEDCBA987654321ULL;
        unsigned __int128 a = ((unsigned __int128)ahi << 64) | alo;
        unsigned __int128 b = ((unsigned __int128)bhi << 64) | blo;
        unsigned __int128 q = a / b, rem = a % b;
        CHECK(udiv_lo(alo,ahi,blo,bhi), (uint64_t)q,         "udiv big lo");
        CHECK(udiv_hi(alo,ahi,blo,bhi), (uint64_t)(q >> 64), "udiv big hi");
        CHECK(urem_lo(alo,ahi,blo,bhi), (uint64_t)rem,        "urem big lo");
        CHECK(urem_hi(alo,ahi,blo,bhi), (uint64_t)(rem >> 64),"urem big hi");
    }
    /* === 无符号:除零(返回 0,不崩溃)== */
    /* 仅 VM 变体验证:宿主原生 __int128/0 是 UB(触发 SIGFPE),而 VM 定义为返回 0
     * 是 BPF 扩展(do_softfp 显式拦截除零),host variant 无对照意义。 */
    if (!getenv("BPF_TEST_VARIANT") ||
        strcmp(getenv("BPF_TEST_VARIANT"), "host") != 0) {
        CHECK(udiv_lo(100,0,0,0), 0, "udiv by0 lo");
        CHECK(udiv_hi(100,0,0,0), 0, "udiv by0 hi");
        CHECK(urem_lo(100,0,0,0), 0, "urem by0 lo");
        CHECK(urem_hi(100,0,0,0), 0, "urem by0 hi");
    }

    /* === 有符号:正数(等价无符号)=== */
    {
        uint64_t alo = 100, ahi = 0, blo = 7, bhi = 0;
        CHECK(sdiv_lo(alo,ahi,blo,bhi), 14, "sdiv pos lo");   /* 100/7 = 14 */
        CHECK(sdiv_hi(alo,ahi,blo,bhi), 0,  "sdiv pos hi");
        CHECK(srem_lo(alo,ahi,blo,bhi), 2,  "srem pos lo");   /* 100%7 = 2 */
        CHECK(srem_hi(alo,ahi,blo,bhi), 0,  "srem pos hi");
    }
    /* === 有符号:负被除数(符号影响结果;C 的 % 截断向零)== */
    {
        /* a = -100, b = 7 -> 商 -14, 余 -2 (截断向零) */
        __int128 a = -100, b = 7;
        uint64_t alo = (uint64_t)a, ahi = (uint64_t)((unsigned __int128)a >> 64);
        uint64_t blo = (uint64_t)b, bhi = (uint64_t)((unsigned __int128)b >> 64);
        CHECK(sdiv_lo(alo,ahi,blo,bhi), (uint64_t)(__int128)(-14), "sdiv neg lo");
        CHECK(sdiv_hi(alo,ahi,blo,bhi), (uint64_t)((unsigned __int128)(__int128)(-14) >> 64), "sdiv neg hi");
        CHECK(srem_lo(alo,ahi,blo,bhi), (uint64_t)(__int128)(-2),  "srem neg lo");
        CHECK(srem_hi(alo,ahi,blo,bhi), (uint64_t)((unsigned __int128)(__int128)(-2) >> 64),  "srem neg hi");
    }
    /* === 有符号:负除数 == */
    {
        /* a = 100, b = -7 -> 商 -14, 余 2 (截断向零) */
        __int128 a = 100, b = -7;
        uint64_t alo = (uint64_t)a, ahi = (uint64_t)((unsigned __int128)a >> 64);
        uint64_t blo = (uint64_t)b, bhi = (uint64_t)((unsigned __int128)b >> 64);
        CHECK(sdiv_lo(alo,ahi,blo,bhi), (uint64_t)(__int128)(-14), "sdiv negdiv lo");
        CHECK(srem_lo(alo,ahi,blo,bhi), (uint64_t)(__int128)(2),   "srem negdiv lo");
    }
    /* === 有符号:两负(商正,余负)== */
    {
        /* a = -100, b = -7 -> 商 14, 余 -2 */
        __int128 a = -100, b = -7;
        uint64_t alo = (uint64_t)a, ahi = (uint64_t)((unsigned __int128)a >> 64);
        uint64_t blo = (uint64_t)b, bhi = (uint64_t)((unsigned __int128)b >> 64);
        CHECK(sdiv_lo(alo,ahi,blo,bhi), (uint64_t)(__int128)(14),  "sdiv bothneg lo");
        CHECK(srem_lo(alo,ahi,blo,bhi), (uint64_t)(__int128)(-2),  "srem bothneg lo");
    }
    /* === 有符号:大数跨半(商 > 2^63 但 < 2^64,正数)== */
    {
        /* a = 2^127, b = 2 -> 商 = 2^126 */
        unsigned __int128 a = ((unsigned __int128)1) << 127;
        __int128 b = 2;
        uint64_t alo = (uint64_t)a, ahi = (uint64_t)(a >> 64);
        uint64_t blo = (uint64_t)b, bhi = 0;
        __int128 q = (__int128)a / b;
        CHECK(sdiv_lo(alo,ahi,blo,bhi), (uint64_t)q,         "sdiv big lo");
        CHECK(sdiv_hi(alo,ahi,blo,bhi), (uint64_t)((unsigned __int128)q >> 64), "sdiv big hi");
    }

    if (fails == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURES\n", fails);
    return 1;
}
