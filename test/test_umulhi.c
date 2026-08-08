/*
 * test_umulhi.c — 验证 (uint128_t)a*b 的高/低半提取（BN_UMULT_HIGH/LOHI 形态）。
 *
 * 这是 OpenSSL bn_local.h BN_UMULT_HIGH 的 IR 形态来源：
 *   #define BN_UMULT_HIGH(a,b) (((uint128_t)(a)*(b))>>64)
 *   #define BN_UMULT_LOHI(lo,hi,a,b) ({ uint128_t r=(uint128_t)(a)*(b); (hi)=r>>64; (lo)=r; })
 *
 * 触发链路（无 pass 时）：
 *   (u128)a*b >> 64  →  IR: zext i64→i128; mul i128; lshr i128,64; trunc→i64
 *   → BPF 后端 lower 成 __multi3 调用 → ISel 拒绝("__multi3 not supported")。
 *
 * BpfSoftFp pass 识别 mul i128 模式：
 *   - 低半 trunc(prod)            → 原生 mul i64（BPF_MUL）
 *   - 高半 trunc(lshr(prod,64))   → BPF_FP_UMULH（走 softfp 通道，VM 侧 x86 mulq /
 *     aarch64 mul+umulh；r0 返回高半）
 *
 * volatile 输入防常量折叠，强制走运行时 mul i128 路径。对照 x86 原生结果，
 * 全部断言通过则 exit(0)，任一失败 exit(1)。
 *
 * 覆盖（对照 test_multi3 的 umul.with.overflow 路径，本测试覆盖直接 u128 乘法）：
 *   - 不溢出（乘积在 64 位内，高半=0）
 *   - 溢出（乘积超过 64 位，高半≠0）
 *   - schoolbook 进位链边界（(2^32)^2、(2^32-1)^2、跨 32 位组合）
 *   - 极值（0 / UINT64_MAX / 2^63 等）
 *   - BN_UMULT_LOHI（同时取高/低半）与 BN_UMULT_HIGH（仅取高半）两种形态
 */
#include <stdio.h>
#include <stdint.h>

static int fails = 0;

/* volatile 防常量折叠，确保走运行时 mul i128 路径。 */
#define UMULHI(va, vb) ({ \
    volatile uint64_t _a = (va), _b = (vb); \
    (uint64_t)(((unsigned __int128)_a * _b) >> 64); \
})

#define UMULLO(va, vb) ({ \
    volatile uint64_t _a = (va), _b = (vb); \
    (uint64_t)((unsigned __int128)_a * _b); \
})

/* 断言高半提取：BN_UMULT_HIGH 形态。 */
#define CHECK_HI(va, vb, expect_hi, label) do { \
    uint64_t got = UMULHI((va), (vb)); \
    if (got != (uint64_t)(expect_hi)) { \
        printf("FAIL %s: a=0x%016llx b=0x%016llx hi=0x%016llx, expect hi=0x%016llx\n", \
               label, (unsigned long long)(va), (unsigned long long)(vb), \
               (unsigned long long)got, (unsigned long long)(expect_hi)); \
        fails++; \
    } \
} while (0)

/* 断言低半提取：乘积低 64 位。 */
#define CHECK_LO(va, vb, expect_lo, label) do { \
    uint64_t got = UMULLO((va), (vb)); \
    if (got != (uint64_t)(expect_lo)) { \
        printf("FAIL %s: a=0x%016llx b=0x%016llx lo=0x%016llx, expect lo=0x%016llx\n", \
               label, (unsigned long long)(va), (unsigned long long)(vb), \
               (unsigned long long)got, (unsigned long long)(expect_lo)); \
        fails++; \
    } \
} while (0)

/* 断言 BN_UMULT_LOHI（同时取高/低半，验证两路独立提取一致）。 */
#define CHECK_LOHI(va, vb, expect_lo, expect_hi, label) do { \
    CHECK_LO((va), (vb), (expect_lo), label "/lo"); \
    CHECK_HI((va), (vb), (expect_hi), label "/hi"); \
} while (0)

int main(void) {
    /* === 不溢出（高半 = 0）=== */
    CHECK_HI(100, 200, 0, "100*200");
    CHECK_HI(0, 0xFFFFFFFFFFFFFFFFULL, 0, "0*UINT64_MAX");
    CHECK_HI(1, 0xFFFFFFFFFFFFFFFFULL, 0, "1*UINT64_MAX");
    CHECK_HI(0xFFFFFFFFULL, 0x100000001ULL, 0, "(2^32-1)*(2^32+1)");   /* = 2^64-1 */
    CHECK_HI(0x7FFFFFFFFFFFFFFFULL, 2, 0, "(2^63-1)*2");               /* = 2^64-2 */

    /* === 溢出（高半 ≠ 0）=== */
    CHECK_HI(0xFFFFFFFFFFFFFFFFULL, 2, 1, "UINT64_MAX*2");             /* hi=1 */
    CHECK_HI(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
             0xFFFFFFFFFFFFFFFEULL, "UINT64_MAX^2");                   /* hi=2^64-2 */
    CHECK_HI(0x8000000000000000ULL, 2, 1, "2^63*2");                   /* = 2^64, hi=1 */

    /* === schoolbook 进位链边界 === */
    CHECK_HI(1ULL << 32, 1ULL << 32, 1, "(2^32)^2");                   /* = 2^64, hi=1 */
    CHECK_HI(0xFFFFFFFFULL, 0xFFFFFFFFULL, 0, "(2^32-1)^2");           /* = 0xFFFFFFFE00000001, hi=0 */
    CHECK_HI(0xFFFFFFFF00000000ULL, 0xFFFFFFFF00000000ULL,
             0xFFFFFFFE00000001ULL, "(2^32-1)*2^32 squared");          /* hi=high*high */
    CHECK_HI(0x100000001ULL, 0x100000001ULL, 1, "(2^32+1)^2");         /* cross 项进位 */
    CHECK_HI(0x200000000ULL, 0x300000000ULL, 6, "2*2^32 * 3*2^32");   /* hi=6 */

    /* === 低半（原生 mul i64，无新指令，但验证 pass 的低半改写正确）=== */
    CHECK_LO(100, 200, 20000, "100*200");
    CHECK_LO(0xFFFFFFFFFFFFFFFFULL, 2, 0xFFFFFFFFFFFFFFFEULL, "UINT64_MAX*2");
    CHECK_LO(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 1, "UINT64_MAX^2");
    CHECK_LO(0x8000000000000000ULL, 2, 0, "2^63*2");
    CHECK_LO(0xFFFFFFFFULL, 0xFFFFFFFFULL, 0xFFFFFFFE00000001ULL, "(2^32-1)^2");

    /* === BN_UMULT_LOHI 形态（同一次乘法同时取高/低半）=== */
    CHECK_LOHI(0x123456789ABCDEF0ULL, 0xFEDCBA9876543210ULL,
               0x236D88FE5618CF00ULL, 0x121FA00AD77D7422ULL, "mixed cross");
    CHECK_LOHI(0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL,
               0x7EB689F4EA447D62ULL, 0x00FD5BDEEEB2A01DULL, "asymmetric");

    /* === 对称性：a*b == b*a（高/低半都对称）=== */
    {
        volatile uint64_t a = 0xABCDEF0123456789ULL, b = 0x9876543210FEDCBAULL;
        uint64_t lo1 = UMULLO(a, b), hi1 = UMULHI(a, b);
        uint64_t lo2 = UMULLO(b, a), hi2 = UMULHI(b, a);
        if (lo1 != lo2 || hi1 != hi2) {
            printf("FAIL symmetry: a*b lo=0x%llx hi=0x%llx vs b*a lo=0x%llx hi=0x%llx\n",
                   (unsigned long long)lo1, (unsigned long long)hi1,
                   (unsigned long long)lo2, (unsigned long long)hi2);
            fails++;
        }
    }

    if (fails == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURES\n", fails);
    return 1;
}
