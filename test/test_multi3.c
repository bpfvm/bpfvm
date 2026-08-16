/*
 * test_multi3.c — 验证 __builtin_mul_overflow(uint64_t, uint64_t, uint64_t*)
 *   (64x64->128 宽乘高位)支持。
 *
 * 触发链路(无 pass 时):
 *   __builtin_mul_overflow -> @llvm.umul.with.overflow.i64
 *   -> BPF 后端 lower 成 __multi3 调用 -> BPF ISel 拒绝("__multi3 not supported")
 *
 * BpfSoftFp pass 在 IR 层把 umul.with.overflow 展开成
 * 原生 mul i64(低位) + BPF_FP_UMULH(高位,走 softfp 通道),消除 __multi3 调用。
 *
 * 用 volatile 输入防常量折叠,强制走运行时 umul.with.overflow 路径。
 * 对照 x86 原生结果,全部断言通过则 exit(0),任一失败 exit(1)。
 *
 * 覆盖:
 *   - 不溢出(乘积在 64 位内)
 *   - 溢出(乘积超过 64 位)
 *   - schoolbook 进位链边界((2^32)^2、(2^32-1)^2、跨 32 位组合)
 *   - 极值(0 / UINT64_MAX / 2^63 等)
 */
#include <stdio.h>
#include <stdint.h>

static int fails = 0;

/* 包装 __builtin_mul_overflow 调用并断言乘积 + 溢出位。
   volatile 防常量折叠,确保走运行时 umul.with.overflow 路径。 */
#define CHECK_MUL(va, vb, expect_prod, expect_ovf, label) do { \
    volatile uint64_t _a = (va), _b = (vb); \
    uint64_t _prod = 0; \
    int _ovf = __builtin_mul_overflow(_a, _b, &_prod); \
    if (_prod != (uint64_t)(expect_prod) || _ovf != (expect_ovf)) { \
        printf("FAIL %s: a=0x%016llx b=0x%016llx got prod=0x%016llx ovf=%d, " \
               "expect prod=0x%016llx ovf=%d\n", \
               label, (unsigned long long)(va), (unsigned long long)(vb), \
               (unsigned long long)_prod, _ovf, \
               (unsigned long long)(expect_prod), (expect_ovf)); \
        fails++; \
    } \
} while (0)

int main(void) {
    /* === 不溢出(乘积在 64 位内)=== */
    CHECK_MUL(100, 200, 20000, 0, "100*200");
    CHECK_MUL(0, 0xFFFFFFFFFFFFFFFFULL, 0, 0, "0*UINT64_MAX");
    CHECK_MUL(1, 0xFFFFFFFFFFFFFFFFULL,
              0xFFFFFFFFFFFFFFFFULL, 0, "1*UINT64_MAX");
    /* (2^32-1)*(2^32+1) = 2^64 - 1,恰好不溢出 */
    CHECK_MUL(0xFFFFFFFFULL, 0x100000001ULL,
              0xFFFFFFFFFFFFFFFFULL, 0, "(2^32-1)*(2^32+1)");
    /* (2^63-1)*2 = 2^64 - 2,恰好不溢出 */
    CHECK_MUL(0x7FFFFFFFFFFFFFFFULL, 2,
              0xFFFFFFFFFFFFFFFEULL, 0, "(2^63-1)*2");
    /* 跨 32 位但乘积仍在 64 位内 */
    CHECK_MUL(0xFFFFFFFFULL, 0x100000000ULL,
              0xFFFFFFFF00000000ULL, 0, "(2^32-1)*2^32");

    /* === 溢出(乘积超过 64 位)=== */
    /* UINT64_MAX * 2:低 64 位 = 0xFFFFFFFFFFFFFFFE,溢出 */
    CHECK_MUL(0xFFFFFFFFFFFFFFFFULL, 2,
              0xFFFFFFFFFFFFFFFEULL, 1, "UINT64_MAX*2");
    /* UINT64_MAX^2 = 0xFFFFFFFFFFFFFFFE_0000000000000001:低 64 位 = 1,溢出 */
    CHECK_MUL(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
              1, 1, "UINT64_MAX^2");
    /* 2^63 * 2 = 2^64:低 64 位 = 0,溢出 */
    CHECK_MUL(0x8000000000000000ULL, 2,
              0, 1, "2^63*2");

    /* === schoolbook 进位链边界 === */
    /* (2^32)^2 = 2^64:低 64 位 = 0,高位 = 1,溢出 */
    CHECK_MUL(1ULL << 32, 1ULL << 32,
              0, 1, "(2^32)^2");
    /* (2^32-1)^2 = 0xFFFFFFFE00000001:恰好 64 位,不溢出
       (PLAN.md 草案曾误标"乘积 1 溢出 1",那是 32x32->64 的视角;
       64x64->128 视角下高位 = 0,不溢出) */
    CHECK_MUL(0xFFFFFFFFULL, 0xFFFFFFFFULL,
              0xFFFFFFFE00000001ULL, 0, "(2^32-1)^2");
    /* (2^32-1)*2^32 平方:c = (2^32-1)*2^32, c*c = (2^32-1)^2 * 2^64
       = 0xFFFFFFFE00000001_0000000000000000,
       低 64 位 = 0,高位 = 0xFFFFFFFE00000001,溢出(覆盖 high*high 项) */
    CHECK_MUL(0xFFFFFFFF00000000ULL, 0xFFFFFFFF00000000ULL,
              0, 1, "(2^32-1)*2^32 squared");
    /* (2^32+1)^2 = 0x1_00000002_00000001:低 64 位 = 0x0000000200000001,
       高位 = 1,溢出(cross 项 aH*bL + aL*bH 进位测试) */
    CHECK_MUL(0x100000001ULL, 0x100000001ULL,
              0x0000000200000001ULL, 1, "(2^32+1)^2");
    /* 2 * 2^32 * 3 * 2^32 = 6 * 2^64:低 64 位 = 0,高位 = 6,溢出
       (纯 high*high 项测试) */
    CHECK_MUL(0x200000000ULL, 0x300000000ULL,
              0, 1, "2*2^32 * 3*2^32");

    if (fails == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURES\n", fails);
    return 1;
}
