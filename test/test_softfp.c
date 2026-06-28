#include <stdio.h>
#include <stdint.h>

/* 软件浮点运行时验证（JIT 原生 SSE 短路 + 解释器 syscall shim 共用此用例）。
   用 volatile 阻止常量折叠，强制浮点运算在 VM 运行时执行（经 BpfSoftFp pass
   把运算直接编成 caller 里的 BPF_CALL_FP_* call → VM do_softfp / JIT SSE 执行）。

   返回 0 表示全部通过，非 0 表示失败。所有结果以整数形式打印（避开 printf %f
   的 PDCLib 打印器，独立验证算术正确性）。 */

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL %s\n", msg); fails++; } } while (0)

int main(void) {
    /* volatile 阻止编译期折叠 */
    volatile double a = 1.5;
    volatile double b = 2.0;

    /* 算术。-0.5 和 0.75 都向 0 截断成 0。 */
    if ((int)(a + b) != 3)   { printf("FAIL add: %d\n", (int)(a+b));     fails++; }
    if ((int)(a - b) != 0)   { printf("FAIL sub: %d\n", (int)(a-b));     fails++; }
    if ((int)(a * b) != 3)   { printf("FAIL mul: %d\n", (int)(a*b));     fails++; }
    if ((int)(a / b) != 0)   { printf("FAIL div: %d\n", (int)(a/b));     fails++; }

    /* 更大的值，验证非平凡运算 */
    volatile double c = 3.0;
    if ((int)(c * c) != 9)   { printf("FAIL mul2: %d\n", (int)(c*c));    fails++; }
    volatile double d = 10.0;
    if ((int)(d / c) != 3)   { printf("FAIL div2: %d\n", (int)(d/c));    fails++; }

    /* int <-> double 转换（有符号源 / 有符号目标） */
    volatile int i = 7;
    if ((int)((double)i + 0.5) != 7) { printf("FAIL i2d: %d\n", (int)((double)i+0.5)); fails++; }
    volatile double g = 9.0;
    if ((int)(double)123 != 123) { printf("FAIL si2d\n"); fails++; }
    /* int32 -> double -> 截断回 int */
    if ((int)(double)(-5) != -5) { printf("FAIL neg_si2d\n"); fails++; }

    /* 比较 */
    if (!(a < b))  { printf("FAIL lt\n");  fails++; }
    if (!(b > a))  { printf("FAIL gt\n");  fails++; }
    if (!(a != b)) { printf("FAIL ne\n"); fails++; }
    if (!(a <= 1.5)) { printf("FAIL le\n"); fails++; }
    if (!(b >= 2.0)) { printf("FAIL ge\n"); fails++; }
    if (!(a == 1.5)) { printf("FAIL eq\n"); fails++; }

    /* float 路径 */
    volatile float fa = 1.5f, fb = 2.0f;
    if ((int)(fa + fb) != 3) { printf("FAIL fadd: %d\n", (int)(fa+fb)); fails++; }
    if ((int)(fa * fb) != 3) { printf("FAIL fmul: %d\n", (int)(fa*fb)); fails++; }
    if ((int)(fb - fa) != 0) { printf("FAIL fsub\n"); fails++; }
    if ((int)(fa / fb) != 0) { printf("FAIL fdiv\n"); fails++; }
    /* float 比较 */
    if (!(fa < fb))  { printf("FAIL flt\n");  fails++; }
    if (!(fb > fa))  { printf("FAIL fgt\n");  fails++; }
    if (!(fa != fb)) { printf("FAIL fne\n"); fails++; }

    /* float<->double 互转 */
    volatile double d2 = (double)fa;       /* fpext */
    if ((int)(d2 + 0.5) != 2) { printf("FAIL fpext\n"); fails++; }
    volatile float f2 = (float)b;          /* fptrunc */
    if ((int)f2 != 2) { printf("FAIL fptrunc\n"); fails++; }

    /* 取负 */
    volatile double neg = -(a);            /* fneg */
    if (!(neg < 0)) { printf("FAIL dneg\n"); fails++; }
    volatile float fneg = -(fa);
    if (!(fneg < 0)) { printf("FAIL fneg\n"); fails++; }

    /* int64 -> double（double 来自强制转换会走 DI2D）*/
    volatile long li = 1000000;
    if ((int)((double)li / 1000.0) != 1000) { printf("FAIL di2d\n"); fails++; }

    /* double -> int64（D2DI）*/
    volatile double big = 2147483647.0;     /* INT_MAX */
    if ((long)big != 2147483647L) { printf("FAIL d2di\n"); fails++; }

    /* —— 边界 / 负值 / 混合序列（重点压 JIT 原生 SSE 短路）—— */

    /* 负数算术 */
    volatile double na = -1.5;
    volatile double nb = 2.0;
    if ((int)(na + nb) != 0) { printf("FAIL neg_add\n"); fails++; }      /* 0.5 → 0 */
    if ((int)(na - nb) != -3) { printf("FAIL neg_sub\n"); fails++; }     /* -3.5 → -3 */
    if ((int)(na * nb) != -3) { printf("FAIL neg_mul\n"); fails++; }     /* -3.0 */
    if ((int)(na / nb) != 0) { printf("FAIL neg_div\n"); fails++; }      /* -0.75 → 0 */
    /* 截断方向：负数向 0 截断（不是向下取整）*/
    if ((int)(double)(-7) != -7) { printf("FAIL neg_trunc\n"); fails++; }
    if ((long)(double)(-1234567890123LL) != -1234567890123LL) { printf("FAIL neg_d2di\n"); fails++; }

    /* float 负值与转换 */
    volatile float nfa = -1.5f;
    if ((int)nfa != -1) { printf("FAIL fneg_d2si\n"); fails++; }
    if ((int)(float)(-9) != -9) { printf("FAIL neg_si2f\n"); fails++; }

    /* sqrt —— PDCLib 只实现了 fabs/fmin/fmax 等少数函数，没有 sqrt/sin/cos/pow/
       floor/ceil 等（math.h 里有声明但无实现，链不上）。sqrt 之所以可用，是因为
       -fno-math-errno 让 __builtin_sqrt 折叠成 @llvm.sqrt intrinsic，BpfSoftFp pass
       把它 lower 成 BPF_CALL_FP_SQRT_D/F，VM 侧用宿主硬件 sqrtsd/fsqrt 执行。
       下面覆盖 sqrt 的 D/F 两条 lowering（含非完全平方数，验宿主硬件精度）。*/
    {
        volatile double sq = 16.0;
        if ((int)__builtin_sqrt(sq) != 4) { printf("FAIL sqrt_d\n"); fails++; }
        volatile double sq2 = 2.0;
        /* sqrt(2)≈1.4142，截断到 int 是 1 */
        if ((int)__builtin_sqrt(sq2) != 1) { printf("FAIL sqrt_d_irr\n"); fails++; }
    }
    {
        volatile float sq = 25.0f;
        if ((int)__builtin_sqrtf(sq) != 5) { printf("FAIL sqrt_f\n"); fails++; }
    }

    /* 无符号整型 ↔ 浮点转换。这是 x86 与 aarch64 行为最容易分叉的一组：
       aarch64 有原生 FCVTZU/UCVTF 全部原生处理，x86 无直接指令（缺 unsigned
       fp↔int 转换，需 AVX-512）走 do_softfp 回退。两端必须语义一致。 */
    {
        /* unsigned int/long -> double/float（值 > INT_MAX 才能区分有/无符号解释）*/
        volatile unsigned u32 = 4000000000u;          /* > INT_MAX(2147483647) */
        if ((int)(double)u32 != -294967296) {         /* 4e9 截到 int32 */
            printf("FAIL usi2d: %d\n", (int)(double)u32); fails++;
        }
        volatile unsigned long u64 = 18446744073709551615ULL;  /* UINT64_MAX */
        {
            double d = (double)u64;                   /* ≈ 1.8e19 */
            if (!(d > 1.8e19)) { printf("FAIL udi2d\n"); fails++; }
        }
        volatile unsigned u32f = 4294967295u;
        if (!((float)u32f > 4.0e9f)) { printf("FAIL usi2f\n"); fails++; }

        /* double/float -> unsigned int/long */
        volatile double d2u = 4294967296.0;           /* 2^32，正好等于 UINT_MAX+1 */
        if ((unsigned long)d2u != 4294967296UL) {
            printf("FAIL d2udi: %lu\n", (unsigned long)d2u); fails++;
        }
        volatile double d2u2 = 4000000000.0;          /* > INT_MAX */
        if ((unsigned)d2u2 != 4000000000u) {
            printf("FAIL d2usi: %u\n", (unsigned)d2u2); fails++;
        }
        volatile float f2u = 4294967296.0f;           /* 2^32 */
        if ((unsigned long)f2u != 4294967296UL) { printf("FAIL f2udi\n"); fails++; }
        volatile float f2u2 = 4000000000.0f;
        if ((unsigned)f2u2 != 4000000000u) {
            printf("FAIL f2usi: %u\n", (unsigned)f2u2); fails++;
        }

        /* unsigned long -> double 往返（再截回 unsigned long 验无损路径）*/
        volatile unsigned long big = 9223372036854775808ULL; /* 2^63，符号位为 1 */
        if ((unsigned long)(double)big != 9223372036854775808ULL) {
            printf("FAIL udi2d_roundtrip\n"); fails++;
        }
    }

    /* 比较的负数/相等边界 */
    volatile double e1 = 2.0, e2 = 2.0;
    if (!(e1 == e2)) { printf("FAIL eq2\n"); fails++; }
    if (!(-3.0 < -2.0)) { printf("FAIL neg_lt\n"); fails++; }
    if (!(-2.0 > -3.0)) { printf("FAIL neg_gt\n"); fails++; }

    /* NaN 比较（IEEE754：NaN 与任何值（含自身）的所有 <,>,<=,>=,== 均为假，
       != 均为真）。直接赋值 NAN 常量会被编译期折叠，故用 union 构造 QNaN 的
       位模式（0x7ff8...，符号位 0、指数全 1、尾数最高位 1）并以 volatile 防
       常量传播，强制走运行时 CMP+UNORD 双原语路径。 */
    {
        volatile union { uint64_t u; double d; } un;
        un.u = 0x7ff8000000000000ULL;
        volatile double nan = un.d;
        /* nan 与自身 */
        if (nan == nan) { printf("FAIL nan_eq_nan\n"); fails++; }
        if (!(nan != nan)) { printf("FAIL nan_ne_nan\n"); fails++; }
        /* nan 与 1.0：所有有序比较都应为假 */
        if (nan < 1.0)  { printf("FAIL nan_lt\n");  fails++; }
        if (nan > 1.0)  { printf("FAIL nan_gt\n");  fails++; }
        if (nan <= 1.0) { printf("FAIL nan_le\n"); fails++; }
        if (nan >= 1.0) { printf("FAIL nan_ge\n"); fails++; }
        if (nan == 1.0) { printf("FAIL nan_eq\n"); fails++; }
        if (!(nan != 1.0)) { printf("FAIL nan_ne\n"); fails++; }
        /* 1.0 与 nan：同上 */
        if (1.0 < nan)  { printf("FAIL lt_nan\n");  fails++; }
        if (1.0 > nan)  { printf("FAIL gt_nan\n");  fails++; }
        if (1.0 <= nan) { printf("FAIL le_nan\n"); fails++; }
        if (1.0 >= nan) { printf("FAIL ge_nan\n"); fails++; }
        if (1.0 == nan) { printf("FAIL eq_nan\n"); fails++; }
        if (!(1.0 != nan)) { printf("FAIL ne_nan\n"); fails++; }

        /* float 版 NaN（位模式：0x7fc00000，单精度 QNaN） */
        volatile union { uint32_t u; float f; } unf;
        unf.u = 0x7fc00000u;
        volatile float fnan = unf.f;
        if (fnan == fnan) { printf("FAIL fnan_eq_nan\n"); fails++; }
        if (!(fnan != fnan)) { printf("FAIL fnan_ne_nan\n"); fails++; }
        if (fnan < 1.0f) { printf("FAIL fnan_lt\n"); fails++; }
        if (fnan > 1.0f) { printf("FAIL fnan_gt\n"); fails++; }
        if (fnan == 1.0f) { printf("FAIL fnan_eq\n"); fails++; }
        if (1.0f == fnan) { printf("FAIL feq_nan\n"); fails++; }
    }

    /* fpext/fptrunc 保留负号 */
    volatile float nf = -2.5f;
    if ((int)(double)nf != -2) { printf("FAIL neg_fpext\n"); fails++; }
    volatile double nd = -3.7;
    if ((int)(float)nd != -3) { printf("FAIL neg_fptrunc\n"); fails++; }

    if (fails == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURES\n", fails);
    return 1;
}
