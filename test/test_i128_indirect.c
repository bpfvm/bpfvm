/* __int128 返回值函数的间接调用：lowerI128Returns 把 callee 改写为
 * void(ptr sret, ...)，但调用点改写只覆盖直接调用——经函数指针调用时调用点
 * 仍持 i128(...) 旧签名：callee 把首个实参当 sret 指针写、caller 读 r0 当
 * 返回值，静默错乱。pass 现按调用点自身类型无条件改写间接调用点（与聚合实参
 * 归一化同一论证：能编译的目标必然已是新签名）。
 * 覆盖：双目标分发、返回值链式使用/忽略、sret+>5 参 pack 组合（总槽 7）、
 * 变参 + i128 返回组合（lowerI128Returns 与 va 改写的叠加）。 */
#include <assert.h>
#include <stdint.h>
#include <stdarg.h>

static __attribute__((noinline)) __int128 mk(uint64_t lo, uint64_t hi) {
    return ((__int128)hi << 64) | lo;
}
static __attribute__((noinline)) __int128 mk1(uint64_t lo, uint64_t hi) {
    return ((__int128)hi << 64) | lo | 1;
}

/* sret + 6 实参：sret 指针后共 7 槽 > 5，第 5 槽起进 pack */
static __attribute__((noinline)) __int128 combine6(uint64_t a, uint64_t b, uint64_t c,
                                                   uint64_t d, uint64_t e, uint64_t f) {
    return ((__int128)a << 64) | (b + 2 * c + 3 * d + 4 * e + 5 * f);
}

/* 变参 + i128 返回 */
static __attribute__((noinline)) __int128 va_ret(int n, ...) {
    va_list ap;
    va_start(ap, n);
    uint64_t lo = va_arg(ap, uint64_t);
    uint64_t hi = va_arg(ap, uint64_t);
    va_end(ap);
    return ((__int128)hi << 64) | lo;
}

int main(void) {
    const uint64_t lo = 0x123456789ABCDEF0ULL, hi = 0xFEDCBA9876543210ULL;

    __int128 (*volatile fp)(uint64_t, uint64_t) = mk;
    __int128 v = fp(lo, hi);
    assert((uint64_t)v == lo && (uint64_t)(v >> 64) == hi);

    /* 双目标分发：真间接 */
    fp = mk1;
    __int128 w = fp(lo, hi);
    assert((uint64_t)w == (uint64_t)(lo | 1) && (uint64_t)(w >> 64) == hi);

    /* 返回值链式使用与忽略 */
    assert((uint64_t)fp(lo, hi) == (uint64_t)(lo | 1));
    fp(lo, hi);

    /* sret + pack 组合 */
    __int128 (*volatile fp6)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) = combine6;
    __int128 s = fp6(hi, lo, 1, 2, 3, 4);
    assert((uint64_t)(s >> 64) == hi);
    assert((uint64_t)s == lo + 2 + 6 + 12 + 20);

    /* 变参 + i128 返回 */
    __int128 (*volatile fpv)(int, ...) = va_ret;
    __int128 t = fpv(2, lo, hi);
    assert((uint64_t)t == lo && (uint64_t)(t >> 64) == hi);
    return 0;
}
