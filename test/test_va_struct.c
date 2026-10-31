/* 结构体变参:BpfWideArgs 的 va 打包对聚合变参存指针(步长 8)——callee 的
 * va_arg 对聚合一律按引用(clang 生成 va_arg ap, ptr 再解引用),此前调用方
 * 按值内嵌与被调方错位,纯 C 传结构体变参即坏。
 * 已知残留:sizeof<=8 且可强转成单整数的结构体(如 {i32,i32})在调用点被
 * clang IRGen 强转成 i64,聚合信息已擦除,pass 无从归一化 —— 纯 C 传这类
 * 变参仍坏(ctypes 不受影响,ffi 侧类型完整,按引用传指针)。 */
#include <assert.h>
#include <stdint.h>
#include <stdarg.h>

typedef struct { int64_t a, b; } Pair16;

volatile Pair16 v16a = { 5, 6 };
volatile Pair16 v16b = { 7, 8 };
volatile int64_t tail = 9;

/* 单个 16B 结构体变参 */
__attribute__((noinline)) int64_t va_one(int32_t n, ...)
{
    va_list ap;
    va_start(ap, n);
    Pair16 p = va_arg(ap, Pair16);
    va_end(ap);
    return p.a * 100 + p.b + n;
}

/* 结构体后跟标量再跟结构体:验证 pack 步长推进(ptr 8B) */
__attribute__((noinline)) int64_t va_mixed(int32_t n, ...)
{
    va_list ap;
    va_start(ap, n);
    Pair16 q1 = va_arg(ap, Pair16);
    int64_t t = va_arg(ap, int64_t);
    Pair16 q2 = va_arg(ap, Pair16);
    va_end(ap);
    return q1.a + q1.b * 10 + t * 100 + q2.a * 1000 + q2.b * 10000;
}

/* __int128 变参:与聚合不同,va_arg i128 是直接 16B 载入(步长 allocSize),
 * 须按值内嵌,不得走指针分支 */
__attribute__((noinline)) int64_t va_i128(int32_t n, ...)
{
    va_list ap;
    va_start(ap, n);
    __int128 v = va_arg(ap, __int128);
    va_end(ap);
    return (int64_t)(v >> 64) + (int64_t)v;
}

int main(void)
{
    assert(va_one(1, v16a) == 5 * 100 + 6 + 1);
    assert(va_mixed(3, v16a, tail, v16b) == 5 + 60 + 900 + 7000 + 80000);
    __int128 x = (__int128)1 << 100 | 5;
    assert(va_i128(1, x) == (int64_t)((__int128)1 << 100 >> 64) + 5);
    return 0;
}
