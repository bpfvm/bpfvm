/* 间接调用 + 聚合实参：BpfWideArgs 对间接调用点同样归一化聚合参数
 * （值 -> 裸指针，与直接调用/被改写被调方同一约定）。此前间接调用点保持
 * clang 原生按构成展开（9-16B 拆两个寄存器、>5 参时 pack 内嵌 16B），与
 * 被调方（恒读指针 / pack 字段 8B）布局错位，纯 C 经函数指针传 9-16B
 * 结构体是静默错乱。≤8B（单寄存器内嵌）与 >16B（byval 指针）两种约定
 * 本就一致，一并覆盖。 */
#include <assert.h>
#include <stdint.h>

typedef struct { int64_t a, b; } Pair;      /* 16B：归一化为指针 */
typedef struct { int32_t a, b; } Point;     /* 8B：单寄存器内嵌 */
typedef struct { int64_t a, b, c; } Triple; /* 24B：byval 指针 */

__attribute__((noinline)) int64_t real_s16(Pair p, int64_t x)
{ return p.a * 1000 + p.b * 10 + x; }
__attribute__((noinline)) int64_t real_s8(Point p, int64_t x)
{ return p.a * 1000 + p.b * 10 + x; }
__attribute__((noinline)) int64_t real_s24(Triple p)
{ return p.a * 10000 + p.b * 100 + p.c; }
/* >5 参 + 16B 结构体落在 pack 区：归一化后 pack 字段为 8B 指针 */
__attribute__((noinline)) int64_t real_pack(int64_t a, int64_t b, int64_t c,
                                            int64_t d, Pair e, int64_t f)
{ return a + 2 * b + 3 * c + 4 * d + e.a * 100 + e.b + f; }

__attribute__((noinline)) Pair real_sret(int64_t x) { Pair r = { x, x * 2 }; return r; }

int main(void)
{
    /* 结构体返回的间接调用:sret 隐藏指针经 r1 */
    Pair (*volatile fps)(int64_t) = real_sret;
    Pair pr = fps(21);
    assert(pr.a == 21 && pr.b == 42);
    /* volatile 函数指针：禁止编译器把间接调用退化成直接调用 */
    int64_t (*volatile fp16)(Pair, int64_t) = real_s16;
    int64_t (*volatile fp8)(Point, int64_t) = real_s8;
    int64_t (*volatile fp24)(Triple) = real_s24;
    int64_t (*volatile fpp)(int64_t, int64_t, int64_t, int64_t, Pair,
                            int64_t) = real_pack;

    assert(fp16((Pair){7, 8}, 9) == 7 * 1000 + 8 * 10 + 9);
    assert(fp8((Point){7, 8}, 9) == 7 * 1000 + 8 * 10 + 9);
    assert(fp24((Triple){7, 8, 9}) == 7 * 10000 + 8 * 100 + 9);
    assert(fpp(1, 2, 3, 4, (Pair){5, 6}, 7) == 1 + 4 + 9 + 16 + 500 + 6 + 7);
    return 0;
}
