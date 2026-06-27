/*
 * test_wideargs.c — 验证 BpfWideArgs pass 插件（突破 BPF 5 参数限制 + 返回结构体）。
 *
 * 依赖编译时启用 -fpass-plugin=libBpfWideArgs.so（由 test/Makefile 自动注入）。
 * 若未启用插件，>5 参数函数在编译期就会被 clang 拒绝，本测试根本无法生成 .out。
 *
 * 覆盖：
 *   - 恰好 6 参数（标量，第 5/6 个被打包进结构体）
 *   - 8 参数（不同类型混合）
 *   - 返回结构体（小 + 大）
 *   - 6/7/8 参数 + 返回结构体的各种组合（>5参数与sret叠加）
 *   - 嵌套调用（>5参数+返回结构体 的函数调用另一个同类函数）
 *   - 多次调用同一函数（验证 sret 缓冲区独立性，不被污染）
 *   - 边界值（全 0 参数）
 *   - 递归（重入安全：每次调用栈结构体独立）
 *   - 通过函数指针间接调用 >5 参函数（含 sret 组合）
 *
 * 全部断言通过则 exit(0)，任一失败 exit(1)。
 */
#include <stdint.h>
#include <stdlib.h>

/* 断言宏：失败时 exit(1)，便于 ctest 判定 */
#define CHECK(cond) do { \
    if (!(cond)) exit(1); \
} while (0)

/* ---- 6 参数：纯标量 ---- */
__attribute__((noinline))
int add6(int a, int b, int c, int d, int e, int f) {
    return a + b + c + d + e + f;
}

/* ---- 8 参数：long 混合 ---- */
__attribute__((noinline))
long add8(long a, long b, long c, long d, long e, long g, long h, long i) {
    return a + b + c + d + e + g + h + i;
}

/* ---- 返回小结构体 ---- */
struct Point { int x; int y; };
__attribute__((noinline))
struct Point make_point(int x, int y) {
    struct Point p = {x, y};
    return p;
}

/* ---- 返回大结构体 ---- */
struct Quad { long a; long b; long c; long d; };
__attribute__((noinline))
struct Quad make_quad(long x) {
    struct Quad q = {x, x * 2, x * 3, x * 4};
    return q;
}

/* ---- 6 参数 + 返回结构体（sret 与打包组合）---- */
__attribute__((noinline))
struct Quad compute6(long x1, long x2, long x3, long x4, long x5, long x6) {
    struct Quad q;
    q.a = x1 + x2 + x3;
    q.b = x4 + x5;
    q.c = x6;
    q.d = x6 * 2;
    return q;
}

/* ---- 7 参数 + 返回结构体（更激进的组合：5个标量 + 打包2个 + sret指针）---- */
struct Pair { long lo; long hi; };
__attribute__((noinline))
struct Pair compute7(long x1, long x2, long x3, long x4, long x5, long x6, long x7) {
    struct Pair p;
    p.lo = x1 + x2 + x3 + x4;          /* 用前 4 个 */
    p.hi = x5 + x6 + x7;               /* 用打包的 3 个 */
    return p;
}

/* ---- 8 参数 + 返回结构体（极限组合：前4标量 + 打包4个 + sret）---- */
__attribute__((noinline))
struct Quad compute8(long x1, long x2, long x3, long x4,
                     long x5, long x6, long x7, long x8) {
    struct Quad q;
    q.a = x1 + x5;
    q.b = x2 + x6;
    q.c = x3 + x7;
    q.d = x4 + x8;
    return q;
}

/* ---- 嵌套：一个 >5参数+返回结构体 的函数调用另一个 ---- */
__attribute__((noinline))
struct Quad nested_caller(long base) {
    /* 内部调 compute6（自身也是 6 参数 + 返回结构体）*/
    return compute6(base, base+1, base+2, base+3, base+4, base+5);
}

/* ---- 递归（验证重入安全：每次调用栈结构体独立）---- */
__attribute__((noinline))
long fac6(long n, long acc, long p3, long p4, long p5, long p6) {
    if (n <= 1) return acc;
    return fac6(n - 1, acc * n, p3, p4, p5, p6);
}

int main(void) {
    /* 6 参数 */
    CHECK(add6(10, 20, 30, 40, 50, 60) == 210);

    /* 8 参数 */
    CHECK(add8(1, 2, 3, 4, 5, 6, 7, 8) == 36);

    /* 返回小结构体 */
    {
        struct Point p = make_point(3, 4);
        CHECK(p.x == 3 && p.y == 4);
    }

    /* 返回大结构体 */
    {
        struct Quad q = make_quad(10);
        CHECK(q.a == 10 && q.b == 20 && q.c == 30 && q.d == 40);
    }

    /* === ">5参数 + 返回结构体" 组合专项 === */

    /* 6 参数 + 返回结构体 */
    {
        struct Quad q = compute6(1, 2, 3, 4, 5, 6);
        /* a=1+2+3=6, b=4+5=9, c=6, d=12 */
        CHECK(q.a == 6 && q.b == 9 && q.c == 6 && q.d == 12);
    }

    /* 7 参数 + 返回结构体 */
    {
        struct Pair p = compute7(1, 2, 3, 4, 5, 6, 7);
        /* lo=1+2+3+4=10, hi=5+6+7=18 */
        CHECK(p.lo == 10 && p.hi == 18);
    }

    /* 8 参数 + 返回结构体（极限：前4标量+打包4个+sret）*/
    {
        struct Quad q = compute8(100, 200, 300, 400, 1, 2, 3, 4);
        /* a=100+1=101, b=200+2=202, c=300+3=303, d=400+4=404 */
        CHECK(q.a == 101 && q.b == 202 && q.c == 303 && q.d == 404);
    }

    /* 边界值：全 0 */
    {
        struct Quad q = compute8(0, 0, 0, 0, 0, 0, 0, 0);
        CHECK(q.a == 0 && q.b == 0 && q.c == 0 && q.d == 0);
    }

    /* 嵌套调用：>5参数+返回结构体 的函数里再调一个同类函数 */
    {
        struct Quad q = nested_caller(10);
        /* compute6(10,11,12,13,14,15): a=33, b=27, c=15, d=30 */
        CHECK(q.a == 33 && q.b == 27 && q.c == 15 && q.d == 30);
    }

    /* 多次调用同一函数：验证 sret 缓冲区每次独立（不被上一次污染）*/
    {
        struct Quad q1 = compute6(1, 1, 1, 1, 1, 1);   /* a=3,b=2,c=1,d=2 */
        struct Quad q2 = compute6(10, 10, 10, 10, 10, 10); /* a=30,b=20,c=10,d=20 */
        CHECK(q1.a == 3 && q1.b == 2 && q1.c == 1 && q1.d == 2);
        CHECK(q2.a == 30 && q2.b == 20 && q2.c == 10 && q2.d == 20);
        /* 再查一次 q1，确认没被 q2 调用破坏 */
        CHECK(q1.a == 3 && q1.d == 2);
    }

    /* 递归：fac6(5,1,...) = 5! = 120，且 p3-p6 透传不变（验证每次调用独立）*/
    CHECK(fac6(5, 1, 7, 8, 9, 10) == 120);

    /* 通过函数指针调用 >5 参函数（间接调用）：pass 把间接调用点也改写成新 ABI
     * （前 4 个走寄存器，剩余的塞 SharedBuf，末尾追加 pack 指针），故通过 fp
     * 发起的调用与直接调用语义一致。
     * volatile 防止编译器把 fp 折叠成直接调用，确保走间接调用路径。 */
    {
        int (*volatile fp)(int, int, int, int, int, int) = add6;
        CHECK(fp(1, 2, 3, 4, 5, 6) == 21);
        CHECK(fp(10, 20, 30, 40, 50, 60) == 210);
        /* 直接调用对照，确认两条路径结果一致 */
        CHECK(add6(1, 2, 3, 4, 5, 6) == 21);
    }

    /* 间接调用 8 参函数（long pack）+ sret 组合 */
    {
        long (*volatile fp)(long, long, long, long, long, long, long, long) = add8;
        CHECK(fp(1, 2, 3, 4, 5, 6, 7, 8) == 36);
    }
    {
        struct Quad (*volatile fp)(long, long, long, long, long, long) = compute6;
        struct Quad q = fp(1, 2, 3, 4, 5, 6);   /* a=6,b=9,c=6,d=12 */
        CHECK(q.a == 6 && q.b == 9 && q.c == 6 && q.d == 12);
    }

    return 0;
}
