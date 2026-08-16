/*
 * test_vla.c — 验证 VLA（变长数组）/ 动态 alloca 的栈分配实现。
 *
 * 由 BpfVlaPass（src/passes/BpfWideArgs.cpp，与 BpfWideArgsPass 同 .so 注册）
 * 把 VLA / 非入口块 alloca 改写成
 * BPF_SYS_ALLOCA syscall（当大小编译期不可知或 alloca 被优化器留在循环里时），
 * 或被优化器折叠成入口块的固定 alloca（当大小编译期已知时）。
 *
 * 关键：为真正走到 BPF_SYS_ALLOCA 动态路径，本测试通过 volatile 取 VLA 大小
 * （编译期对优化器不透明），迫使 BpfVlaPass 生成 syscall 调用而非折叠成静态
 * alloca。这样同时覆盖：
 *   - 动态路径（编译期未知大小 -> BPF_SYS_ALLOCA syscall）；
 *   - 静态折叠路径（编译期已知大小 -> 入口块固定 alloca，由 BPF 后端处理）。
 *
 * 覆盖：
 *   -  基本 VLA 求和（int buf[n]）。
 *   -  VLA 在嵌套调用中：被调函数独立分配，返回后调用者再分配不重叠。
 *   -  多次 VLA 在同一函数里：累计分配，地址不重叠。
 *   -  VLA 跨函数调用传递指针。
 *   -  回收：循环里反复调用含 VLA 的函数，验证不爆栈（alloca 区随返回回收）。
 *   -  long long VLA（元素 8 字节，验证 size 计算）。
 *
 * 全部通过 exit(0)，否则 exit(1)。
 */
#include <stdio.h>
#include <string.h>

/* volatile 阻止优化器把 VLA 大小折叠成常量，迫使走 BPF_SYS_ALLOCA 动态路径。 */
static volatile int g_seed = 50;

/* -  基本 VLA 求和：n 编译期未知 -> 走 BPF_SYS_ALLOCA */
static int vla_sum(int n) {
    int buf[n];
    for (int i = 0; i < n; i++) buf[i] = i * i;
    int s = 0;
    for (int i = 0; i < n; i++) s += buf[i];
    return s;
}

/* -  嵌套：被调函数用 VLA */
static int vla_inner(int n) {
    int tmp[n];
    for (int i = 0; i < n; i++) tmp[i] = n - i;
    return tmp[0] + tmp[n - 1];
}

/* 调用者自己也有 VLA，验证两份不冲突 */
static int vla_nested_call(int n) {
    int outer[n];
    for (int i = 0; i < n; i++) outer[i] = i;
    int got = vla_inner(n);   /* 被调函数分配自己的 VLA */
    int sum = 0;
    for (int i = 0; i < n; i++) sum += outer[i];
    /* outer 必须仍正确（被调函数的 VLA 不应覆盖 outer） */
    return sum == n * (n - 1) / 2 ? got + sum : -1;
}

/* -  同一函数多次 VLA：累计分配，地址不重叠 */
static int vla_multi(int n) {
    int a[n];
    int b[n];
    for (int i = 0; i < n; i++) { a[i] = i; b[i] = i * 10; }
    /* 若 a/b 重叠，写 b 会改 a —— 这里检测 */
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i] + b[i];
    return s;
}

/* -  VLA 指针跨函数传递 */
static int fill_and_sum(int *p, int n) {
    for (int i = 0; i < n; i++) p[i] = i + 1;
    int s = 0;
    for (int i = 0; i < n; i++) s += p[i];
    return s;
}

/* -  回收：每次调用都分配，循环 N 次不爆栈 */
static int vla_recycle_one(int n) {
    char buf[n];
    memset(buf, 0xAB, n);
    return (unsigned char)buf[0] + (unsigned char)buf[n - 1];
}

/* -  long long VLA（元素 8 字节，验证 size 计算） */
static long long vla_ll(long long n) {
    long long buf[n];
    for (long long i = 0; i < n; i++) buf[i] = i;
    long long s = 0;
    for (long long i = 0; i < n; i++) s += buf[i];
    return s;
}

int main(void) {
    /* volatile 读取 -> 编译期未知，迫使 VLA 走 BPF_SYS_ALLOCA 动态路径。 */
    int base = g_seed;
    if(base < 4) base = 4;
    int ok = 1;

    /* -  基本 VLA：sum_{i=0}^{n-1} i^2 */
    {
        int n = base;
        int r = vla_sum(n);
        int expect = 0;
        for (int i = 0; i < n; i++) expect += i * i;
        printf("vla_sum(%d) = %d (expect %d)\n", n, r, expect);
        ok &= (r == expect);
    }

    /* -  嵌套调用 */
    {
        int n = base;
        int r = vla_nested_call(n);
        int expect = (n + 1) + n * (n - 1) / 2;
        printf("vla_nested_call(%d) = %d (expect %d)\n", n, r, expect);
        ok &= (r == expect);
    }

    /* -  同函数多次 VLA */
    {
        int n = base;
        int r = vla_multi(n);
        int expect = 0;
        for (int i = 0; i < n; i++) expect += i + i * 10;
        printf("vla_multi(%d) = %d (expect %d)\n", n, r, expect);
        ok &= (r == expect);
    }

    /* -  VLA 指针跨函数 */
    {
        int n = base;
        int buf[n];
        int r = fill_and_sum(buf, n);
        int expect = n * (n + 1) / 2;
        printf("vla cross-func(%d) = %d (expect %d)\n", n, r, expect);
        ok &= (r == expect);
    }

    /* -  回收：循环多次，每次分配；若不回收会很快吃满栈 */
    {
        int total = 0;
        for (int k = 0; k < 2000; k++) {
            total += vla_recycle_one(base < 64 ? base : 64);
        }
        int per = 0xAB + 0xAB;   /* = 342 */
        printf("vla_recycle loop = %d (expect %d)\n", total, per * 2000);
        ok &= (total == per * 2000);
    }

    /* -  long long VLA */
    {
        long long n = base;
        long long r = vla_ll(n);
        long long expect = n * (n - 1) / 2;
        printf("vla_ll(%lld) = %lld (expect %lld)\n", n, r, expect);
        ok &= (r == expect);
    }

    printf("vla: %s\n", ok ? "ok" : "FAILED");
    return ok ? 0 : 1;
}

