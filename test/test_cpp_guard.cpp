// __cxa_guard 多线程并发测试：验证 static 局部变量初始化守卫在并发下正确。
//
// 机制（见 port_cplusplus.md）：
//   - libc++abi 的 cxa_guard.cpp（GlobalMutex 实现：pthread_mutex + pthread_cond，
//     底层 musl 走 futex）提供 __cxa_guard_acquire/release/abort。
//   - 裸 syscall(SYS_futex, int*, ...) 经 bits/syscall.h 的 C++ 指针重载处理类型转换。
//
// 覆盖：
//   - 多线程并发首次调用含 static 局部的函数：static 变量只构造一次
//   - 构造期间其它线程阻塞等待（不读到半构造状态）
//   - 不同函数的 static 局部互不干扰
//
// host 变体用 g++ 编宿主 glibc，作为对照基线。

#include <pthread.h>
#include <cstdio>
#include <atomic>

static std::atomic<int> ctor_count{0};   // 全局构造计数（追踪 static 是否多次构造）

// 函数 A：static 局部，构造慢（模拟耗时初始化），构造时 ctor_count++
int func_a(int x) {
    static int val = []() {
        ctor_count.fetch_add(1);
        // 故意慢构造，放大竞态窗口——让其它线程在构造期间到达 func_a
        for (volatile int i = 0; i < 100000; i++) {}
        return 999;
    }();
    return val + x;
}

// 函数 B：另一个 static 局部，验证不同 guard 互不干扰
int func_b(int x) {
    static int val = []() {
        ctor_count.fetch_add(1);
        return 42;
    }();
    return val + x;
}

struct Arg {
    int (*fn)(int);
    int id;
    int result;
};

static void *worker(void *p) {
    auto *a = static_cast<Arg *>(p);
    // 多次调用，首次必经 guard，后续 fast path
    int sum = 0;
    for (int i = 0; i < 200; i++) sum += a->fn(a->id);
    a->result = sum;
    return nullptr;
}

int main() {
    const int N = 4;
    int failures = 0;

    // (1) 多线程并发首次调用 func_a：static val 只构造一次（ctor_count 只 +1）
    {
        ctor_count = 0;
        Arg args[N];
        pthread_t threads[N];
        for (int i = 0; i < N; i++) { args[i] = {func_a, i + 1, 0}; }
        for (int i = 0; i < N; i++) pthread_create(&threads[i], nullptr, worker, &args[i]);
        for (int i = 0; i < N; i++) pthread_join(threads[i], nullptr);

        if (ctor_count.load() != 1) {
            printf("FAIL func_a constructed %d times (expected 1)\n", ctor_count.load());
            failures++;
        }
        // val=999, 每个 worker sum = 200*(999 + id+1)
        for (int i = 0; i < N; i++) {
            int id = i + 1;
            int expected = 200 * (999 + id);
            if (args[i].result != expected) {
                printf("FAIL func_a worker %d result=%d expected=%d\n", id, args[i].result, expected);
                failures++;
            }
        }
        if (failures == 0) printf("[OK] concurrent func_a (single construction)\n");
    }

    // (2) func_a + func_b 混合并发：两个 guard 独立。
    // func_a 已在 (1) 构造过，此处不再构造；func_b 首次构造。ctor_count 增量应为 1。
    {
        ctor_count = 0;
        Arg args_a[N], args_b[N];
        pthread_t threads[N * 2];
        for (int i = 0; i < N; i++) { args_a[i] = {func_a, i, 0}; args_b[i] = {func_b, i, 0}; }
        for (int i = 0; i < N; i++) {
            pthread_create(&threads[i], nullptr, worker, &args_a[i]);
            pthread_create(&threads[N + i], nullptr, worker, &args_b[i]);
        }
        for (int i = 0; i < N * 2; i++) pthread_join(threads[i], nullptr);

        // func_a 已构造（增量 0）+ func_b 首次构造（增量 1）= ctor_count 增量 1
        if (ctor_count.load() != 1) {
            printf("FAIL mixed ctor_count delta=%d (expected 1)\n", ctor_count.load());
            failures++;
        }
        if (failures == 0) printf("[OK] mixed func_a + func_b (independent guards)\n");
    }

    // (3) 单线程基本正确性（构造后多次调用值稳定）
    {
        int r1 = func_a(1);
        int r2 = func_a(2);
        if (r1 != 1000 || r2 != 1001) {
            printf("FAIL single-thread func_a r1=%d r2=%d\n", r1, r2);
            failures++;
        }
        if (failures == 0) printf("[OK] single-thread func_a stability\n");
    }

    if (failures == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURE(S)\n", failures);
    return 1;
}
