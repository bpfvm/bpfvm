// STL <barrier> 测试：验证 std::barrier 在 bpfvm 上正确工作。
//
// 背景：<barrier> 头默认的 tree barrier 实现里 __barrier_phase_t = uint8_t，
// 触发 1 字节 atomic cmpxchg——BPF 后端原生只支持 32/64 位原子，原本编不过
// （"unsupported atomic operation, please use 32/64 bit version"）。现已由
// BpfWideArgs.cpp 的 BpfAtomicLowerPass（子字节 CAS 循环展开，照搬 LLVM
// AtomicExpandPass）解锁，barrier.cpp 已纳入 libcxx.a。本测试端到端验证：
//   1) #include <barrier> 能链接（__construct/__arrive/__destroy_barrier_algorithm_base
//      三个非内联符号在 libcxx.a 中）；
//   2) std::barrier::arrive/arrive_and_wait/arrive_and_drop 的同步语义正确。
//
// host 变体用 clang++ 编宿主 glibc，作为对照基线。
//
// 注意：①刻意避免 std::atomic——eBPF ISA 无 plain atomic load/store（C++ <atomic>
// 的 load/store 会撞 BPF 后端，见 BpfAtomicLowerPass 的 D1 注释），改用 mutex
// 保护普通 int；②所有同步靠 barrier.arrive_and_wait / join 显式定序，不依赖时序，
// 保证 host 与 BPF（单核解释/JIT）行为一致。

#include <barrier>
#include <thread>
#include <mutex>
#include <vector>
#include <cstdio>

int main() {
    int failures = 0;

    // (1) 单阶段 barrier：N 个线程全部到达后一起放行，验证基本 arrive_and_wait 语义。
    //     每个线程在屏障前后分别 ++before / ++after（mutex 保护）。屏障保证全部"前半段"
    //     先完成，再开始"后半段"。
    {
        const int N = 4;
        std::mutex m;
        int before = 0, after = 0;
        std::barrier sync(N);
        std::vector<std::thread> ts;
        for (int i = 0; i < N; ++i) {
            ts.emplace_back([&] {
                { std::lock_guard<std::mutex> lk(m); ++before; }
                sync.arrive_and_wait();
                { std::lock_guard<std::mutex> lk(m); ++after; }
            });
        }
        for (auto &t : ts) t.join();
        if (before != N || after != N) {
            printf("FAIL single-phase: before=%d after=%d (expect %d/%d)\n",
                   before, after, N, N);
            ++failures;
        }
    }

    // (2) 多阶段复用：同一屏障复用 ROUNDS 轮，验证 phase 推进正确。
    //     每轮每个线程 ++counter，ROUNDS 轮后 counter 应 == N*ROUNDS。
    {
        const int N = 4;
        const int ROUNDS = 5;
        std::mutex m;
        long counter = 0;
        std::barrier sync(N);
        std::vector<std::thread> ts;
        for (int i = 0; i < N; ++i) {
            ts.emplace_back([&] {
                for (int r = 0; r < ROUNDS; ++r) {
                    { std::lock_guard<std::mutex> lk(m); ++counter; }
                    sync.arrive_and_wait();
                }
            });
        }
        for (auto &t : ts) t.join();
        if (counter != (long)N * ROUNDS) {
            printf("FAIL reuse: counter=%ld (expect %d)\n", counter, N * ROUNDS);
            ++failures;
        }
    }

    // (3) arrive_and_drop：主线程参与第 1 轮后退出，后续轮次的 expected 自动减 1。
    //     验证 barrier 的动态参与人数调整。N-1 个 worker 跑 ROUNDS 轮，主线程跑 1 轮后 drop。
    {
        const int N = 4;
        const int ROUNDS = 3;
        std::mutex m;
        long counter = 0;
        std::barrier sync(N);
        std::vector<std::thread> ts;
        for (int i = 0; i < N - 1; ++i) {
            ts.emplace_back([&] {
                for (int r = 0; r < ROUNDS; ++r) {
                    { std::lock_guard<std::mutex> lk(m); ++counter; }
                    sync.arrive_and_wait();
                }
            });
        }
        // 主线程：参与第 1 轮，然后 drop（后续轮次 expected = N-1）。
        { std::lock_guard<std::mutex> lk(m); ++counter; }
        sync.arrive_and_drop();
        for (auto &t : ts) t.join();
        // counter = (N-1 worker × ROUNDS 轮) + 主 1 次
        long expect = (long)(N - 1) * ROUNDS + 1;
        if (counter != expect) {
            printf("FAIL arrive_and_drop: counter=%ld (expect %ld)\n", counter, expect);
            ++failures;
        }
    }

    // (4) completion function：屏障阶段切换时回调被调用恰好 ROUNDS 次（每阶段一次）。
    //     completion 由最后到达的线程在阶段切换时同步调用，串行执行，普通 int ++ 在锁内安全。
    {
        const int N = 3;
        const int ROUNDS = 4;
        std::mutex m;
        int calls = 0;
        std::barrier sync(N, [&] {
            std::lock_guard<std::mutex> lk(m);
            ++calls;
        });
        std::vector<std::thread> ts;
        for (int i = 0; i < N; ++i) {
            ts.emplace_back([&] {
                for (int r = 0; r < ROUNDS; ++r) {
                    sync.arrive_and_wait();
                }
            });
        }
        for (auto &t : ts) t.join();
        if (calls != ROUNDS) {
            printf("FAIL completion: calls=%d (expect %d)\n", calls, ROUNDS);
            ++failures;
        }
    }

    printf("stl_barrier: ok=%d failures=%d\n", (failures == 0), failures);
    return failures == 0 ? 0 : 1;
}
