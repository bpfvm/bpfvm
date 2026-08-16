// STL 线程测试：验证 <thread>/<mutex>/<future>/<condition_variable> 在 bpfvm 上正确工作。
//
// 机制（见 port_cplusplus.md「thread 支持」）：
//   - libc++ 的 pthread 后端（__thread/support/pthread.h，inline 头）包装 musl pthread_*；
//   - libcxx.a 提供 std::thread/mutex/condition_variable/future 的非内联成员
//     （thread.cpp/mutex.cpp/condition_variable.cpp/future.cpp + 两个 _destructor.cpp）；
//   - pthread_key 析构器在 guest 线程退出时由 musl __pthread_exit->__pthread_tsd_run_dtors
//     触发，故 std::async/notify_all_at_thread_exit 的清理语义有效。
//
// host 变体用 g++ 编宿主 glibc，作为对照基线。
//
// 注意：(1)刻意避免 std::atomic——eBPF ISA 无 plain atomic load/store，C++ <atomic> 的
// load/store 会撞 BPF 后端，改用 mutex 保护普通 int；(2)所有同步靠 join/wait 显式定序，
// 不依赖时序，保证 host 与 BPF（单核解释/JIT）行为一致。

#include <thread>
#include <mutex>
#include <future>
#include <condition_variable>
#include <chrono>
#include <vector>
#include <functional>
#include <cstdio>

int main() {
    int failures = 0;

    // (1) std::thread + join：两个线程各自累加（mutex 保护），join 后验证。
    {
        std::mutex m;
        int counter = 0;
        auto work = [&] {
            for (int i = 0; i < 10000; ++i) {
                std::lock_guard<std::mutex> lk(m);
                ++counter;
            }
        };
        std::thread t1(work), t2(work);
        t1.join();
        t2.join();
        if (counter != 20000) {
            printf("FAIL thread/join: counter=%d (expect 20000)\n", counter);
            ++failures;
        }
    }

    // (2) std::mutex + lock_guard：互斥保护的共享计数（4 线程 * 10000）。
    {
        std::mutex m;
        long x = 0;
        auto work = [&] {
            for (int i = 0; i < 10000; ++i) {
                std::lock_guard<std::mutex> lk(m);
                ++x;
            }
        };
        std::thread t1(work), t2(work), t3(work), t4(work);
        t1.join(); t2.join(); t3.join(); t4.join();
        if (x != 40000) {
            printf("FAIL mutex: x=%ld (expect 40000)\n", x);
            ++failures;
        }
    }

    // (3) std::async(std::launch::async) + std::future::get：异步计算并取回结果。
    {
        auto f = std::async(std::launch::async, [](int a, int b) { return a + b; }, 40, 2);
        int r = f.get();
        if (r != 42) {
            printf("FAIL async: r=%d (expect 42)\n", r);
            ++failures;
        }
    }

    // (4) std::promise / std::future：跨线程设值，主线程取值。
    {
        std::promise<int> p;
        std::future<int> ff = p.get_future();
        std::thread t([&p] { p.set_value(123); });
        int pr = ff.get();
        t.join();
        if (pr != 123) {
            printf("FAIL promise: pr=%d (expect 123)\n", pr);
            ++failures;
        }
    }

    // (5) std::condition_variable：生产者置标志并 notify，消费者 wait(谓词) 直到就绪。
    {
        std::mutex m;
        std::condition_variable cv;
        int ready = 0;
        std::thread producer([&] {
            std::lock_guard<std::mutex> lk(m);
            ready = 7;
            cv.notify_one();
        });
        {
            std::unique_lock<std::mutex> lk(m);
            cv.wait(lk, [&] { return ready != 0; });
        }
        producer.join();
        if (ready != 7) {
            printf("FAIL condition_variable: ready=%d (expect 7)\n", ready);
            ++failures;
        }
    }

    // (6) std::condition_variable + 多个消费者：notify_all 唤醒所有等待者。
    {
        std::mutex m;
        std::condition_variable cv;
        int generation = 0;
        int done = 0;  // 在锁内 ++，读取在 join 之后（happens-before），普通 int 安全
        const int NWORK = 4;
        std::vector<std::thread> workers;
        for (int i = 0; i < NWORK; ++i) {
            workers.emplace_back([&] {
                std::unique_lock<std::mutex> lk(m);
                cv.wait(lk, [&] { return generation >= 1; });
                ++done;
            });
        }
        // 让消费者先进入 wait，再广播。
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        {
            std::lock_guard<std::mutex> lk(m);
            generation = 1;
            cv.notify_all();
        }
        for (auto &t : workers) t.join();
        if (done != NWORK) {
            printf("FAIL cv/notify_all: done=%d (expect %d)\n", done, NWORK);
            ++failures;
        }
    }

    // (7) std::this_thread::get_id / thread::get_id：同一线程内 get_id 一致，不同线程不同。
    {
        auto self = std::this_thread::get_id();
        std::thread::id other;
        std::thread t([&] { other = std::this_thread::get_id(); });
        t.join();
        if (!(self != other)) {
            printf("FAIL thread::get_id: self==other (should differ)\n");
            ++failures;
        }
    }

    // (8) thread::hardware_concurrency()：返回值应 >=1（不强求具体值，宿主/BPF 都可能返回 1）。
    {
        unsigned hc = std::thread::hardware_concurrency();
        if (hc < 1) {
            printf("FAIL hardware_concurrency: hc=%u (expect >=1)\n", hc);
            ++failures;
        }
    }

    // (9) std::call_once：多线程并发调用，仅执行一次。
    //     calls 在 std::call_once 内部回调里 ++（串行化），读取在 join 后，普通 int 安全。
    {
        std::once_flag flag;
        int calls = 0;
        auto runner = [&] {
            std::call_once(flag, [&] { ++calls; });
        };
        std::thread t1(runner), t2(runner), t3(runner);
        t1.join(); t2.join(); t3.join();
        if (calls != 1) {
            printf("FAIL call_once: calls=%d (expect 1)\n", calls);
            ++failures;
        }
    }

    // (10) std::async 返回多个 future 并行求和。
    {
        auto sq = [](int x) { return (long)x * x; };
        auto f1 = std::async(std::launch::async, sq, 10);
        auto f2 = std::async(std::launch::async, sq, 20);
        auto f3 = std::async(std::launch::async, sq, 30);
        long total = f1.get() + f2.get() + f3.get();  // 100+400+900 = 1400
        if (total != 1400) {
            printf("FAIL async/parallel: total=%ld (expect 1400)\n", total);
            ++failures;
        }
    }

    printf("stl_thread: ok=%d failures=%d\n", (failures == 0), failures);
    return failures == 0 ? 0 : 1;
}
