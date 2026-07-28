// emutls 竞态回归用例：多线程同时首次访问同一 TLS 变量时，控制块的 index 懒分配
// 必须给同一变量分到同一个值，否则某线程会走到全新 slot、重新拷贝模板初值，表现为
// 「写 id 后立即读，读到的不是刚写的值」。emutls.c 的 emutls_get_index 用
// double-checked 上锁保证这一点；本用例固定该不变式。
//
// 手法：4 个线程在 barrier 上对齐后，各自紧贴 start 反复 `c = id; 读 c;`，检查自洽。
// host 不注入 -Dthread_local，是真正的 thread_local，自然充当基线。

#include <pthread.h>
#include <sched.h>
#include <stdio.h>

thread_local long c = 42;   // 模板初值 42；各线程写入自己的 id (>=1)

static volatile int ready = 0;   // 报到计数（主线程等齐 4 个 worker）
static volatile int start = 0;   // 放行门：0=spin 等待，1=同时开跑

struct Result {
    long id;
    int inconsistent;            // 自洽失败次数（写 id 后立即读 != id）
    long last_read;              // 最后一次读到的值（失败时用于诊断）
};

static void *worker(void *p) {
    Result *r = (Result *)p;
    long id = r->id;
    __atomic_fetch_add(&ready, 1, __ATOMIC_SEQ_CST);   // 报到
    while (!start) /* tight spin：不 yield，最大化同时进入 */ ;
    for (int i = 0; i < 5000; i++) {
        c = id;                 // 写
        long got = c;           // 自洽不变式：刚写 id 就该读回 id
        if (got != id) {
            r->inconsistent++;
            r->last_read = got;
        }
    }
    return nullptr;
}

int main() {
    Result res[4] = {{1,0,0},{2,0,0},{3,0,0},{4,0,0}};
    pthread_t t[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&t[i], nullptr, worker, &res[i]);
    while (ready < 4) sched_yield();   // 等所有 worker 就绪
    start = 1;                          // 同时放行
    for (int i = 0; i < 4; i++)
        pthread_join(t[i], nullptr);

    int total = 0;
    for (int i = 0; i < 4; i++) {
        if (res[i].inconsistent) {
            printf("FAIL thread %ld: %d inconsistent reads, last_read=%ld\n",
                   res[i].id, res[i].inconsistent, res[i].last_read);
            total += res[i].inconsistent;
        }
    }
    if (total > 0) {
        printf("FAIL: %d self-inconsistent reads (emutls index race)\n", total);
        return 1;
    }
    printf("OK: all threads self-consistent, c=%ld\n", c);
    return 0;
}
