/*
 * #4 探测（pthread 接口版，间接驱动 musl futex -> VM 的 g_futex_table）。
 *
 * 大量 cond 变量并发 signal/wait：每个 cond 内部对应不同 futex 地址，
 * 持续触发 g_futex_table 的 try_emplace（哈希表增长/rehash）。
 * 同时一个线程长期 cond_wait（持有的 bucket 生命周期最长）。
 *
 * 期望：不死锁、不崩溃，长期等待者最终被唤醒。
 *  host 基线：glibc cond 走内核 futex；本测试验证逻辑自洽。
 */
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

static volatile int stop = 0;

/* 长期阻塞者 */
static pthread_mutex_t hmtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t hcond = PTHREAD_COND_INITIALIZER;
static volatile int hold_woken = 0;
static void *holder(void *arg) {
    (void)arg;
    pthread_mutex_lock(&hmtx);
    while (!hold_woken) pthread_cond_wait(&hcond, &hmtx);
    pthread_mutex_unlock(&hmtx);
    return NULL;
}

/* 压力：每个线程有若干私有 cond，反复 signal/wait 制造大量 futex 地址 */
static void *stress(void *arg) {
    long idx = (long)arg;
    pthread_mutex_t m[8];
    pthread_cond_t c[8];
    for (int i = 0; i < 8; i++) { pthread_mutex_init(&m[i], NULL); pthread_cond_init(&c[i], NULL); }
    while (!stop) {
        for (int i = 0; i < 8; i++) {
            pthread_mutex_lock(&m[i]);
            pthread_cond_signal(&c[i]);   /* 唤醒（即便没人等）-> futex_wake */
            /* 短暂 wait（几乎立即被自己后续或超时唤醒）-> futex_wait */
            struct timespec ts = {0, 1000};
            pthread_cond_timedwait(&c[i], &m[i], &ts);
            pthread_mutex_unlock(&m[i]);
        }
    }
    for (int i = 0; i < 8; i++) { pthread_cond_destroy(&c[i]); pthread_mutex_destroy(&m[i]); }
    return (void*)idx;
}

int main(void) {
    pthread_t h;
    pthread_create(&h, NULL, holder, NULL);

    pthread_t s[4];
    for (long i = 0; i < 4; i++) pthread_create(&s[i], NULL, stress, (void*)i);

    struct timespec ts = {1, 500000000};
    nanosleep(&ts, NULL);
    stop = 1;

    for (int i = 0; i < 4; i++) pthread_join(s[i], NULL);

    pthread_mutex_lock(&hmtx);
    hold_woken = 1;
    pthread_cond_signal(&hcond);
    pthread_mutex_unlock(&hmtx);
    pthread_join(h, NULL);

    if (!hold_woken) { printf("FAIL: holder never woken\n"); return 1; }
    printf("futex stress: holder woken, survived\n");
    return 0;
}
