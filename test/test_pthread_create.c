#include <stdio.h>
#include <pthread.h>
#include <assert.h>

/* counter 受 mutex 保护，确保并发自增的正确性。
 * （旧版 counter++ 无锁，靠编译器把 for(i<n) counter++ 折叠成单次 counter+=n
 *  才「碰巧」不丢更新；那是无效测试，没在测并发。这里用锁做正确同步。） */
static long counter = 0;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

static void *worker(void *arg) {
    long n = (long)arg;
    for (long i = 0; i < n; i++) {
        pthread_mutex_lock(&mtx);
        counter++;
        pthread_mutex_unlock(&mtx);
    }
    return (void *)counter;
}

int main(void) {
    pthread_t t1, t2;
    void *r1, *r2;

    if (pthread_create(&t1, NULL, worker, (void *)100000) != 0) {
        printf("pthread_create 1 failed\n");
        return 1;
    }
    if (pthread_create(&t2, NULL, worker, (void *)100000) != 0) {
        printf("pthread_create 2 failed\n");
        return 1;
    }

    pthread_join(t1, &r1);
    pthread_join(t2, &r2);

    if (counter != 200000) {
        printf("counter=%ld expected 200000\n", counter);
        return 1;
    }
    printf("pthread create ok, counter=%ld\n", counter);
    return 0;
}
