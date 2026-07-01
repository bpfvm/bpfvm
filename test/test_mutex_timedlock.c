/*
 * 验证 pthread_mutex_timedlock 的超时语义。
 *
 * 主线程持有一把普通互斥锁不释放，副线程用 pthread_mutex_timedlock 以
 * 100ms 绝对超时去抢锁。POSIX 要求：超时必须返回 ETIMEDOUT（而不是挂死）。
 *
 * 该测试的正确性强依赖底层 futex(FUTEX_WAIT, ..., timeout) 在超时后返回
 * -ETIMEDOUT —— 若 VM 的 futex 超时也返回 0，则 musl __timedwait_cp 会把 0
 * 当成成功，timedlock 循环永远不 break，副线程挂死。
 *
 * 用 alarm(5) 兜底：正常情况应远小于 5s 就返回 ETIMEDOUT；若超 5s 仍卡住，
 * 视为 VM bug（futex 超时未生效），用 _exit 报错退出。
 */
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int result = -1;   /* 副线程的 timedlock 返回值（join 提供同步）*/

static void on_alarm(int sig) { (void)sig; }

static void *worker(void *arg) {
    (void)arg;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 100 * 1000 * 1000;   /* 100ms 绝对超时 */
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec += 1; ts.tv_nsec -= 1000000000L; }

    int r = pthread_mutex_timedlock(&lock, &ts);
    result = r;
    return NULL;
}

int main(void) {
    /* 兜底：5s 后仍无结果，认为 VM 挂死了副线程 */
    struct sigaction sa = {0};
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);
    alarm(5);

    pthread_mutex_lock(&lock);   /* 主线程持有，永不释放 */

    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL) != 0) {
        printf("pthread_create failed\n");
        return 1;
    }
    pthread_join(t, NULL);

    int r = result;
    if (r != ETIMEDOUT) {
        printf("FAIL: expected ETIMEDOUT(%d), got %d\n", ETIMEDOUT, r);
        return 1;
    }
    printf("timedlock returned ETIMEDOUT ok\n");
    return 0;
}
