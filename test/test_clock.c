// clock_nanosleep 验证：CPython time.sleep() 的主路径。
//   相对睡眠（CLOCK_MONOTONIC, flags=0）与绝对睡眠（TIMER_ABSTIME）都必须成功
//   （BPF_SYS_CLOCK_NANOSLEEP 之前未实现，musl 对 MONOTONIC/ABSTIME 直接拿 ENOSYS）。
//   顺带验证非法 clockid 返回 EINVAL。
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

static uint64_t elapsed_ms(struct timespec* a, struct timespec* b) {
    return (uint64_t)((int64_t)(b->tv_sec - a->tv_sec) * 1000
                    + (int64_t)(b->tv_nsec - a->tv_nsec) / 1000000);
}

int main(void) {
    struct timespec before, after, req, rem;
    int rc;

    clock_gettime(CLOCK_MONOTONIC, &before);
    req.tv_sec = 0;
    req.tv_nsec = 10 * 1000 * 1000;
    rem.tv_sec = rem.tv_nsec = 0;
    rc = clock_nanosleep(CLOCK_MONOTONIC, 0, &req, &rem);
    if (rc != 0) {
        printf("FAIL: relative sleep returned %d (errno=%d)\n", rc, errno);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &after);
    uint64_t el = elapsed_ms(&before, &after);
    if (el < 10 || el > 5000) {
        printf("FAIL: relative sleep elapsed %llu ms\n", (unsigned long long)el);
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &req);
    req.tv_nsec += 10 * 1000 * 1000;
    if (req.tv_nsec >= 1000000000L) {
        req.tv_sec += 1;
        req.tv_nsec -= 1000000000L;
    }
    rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &req, NULL);
    if (rc != 0) {
        printf("FAIL: absolute sleep returned %d (errno=%d)\n", rc, errno);
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &after);
    el = elapsed_ms(&req, &after);
    /* 过零点会得到巨大值，只在睡眠确实越过目标时刻时校验上界 */
    if (el > 5000) {
        printf("FAIL: absolute sleep overshot by %llu ms\n", (unsigned long long)el);
        return 1;
    }

    /* CLOCK_THREAD_CPUTIME_ID 不可睡眠，EINVAL（musl 显式拦截，两侧行为一致） */
    req.tv_sec = 0;
    req.tv_nsec = 1;
    rc = clock_nanosleep(CLOCK_THREAD_CPUTIME_ID, 0, &req, NULL);
    if (rc != EINVAL) {
        printf("FAIL: THREAD_CPUTIME_ID sleep returned %d, expected EINVAL\n", rc);
        return 1;
    }

    printf("clock_nanosleep ok (relative 10ms elapsed=%llu ms)\n", (unsigned long long)elapsed_ms(&before, &after));
    return 0;
}
