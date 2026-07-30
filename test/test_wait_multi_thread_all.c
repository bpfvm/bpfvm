/* 多线程父进程并发 wait 抢占回归测试（per-child waiter + 全收 collector）。
 *
 * 父进程 fork N 个子进程后创建 N 个 per-child waiter 线程（每个 waitpid 自己的子）
 * + 1 个 collector 线程（waitpid(-1) 循环回收所有子进程）。靠同步管道让所有子进程
 * 在全部 waiter 进 入 waitpid 后才同时退出，构造 N+1 个线程在 do_wait_common 上
 * 抢同一批子进程的并发场景。
 *
 * 验证恰好一次回收：每个子进程（按唯一退出码 1..N 标识）被恰好一个 waiter 回收，
 * 不重复、不丢失。覆盖 do_wait_common 的 claim_one 在 pid_map_mutex 内原子
 * erase/CAS 的正确性——并发抢同一子进程时只有首个进入者赢，余者不再从 pid_map
 * 见到该子进程（得 ECHILD 或转而抢别的子进程），杜绝重复回收/重复报告。
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <errno.h>

#define N 4

/* seen[i]：退出码 i+1 的子进程被回收的次数。恰好一次 ⇒ 全 1。 */
static int seen[N];
static pthread_mutex_t seen_mtx = PTHREAD_MUTEX_INITIALIZER;
static int bad = 0;   /* 非预期退出码/状态 */

static void record(int code) {
    if(code < 1 || code > N) {
        pthread_mutex_lock(&seen_mtx);
        bad = 1;
        pthread_mutex_unlock(&seen_mtx);
        return;
    }
    pthread_mutex_lock(&seen_mtx);
    seen[code - 1]++;
    pthread_mutex_unlock(&seen_mtx);
}

/* 就绪屏障：N+1 个 waiter 各自进入 waitpid 前报到。 */
static pthread_mutex_t ready_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready_cond = PTHREAD_COND_INITIALIZER;
static int ready = 0;

static void ready_signal(void) {
    pthread_mutex_lock(&ready_mtx);
    ready++;
    pthread_cond_signal(&ready_cond);
    pthread_mutex_unlock(&ready_mtx);
}

struct waiter_arg {
    pid_t pid;
    int expect;   /* 期望退出码 = i+1 */
    int ok;
};

/* per-child waiter：waitpid 自己专属的子进程。可能被 collector 抢走 → 得 ECHILD（合法）。 */
static void *waiter(void *p) {
    struct waiter_arg *a = p;
    ready_signal();
    int status = 0;
    pid_t r = waitpid(a->pid, &status, 0);
    if(r == a->pid) {
        if(WIFEXITED(status) && WEXITSTATUS(status) == a->expect) {
            record(a->expect);
            a->ok = 1;
        } else {
            a->ok = 0;
        }
    } else if(r < 0 && errno == ECHILD) {
        a->ok = 1;   /* 被 collector 抢走，合法 */
    } else {
        a->ok = 0;
    }
    return NULL;
}

/* collector：waitpid(-1) 循环回收所有子进程，直到 ECHILD。 */
static void *collector(void *p) {
    (void)p;
    ready_signal();
    for(;;) {
        int status = 0;
        pid_t r = waitpid(-1, &status, 0);
        if(r > 0) {
            if(WIFEXITED(status)) {
                record(WEXITSTATUS(status));
            } else {
                pthread_mutex_lock(&seen_mtx);
                bad = 1;
                pthread_mutex_unlock(&seen_mtx);
            }
        } else if(r < 0 && errno == ECHILD) {
            break;   /* 全部回收完 */
        } else if(errno == EINTR) {
            continue;
        } else {
            pthread_mutex_lock(&seen_mtx);
            bad = 1;
            pthread_mutex_unlock(&seen_mtx);
            break;
        }
    }
    return NULL;
}

int main(void) {
    int syncfd[2];
    if(pipe(syncfd) < 0) {
        printf("pipe failed\n");
        return 1;
    }

    pid_t children[N];
    for(int i = 0; i < N; i++) {
        pid_t c = fork();
        if(c < 0) {
            printf("fork %d failed\n", i);
            return 1;
        }
        if(c == 0) {
            close(syncfd[1]);
            char b;
            if(read(syncfd[0], &b, 1) != 1) {
                _exit(126);
            }
            _exit(i + 1);
        }
        children[i] = c;
    }
    close(syncfd[0]);

    struct waiter_arg args[N];
    pthread_t th[N];
    for(int i = 0; i < N; i++) {
        args[i].pid = children[i];
        args[i].expect = i + 1;
        args[i].ok = 0;
        if(pthread_create(&th[i], NULL, waiter, &args[i]) != 0) {
            printf("pthread_create %d failed\n", i);
            return 1;
        }
    }
    pthread_t coll;
    if(pthread_create(&coll, NULL, collector, NULL) != 0) {
        printf("pthread_create collector failed\n");
        return 1;
    }

    /* 等全部 N+1 个 waiter 报到（均已进入/即将进入 waitpid）再放行子进程同时退出，
     * 迫使它们并发抢同一批退出事件。 */
    pthread_mutex_lock(&ready_mtx);
    while(ready < N + 1) {
        pthread_cond_wait(&ready_cond, &ready_mtx);
    }
    pthread_mutex_unlock(&ready_mtx);

    if(write(syncfd[1], "xxxxx", N) != N) {
        printf("sync write failed\n");
        return 1;
    }
    close(syncfd[1]);

    int fail = 0;
    for(int i = 0; i < N; i++) {
        pthread_join(th[i], NULL);
        if(!args[i].ok) fail = 1;
    }
    pthread_join(coll, NULL);

    /* 恰好一次：每个退出码 1..N 计数 == 1，且无非预期状态。 */
    pthread_mutex_lock(&seen_mtx);
    if(bad) fail = 1;
    for(int i = 0; i < N; i++) {
        if(seen[i] != 1) {
            printf("child exit %d reaped %d time(s), expected 1\n", i + 1, seen[i]);
            fail = 1;
        }
    }
    pthread_mutex_unlock(&seen_mtx);

    if(fail) {
        printf("multi-thread wait-all failed\n");
        return 1;
    }
    printf("multi-thread wait-all ok, %d children reaped exactly once\n", N);
    return 0;
}
