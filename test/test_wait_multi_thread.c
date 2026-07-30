/* 多线程父进程并发 waitpid 回归测试。
 *
 * 父进程先 fork N 个子进程（单线程 fork，子进程各自阻塞在同步管道上等放行），
 * 再创建 N 个 waiter 线程，每个线程 waitpid 自己专属的子进程。靠 mutex+cond 让
 * main 等到全部 N 个 waiter 都已进入 waitpid（注册进各自子的 tg->waiters）后才
 * 放行子进程同时退出——从而构造 N 个线程同时阻塞在 do_wait_common（各自
 * vm::wait_for）的并发场景。
 *
 * 验证：每个子进程恰好被其专属 waiter 回收、退出码正确，无串子、无重复回收、
 * 无丢失。覆盖等待列表（tg->waiters）在多 waiter 并发唤醒下的正确性——参照
 * futex 等待桶模型：等待者阻塞在自身 wait_for，子进程 exit 经 wake_waiters
 * 唤醒对应 waiter。
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <errno.h>

#define N 4

struct waiter_arg {
    pid_t pid;
    int expect;   /* 期望退出码 = i+1 */
    int ok;
};

/* 就绪屏障：N 个 waiter 各自在进入 waitpid 前 +1，main 等到 ready==N 再放行子进程。 */
static pthread_mutex_t ready_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready_cond = PTHREAD_COND_INITIALIZER;
static int ready = 0;

static void *waiter(void *p) {
    struct waiter_arg *a = p;
    /* 报到：告诉 main 本线程即将进入 waitpid。必须在 waitpid 前，否则 main 可能在
     * 本线程尚未阻塞时就放行子进程，失去并发性。 */
    pthread_mutex_lock(&ready_mtx);
    ready++;
    pthread_cond_signal(&ready_cond);
    pthread_mutex_unlock(&ready_mtx);

    int status = 0;
    pid_t r = waitpid(a->pid, &status, 0);
    if (r != a->pid) {
        printf("waiter: waitpid(%d) returned %d errno=%d\n", a->pid, r, errno);
        a->ok = 0;
        return NULL;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != a->expect) {
        printf("waiter: child %d status=0x%x expected exit %d\n", a->pid, status, a->expect);
        a->ok = 0;
        return NULL;
    }
    a->ok = 1;
    return NULL;
}

int main(void) {
    int syncfd[2];
    if (pipe(syncfd) < 0) {
        printf("pipe failed\n");
        return 1;
    }

    /* 先 fork 全部子进程（单线程 fork，避免 fork-with-threads 的语义负担）。
     * 子进程各自关闭写端、阻塞读等放行，收到 go 后 _exit(i+1)。 */
    pid_t children[N];
    for (int i = 0; i < N; i++) {
        pid_t c = fork();
        if (c < 0) {
            printf("fork %d failed\n", i);
            return 1;
        }
        if (c == 0) {
            close(syncfd[1]);
            char b;
            if (read(syncfd[0], &b, 1) != 1) {
                _exit(126);   /* 同步失败 */
            }
            _exit(i + 1);
        }
        children[i] = c;
    }
    close(syncfd[0]);   /* 父侧不用读端 */

    struct waiter_arg args[N];
    pthread_t th[N];
    for (int i = 0; i < N; i++) {
        args[i].pid = children[i];
        args[i].expect = i + 1;
        args[i].ok = 0;
        if (pthread_create(&th[i], NULL, waiter, &args[i]) != 0) {
            printf("pthread_create %d failed\n", i);
            return 1;
        }
    }

    /* 等全部 waiter 报到（均已进入/即将进入 waitpid），再放行子进程同时退出，
     * 迫使 N 个 waiter 并发被 wake_waiters 唤醒。 */
    pthread_mutex_lock(&ready_mtx);
    while (ready < N) {
        pthread_cond_wait(&ready_cond, &ready_mtx);
    }
    pthread_mutex_unlock(&ready_mtx);

    /* 写 N 字节放行 N 个子进程；小写 <= PIPE_BUF 原子。 */
    if (write(syncfd[1], "xxxx", N) != N) {
        printf("sync write failed\n");
        return 1;
    }
    close(syncfd[1]);

    int fail = 0;
    for (int i = 0; i < N; i++) {
        pthread_join(th[i], NULL);
        if (!args[i].ok) {
            fail = 1;
        }
    }
    if (fail) {
        printf("multi-thread wait failed\n");
        return 1;
    }
    printf("multi-thread wait ok, %d children reaped concurrently\n", N);
    return 0;
}
