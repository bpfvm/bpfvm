/*
 * clone/pthread + exit_group 的三条语义/竞争探测，每轮 fork 一个独立子进程做：
 *
 * #5 注册窗口竞争（漏杀）：
 *   do_clone 在 pthread_create 成功「之后」才把 child push 进 tg->threads。
 *   若此时同组另一线程 exit_group 遍历 tg->threads 置 VM_KILLED，会漏掉刚创建
 *   的 child -> child 未被 kill，继续执行；其 live_threads 已 +1。
 *   - 被正确 kill：进程迅速结束（child 的阻塞被 VM_KILLED 打断）
 *   - 漏杀：child 继续阻塞 N 秒，进程退出被拖长（耗时异常增大或挂死）
 *
 * #6 退出码被 KILL 线程覆盖（exit_code 覆盖）：
 *   do_exit_group(code) 应让整组以 code 退出。被置 VM_KILLED 的线程不走 do_exit，
 *   fini 里不碰 tg->exit_code（CAS(-1->code) 仅首个正常退出者赢）。若实现错误地
 *   让被杀线程覆盖 tg->exit_code，waitpid 会读到 137 而非 code。
 *   - 期望（Linux 语义）：WEXITSTATUS == exit_group 的参数
 *   - 有 bug：WEXITSTATUS == 137
 *
 * #7 host 阻塞 syscall 可被打断：
 *   exit_group 走 queue_signal(SIGKILL) -> pthread_kill(tid, SIGUSR1)，SIGUSR1 未设
 *   SA_RESTART，把目标线程正阻塞的 host syscall（nanosleep 等）踢成 EINTR。若该
 *   机制失效（如漏掉 pthread_kill、或 SIGUSR1 误设 SA_RESTART），子线程会睡满
 *   SLEEP_SEC 才返回 -> 单轮耗时 ~ SLEEP_SEC，被 slow 阈值检出。
 *
 * 用 pthread_create 而非手写 clone()：musl 的 clone() wrapper 显式禁用
 * CLONE_THREAD（badflags），直接调 clone(CLONE_THREAD,...) 会返回 EINVAL，根本
 * 创建不出线程；pthread_create 内部走 __clone 汇编带正确 flags。
 *
 * 子线程阻塞在 nanosleep（而非忙等）：既覆盖 #7 的 host 阻塞打断，又保留 #5 的
 * 漏杀检测——漏杀的 child 没人给它发 SIGUSR1，会睡满 SLEEP_SEC。
 *
 * 多轮重复，统计耗时分布 + 退出码正确性。
 *   host 基线：glibc clone+exit_group 走内核，无此窗口，退出码 == 参数。
 */
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

/* exit_group 的参数：子进程以此码退出，父进程校验 WEXITSTATUS == EXIT_CODE。 */
#define EXIT_CODE 7

/* 子线程 nanosleep 时长：远超 slow 阈值，被正确打断时单轮应 << SLOW_THRESH。 */
#define SLEEP_SEC 5
#define SLOW_THRESH 0.5   /* 单轮 >0.5s 视为疑似漏杀 / 打断失效 */

static void *child_fn(void *arg) {
    (void)arg;
    /* 阻塞在 host syscall：被 exit_group 打断应立刻 EINTR 返回；
     * 漏杀或打断失效则睡满 SLEEP_SEC。 */
    struct timespec ts = { .tv_sec = SLEEP_SEC, .tv_nsec = 0 };
    nanosleep(&ts, NULL);
    return NULL;
}

int main(void) {
    /* 多轮，每轮 fork 一个独立进程做 pthread_create+exit_group，避免污染本进程 */
    int rounds = 30;
    int slow_rounds = 0;
    int bad_code_rounds = 0;
    double total = 0;
    for (int r = 0; r < rounds; r++) {
        pid_t sub = fork();
        if (sub == 0) {
            /* 子进程：起一个线程阻塞睡眠，然后立即 exit_group（不给线程注册时间） */
            pthread_t t;
            if (pthread_create(&t, NULL, child_fn, NULL) != 0) {
                _exit(100);
            }
            /* 立即 exit_group：竞争窗口在此；EXIT_CODE 应成为整组退出码 */
            _exit(EXIT_CODE);   /* _exit 即 exit_group 语义 */
        }
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int st = 0;
        waitpid(sub, &st, 0);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec)/1e9;
        total += dt;
        if (dt > SLOW_THRESH) slow_rounds++;
        if (!WIFEXITED(st) || WEXITSTATUS(st) != EXIT_CODE) {
            bad_code_rounds++;        /* 退出码被覆盖（如 137） */
        }
    }
    printf("exit_group race: %d rounds, %d slow(>%gs), %d bad-code, avg %.3fs\n",
           rounds, slow_rounds, SLOW_THRESH, bad_code_rounds, total/rounds);
    if (slow_rounds > 0) {
        printf("FAIL: %d rounds were slow — possible missed-kill or host-block interrupt failure\n",
               slow_rounds);
        return 1;
    }
    if (bad_code_rounds > 0) {
        printf("FAIL: %d rounds had wrong exit code (expected %d, got 137?)\n",
               bad_code_rounds, EXIT_CODE);
        return 1;
    }
    printf("ok\n");
    return 0;
}
