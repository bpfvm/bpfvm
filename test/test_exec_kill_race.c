/* kill(pid,SIGKILL) 杀多线程进程的回归 stress 测试。
 *
 * 触发点（src/posix/signal.cpp do_kill）：
 *   do_kill(pid>0, SIGKILL) 原本只给目标 pid 的 leader 线程投递 SIGKILL，不给
 *   同组 sibling 线程投递——违反 Linux 语义（kill(pid,SIGKILL) 杀整个线程组）。
 *   leader 退出时 sibling 仍活 → 不是 last 线程 → tg->exited 不设 → 父进程
 *   waitpid 永久阻塞。修复：do_kill 对 SIGKILL 遍历 tg->threads 逐个投递，
 *   与 do_execveat / do_exit_group 一致。
 *
 * 结构（每轮）：
 *   主进程 fork A；A 起 N 个忙循环 worker 线程占住 live_threads
 *   A 通知主进程就绪后 execve(test_arg)（do_execveat 杀 worker + 等待收敛）
 *   主进程收到就绪立即 kill(A, sig)，试图命中 exec/多线程窗口
 *   主进程 waitpid(A)（带超时兜底防卡死），判定退出信号
 *
 * 修复前（SIGKILL）：worker 不被杀 → tg->exited 不设 → waitpid 超时。
 * 修复后：全组被 SIGKILL，正常回收，WTERMSIG==sig。
 *
 * 用法：test_exec_kill_race [iters] [workers] [sig]
 *   iters    迭代轮数（默认 20）
 *   workers  每轮起的 worker 线程数（默认 1，≤8）
 *   sig      杀 A 用的信号号（默认 9=SIGKILL；10=SIGUSR1 测普通信号路径）
 * 参数经 guest argv 传入（bpfvm 不透传 host 环境变量）。host 与 bpfvm 同一约定。
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/wait.h>
#include <errno.h>

static volatile int stop = 0;
static void *worker(void *a) { (void)a; volatile long s = 0; while (!stop) s++; return (void *)s; }

int main(int argc, char **argv) {
    int iters = (argc > 1 && atoi(argv[1])) ? atoi(argv[1]) : 20;
    int nworkers = (argc > 2 && atoi(argv[2])) ? atoi(argv[2]) : 1;
    int usesig = (argc > 3 && atoi(argv[3])) ? atoi(argv[3]) : SIGKILL;
    if (nworkers < 1) nworkers = 1;
    if (nworkers > 8) nworkers = 8;

    int crashes = 0, ok = 0, weird = 0, timeouts = 0;

    for (int i = 0; i < iters; i++) {
        int ready[2];
        if (pipe(ready) < 0) { printf("pipe failed\n"); return 1; }

        pid_t a = fork();
        if (a < 0) { printf("fork failed\n"); return 1; }
        if (a == 0) {
            /* A：起 worker 线程，execve 触发 do_execveat 杀 worker + 等待 */
            close(ready[0]);
            pthread_t t[8];
            for (int k = 0; k < nworkers; k++) {
                if (pthread_create(&t[k], NULL, worker, NULL) != 0) _exit(70);
            }
            write(ready[1], "x", 1);
            for (volatile int d = 0; d < 2000; d++) { }  /* worker 起来 + 拉长 exec 窗口 */

            /* BPF_TEST_VARIANT 选 exec 目标变体：out=静态 .out / linked=动态 .linked /
             * host=宿主 .host。host 对照必须用 host 变体（exec 宿主 ELF）；BPF 端
             * 默认 out（静态）。失败 _exit(71) 表示 exec 本身失败，与竞态无关。 */
            const char *v = getenv("BPF_TEST_VARIANT");
            if (!v || !*v) v = "out";
            char target[128];
            snprintf(target, sizeof(target), "test/test_arg.%s", v);
            char *const av[] = { "execed", NULL };
            execve(target, av, NULL);
            _exit(71);  /* exec 失败才到这 */
        }

        close(ready[1]);
        char ack;
        if (read(ready[0], &ack, 1) != 1) {
            /* A 提前死（fork/pthread_create/execve 失败等），与本测试目标无关 */
            int st = 0;
            waitpid(a, &st, 0);
            weird++;
            close(ready[0]);
            continue;
        }
        /* 立即杀，尽量命中 do_execveat 杀 worker + 等待收敛的窗口 */
        kill(a, usesig);

        /* 超时兜底：worker 被 SIGKILL 必死、必收敛，理应很快退出；若卡住则报超时 */
        int st = 0;
        pid_t r;
        int waited = 0;
        while ((r = waitpid(a, &st, WNOHANG)) == 0) {
            for (volatile int d = 0; d < 5000; d++) { }
            waited++;
            if (waited > 3000) {  /* 约 1.5s */
                timeouts++;
                kill(a, SIGKILL);
                waitpid(a, &st, 0);
                break;
            }
        }
        if (r > 0 || timeouts > 0) {
            if (WIFSIGNALED(st) && WTERMSIG(st) == usesig) {
                ok++;
            } else if (WIFSIGNALED(st)) {
                printf("iter %d: A killed by sig %d (expected %d)\n",
                       i, WTERMSIG(st), usesig);
                crashes++;
            } else {
                printf("iter %d: A exit %d (expected signal %d)\n",
                       i, WEXITSTATUS(st), usesig);
                weird++;
            }
        }
        close(ready[0]);
    }

    printf("iters=%d sig=%d ok=%d crashes=%d weird=%d timeouts=%d\n",
           iters, usesig, ok, crashes, weird, timeouts);
    return crashes ? 1 : 0;
}
