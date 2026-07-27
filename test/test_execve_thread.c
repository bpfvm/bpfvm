//
// 多线程进程 exec 后，同进程其它线程必须被终止（POSIX/Linux 语义）。
// 验证 bpfvm 的 do_execveat 是否正确杀掉线程组内其它线程。
//
// 流程：
//   1. fork 出子进程（fork 只复制调用线程，子进程是单线程）。
//   2. 子进程 pthread_create 一个 worker 线程，worker 跑一个长时间忙循环，
//      持续写全局变量 worker_alive=1。
//   3. 子进程主线程稍后 execve 另一个程序（test_arg.out）。
//   4. 按 POSIX/Linux 语义：exec 会终止 worker（线程组只剩调用 exec 的线程）。
//      worker 不应在新地址空间里继续执行。
//
// 验证点（父进程通过子进程的退出码 + 输出判断）：
//   - 若 exec 正确杀线程：子进程 exec 成功，test_arg 正常输出参数并 exit 0x22(34)。
//   - 若 exec 未杀线程（bug）：worker 在被换掉的新地址空间里按旧 pc/旧栈继续跑，
//     很快崩溃（段错误等），子进程非正常退出，退出码 ≠ 34，且不会有 test_arg 的输出。
//
// 被 exec 的目标 test_arg 是 BPF_TEST_HELPERS（不在 CTest 独立注册），由本测试驱动。
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>

/* worker 持续写这个标志。exec 若杀线程，worker 停下；
 * 若没杀，worker 会在新地址空间乱跑（此变量的新地址可能无效）。 */
static volatile int worker_alive = 1;

static void *worker(void *arg) {
    (void)arg;
    /* 忙循环：让 worker 持续占用 CPU，确保 exec 发生时它还在跑。
     * 不用 sleep——sleep 会让出 CPU，worker 可能恰好在睡眠态，
     * 掩盖"exec 未杀运行中线程"的问题。 */
    long sum = 0;
    while (worker_alive) {
        sum += 1;
    }
    return (void *)sum;
}

int main(void) {
    pid_t pid = fork();
    if (pid < 0) {
        printf("fork failed\n");
        return 1;
    }

    if (pid == 0) {
        /* 子进程：先建一个 worker 线程。 */
        pthread_t t;
        if (pthread_create(&t, NULL, worker, NULL) != 0) {
            printf("child: pthread_create failed\n");
            _exit(50);
        }
        /* 给 worker 一点时间真正进入忙循环。 */
        for (volatile int i = 0; i < 100000; i++) { }

        /* 主线程 exec。按 POSIX 语义此时 worker 应被终止。
         * BPF_TEST_VARIANT 选目标变体：out=静态 .out / linked=动态 .linked / host=宿主 .host。
         * （对齐 test_execve.c 的模式；CTest 各变体据此 exec 对应变体的 test_arg。） */
        const char *variant = getenv("BPF_TEST_VARIANT");
        if (!variant || !*variant) variant = "out";
        char target[128];
        snprintf(target, sizeof(target), "test/test_arg.%s", variant);

        char *const argv[] = { "execved", "after-thread", NULL };
        char ldpath_var[280];
        const char *lp = getenv("LD_LIBRARY_PATH");
        char *envp[5];
        int en = 0;
        if (lp && *lp) {
            snprintf(ldpath_var, sizeof(ldpath_var), "LD_LIBRARY_PATH=%s", lp);
            envp[en++] = ldpath_var;
        }
        envp[en] = NULL;

        execve(target, (char *const *)argv, (char *const *)envp);
        /* exec 失败才到这里 */
        printf("child: execve failed\n");
        _exit(51);
    }

    /* 父进程：等子进程结束，检查退出码。 */
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        printf("parent: waitpid failed\n");
        return 1;
    }

    if (!WIFEXITED(status)) {
        printf("parent: child killed by signal %d\n", WTERMSIG(status));
        return 2;
    }
    int code = WEXITSTATUS(status);
    /* test_arg 返回 0x22(34)。若 exec 未杀 worker 导致崩溃，code ≠ 34。 */
    if (code != 0x22) {
        printf("parent: child exit code=%d (expected 0x22=34, exec may not have killed worker)\n", code);
        return 3;
    }
    printf("parent: child exec ok, exit code=0x%x\n", code);
    return 0;
}
