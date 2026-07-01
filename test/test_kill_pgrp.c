#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <sched.h>

static volatile sig_atomic_t got = 0;
static void on_term(int sig) { (void)sig; got++; }

/* pid 1 是 session leader，不能 setpgid。用中间进程创建新进程组。 */
int main(void) {
    pid_t inter = fork();
    if (inter < 0) { printf("fork failed\n"); return 1; }
    if (inter == 0) {
        setpgid(0, 0);
        pid_t pgid = getpgrp();
        signal(SIGTERM, on_term);

        pid_t g1 = fork();
        if (g1 < 0) _exit(1);
        if (g1 == 0) {
            /* 子进程继承 inter 的 pgrp */
            while (got == 0) sched_yield();
            _exit(got == 1 ? 0 : 1);
        }
        pid_t g2 = fork();
        if (g2 < 0) _exit(1);
        if (g2 == 0) {
            while (got == 0) sched_yield();
            _exit(got == 1 ? 0 : 1);
        }

        /* 让子进程启动 */
        for (int i = 0; i < 200; i++) sched_yield();

        /* 给整个进程组发 SIGTERM：inter + g1 + g2 都应收到 */
        if (kill(-pgid, SIGTERM) != 0) _exit(2);

        /* inter 自己应收到 */
        while (got == 0) sched_yield();

        int s1 = 0, s2 = 0;
        waitpid(g1, &s1, 0);
        waitpid(g2, &s2, 0);
        if (s1 != 0 || s2 != 0) _exit(3);
        _exit(0);
    }

    int status = 0;
    waitpid(inter, &status, 0);
    if (status != 0) {
        printf("inter status %d\n", status);
        return 1;
    }
    printf("kill pgrp ok\n");
    return 0;
}
