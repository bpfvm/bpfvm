#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

static volatile sig_atomic_t got = 0;
static void on_sig(int s) { (void)s; got++; }

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        printf("FAIL sigaction\n");
        return 1;
    }

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);

    /* 初值应当为空（不含 SIGUSR1） */
    sigset_t old;
    sigemptyset(&old);
    if (sigprocmask(SIG_BLOCK, &set, &old) != 0) {
        printf("FAIL sigprocmask BLOCK\n");
        return 2;
    }
    if (sigismember(&old, SIGUSR1)) {
        printf("FAIL oldmask not empty\n");
        return 3;
    }

    /* 投出 SIGUSR1；被阻塞：handler 不应执行 */
    if (kill(getpid(), SIGUSR1) != 0) {
        printf("FAIL kill\n");
        return 4;
    }
    /* 触发若干 safepoint（syscall 返回）—— 信号被阻塞应保持 pending */
    for (int i = 0; i < 5; i++) usleep(20 * 1000);
    if (got != 0) {
        printf("FAIL handler ran while blocked (got=%d)\n", (int)got);
        return 5;
    }

    /* 解除阻塞：pending SIGUSR1 立即投递到 handler */
    if (sigprocmask(SIG_UNBLOCK, &set, NULL) != 0) {
        printf("FAIL sigprocmask UNBLOCK\n");
        return 6;
    }
    /* UNBLOCK 自身末 safepoint（本调用）已开始投递；再 usleep 兜底 */
    usleep(50 * 1000);
    if (got != 1) {
        printf("FAIL not delivered after unblock (got=%d)\n", (int)got);
        return 7;
    }

    /* SIG_SETMASK 回读写盘 */
    sigset_t cur;
    sigemptyset(&cur);
    sigaddset(&cur, SIGUSR1);
    if (sigprocmask(SIG_SETMASK, &cur, &old) != 0) {
        printf("FAIL sigprocmask SETMASK\n");
        return 8;
    }
    /* old 应反映 SETMASK 之前的 mask（上一轮已 UNBLOCK，故不含 SIGUSR1） */
    if (sigismember(&old, SIGUSR1)) {
        printf("FAIL SETMASK old not empty\n");
        return 9;
    }

    /* SIGKILL/SIGSTOP 不可阻塞：尝试不应使 mask 包含它们 */
    sigset_t ks;
    sigemptyset(&ks);
    sigaddset(&ks, SIGKILL);
    sigaddset(&ks, SIGSTOP);
    sigprocmask(SIG_BLOCK, &ks, &old);
    if (sigismember(&old, SIGKILL) || sigismember(&old, SIGSTOP)) {
        printf("FAIL kill/stop masked\n");
        return 10;
    }

    puts("OK sigprocmask");
    return 0;
}
