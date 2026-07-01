#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <sys/syscall.h>

static volatile sig_atomic_t got = 0;
static void on_usr1(int sig) { (void)sig; got++; }

int main(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);

    /* tkill(gettid(), SIGUSR1) — 给自己发信号 */
    long tid = syscall(SYS_gettid);
    if (syscall(SYS_tkill, tid, SIGUSR1) != 0) {
        printf("tkill failed\n");
        return 1;
    }

    /* 等信号投递（sched_yield 触发 safepoint） */
    while (got == 0) {
        sched_yield();
    }

    if (got != 1) {
        printf("got=%d expected 1\n", got);
        return 1;
    }
    printf("tkill ok\n");
    return 0;
}
