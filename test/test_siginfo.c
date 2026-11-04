/* SA_SIGINFO 投递：siginfo_t 载荷、ucontext 恢复（rt_sigreturn 语义）、sigqueue。
 * gregs 改写部分是 BPF ucontext 布局专属（REG_PC=11、r0..r10 = gregs[0..10]），
 * host 变体跳过。 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __BPF__
#include <sys/ucontext.h>
#endif

static int fails = 0;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %d: %s\n", __LINE__, #cond); fails++; } \
} while (0)

static volatile sig_atomic_t got_usr1 = 0;
static volatile int si_pid_seen = -1;

static void on_usr1(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    got_usr1 = 1;
    CHECK(sig == SIGUSR1);
    CHECK(si->si_signo == SIGUSR1);
    CHECK(si->si_code == SI_USER);
    si_pid_seen = si->si_pid;
    /* handler 内阻塞一切信号：返回后应由 sigreturn 恢复投递前掩码 */
    sigset_t all;
    sigfillset(&all);
    sigprocmask(SIG_BLOCK, &all, NULL);
}

static volatile sig_atomic_t got_usr2 = 0;

static void on_usr2(int sig, siginfo_t *si, void *uc) {
    (void)sig; (void)uc;
    got_usr2 = 1;
    CHECK(si->si_signo == SIGUSR2);
    CHECK(si->si_code == SI_QUEUE);
    CHECK(si->si_int == 0x1234);
}

static volatile sig_atomic_t got_chld = 0;
static volatile int chld_code = -1, chld_status = -1;
static volatile pid_t chld_pid = -1;

static void on_chld(int sig, siginfo_t *si, void *uc) {
    (void)sig; (void)uc;
    got_chld = 1;
    chld_code = si->si_code;
    chld_status = si->si_status;
    chld_pid = si->si_pid;
}

/* fork 前阻塞 SIGCHLD，防止子进程在父进程到达 sigsuspend 前退出、SIGCHLD 被
 * 提前投递消费而 sigsuspend 永远等不到。call_fn 在 SIGCHLD 阻塞下跑 fork。 */
static pid_t fork_chld_blocked(void (*child_fn)(void)) {
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, NULL);
    pid_t c = fork();
    if (c == 0) {
        child_fn();
        _exit(0);   /* 不应到达 */
    }
    CHECK(c >= 0);
    return c;
}

/* 等待已阻塞的 SIGCHLD 投递；掩码归空收尾（POSIX sigsuspend 回滚掩码、本 VM 不
 * 回滚，两种语义下都收敛到空）。 */
static void wait_sigchld(void) {
    sigset_t empty;
    sigemptyset(&empty);
    sigsuspend(&empty);   /* 换空掩码：SIGCHLD 立即可投递 */
    sigprocmask(SIG_SETMASK, &empty, NULL);
}

static void chld_exit7(void) { _exit(7); }
static void chld_suicide(void) { kill(getpid(), SIGKILL); }

#ifdef __BPF__
static const uint64_t gregs6_magic = 0x5a5ac0de5a5ac0deULL;

static inline uint64_t read_r6(void) {
    uint64_t x;
    __asm__ volatile("%0 = r6" : "=r"(x));
    return x;
}

/* handler 把 gregs[REG_PC] 改到本函数、gregs[6] 写魔数；sigreturn 后从恢复点继续。
 * 不返回（栈顶已是 main 帧，return 会 pop 错帧），检查完直接 _exit。 */
static void __attribute__((noinline)) hijack_landing(void) {
    CHECK(read_r6() == gregs6_magic);
    _exit(fails ? 1 : 0);
}

static void on_term_hijack(int sig, siginfo_t *si, void *uc_) {
    ucontext_t *uc = uc_;
    CHECK(sig == SIGTERM);
    CHECK(si->si_signo == SIGTERM);
    uc->uc_mcontext.gregs[6] = (greg_t)gregs6_magic;
    uc->uc_mcontext.gregs[REG_PC] = (greg_t)(uintptr_t)hijack_landing;
}
#endif

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_usr1;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);

    CHECK(kill(getpid(), SIGUSR1) == 0);
    CHECK(got_usr1 == 1);
    CHECK(si_pid_seen == (int)getpid());

    /* handler 内 sigfillset 阻塞过全部信号：正常返回（sigreturn）后掩码须复原 */
    sigset_t chk;
    sigemptyset(&chk);
    CHECK(sigprocmask(SIG_SETMASK, NULL, &chk) == 0);
    CHECK(!sigismember(&chk, SIGUSR1));
    CHECK(!sigismember(&chk, SIGUSR2));

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_usr2;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    CHECK(sigaction(SIGUSR2, &sa, NULL) == 0);
    union sigval v = { .sival_int = 0x1234 };
    CHECK(sigqueue(getpid(), SIGUSR2, v) == 0);
    CHECK(got_usr2 == 1);
    /* sig==0：仅存在性检查不发信号（对齐 kill）；不存在的 pid 报 ESRCH */
    CHECK(sigqueue(getpid(), 0, v) == 0);
    CHECK(sigqueue(-999999, 0, v) == -1 && errno == ESRCH);

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_chld;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    CHECK(sigaction(SIGCHLD, &sa, NULL) == 0);

    pid_t child = fork_chld_blocked(chld_exit7);
    wait_sigchld();
    CHECK(got_chld == 1);
    CHECK(chld_code == CLD_EXITED);
    CHECK(chld_status == 7);
    CHECK(chld_pid == child);
    int st = 0;
    CHECK(waitpid(child, &st, 0) == child);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 7);

    /* CLD_KILLED：子进程被 SIGKILL 杀死，si_status 报信号号 */
    child = fork_chld_blocked(chld_suicide);
    wait_sigchld();
    CHECK(got_chld == 1);
    CHECK(chld_code == CLD_KILLED);
    CHECK(chld_status == SIGKILL);
    CHECK(chld_pid == child);
    CHECK(waitpid(child, &st, 0) == child);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);

#ifdef __BPF__
    /* 最后一个测试不返回 main：恢复点被改写为 hijack_landing，其检查后 _exit */
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_term_hijack;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    CHECK(sigaction(SIGTERM, &sa, NULL) == 0);
    CHECK(kill(getpid(), SIGTERM) == 0);
    printf("not reached: gregs[REG_PC] hijack failed\n");
    return 1;
#else
    if (fails == 0) {
        printf("siginfo OK\n");
    }
    return fails ? 1 : 0;
#endif
}
