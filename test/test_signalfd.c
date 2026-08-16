// test_signalfd.c — 验证 bpfvm 的 signalfd 语义。
//
// 覆盖：
//   -  阻塞 SIGUSR1 + signalfd 读，fork 子进程 kill 父，阻塞 read 返回 128 字节、
//      ssi_signo == SIGUSR1，ssi_pid == 子进程 pid，ssi_code == SI_USER（验证 siginfo 透传）。
//   -  多信号排队：连续两次 kill 后两次 read 各得一个 siginfo。
//   -  SFD_NONBLOCK + 空队列 -> read 返回 -1/EAGAIN。
//   -  poll(signalfd)：信号到达前 timeout=0 返回 0；信号入队后返回 POLLIN。
//   -  更新 mask：signalfd(fd, ...) 用既有 fd 重新设置监听集合。
//   -  fork 后子进程的 signalfd 独立（读子进程自己的信号，与父互不干扰）。
//   -  非法操作（write/pwrite/pread/writev/ftruncate）被拦截，返回与 Linux 一致的 errno。
//   -  close 后资源清理：50 次 signalfd()/close 循环后 fd 号能回收（防 host fd / fd 表泄漏）。
//   -  SIGCHLD：fork 子进程分别正常退出/被信号杀，父 signalfd 读到 ssi_code ==
//      CLD_EXITED/CLD_KILLED，ssi_status == 退出码/信号号（验证 SIGCHLD siginfo 语义）。
// 全部断言通过返回 0。

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/signalfd.h>

static int fail(const char* case_name, const char* msg) {
    fprintf(stderr, "FAIL %s: %s (errno=%d %s)\n", case_name, msg, errno, strerror(errno));
    return 1;
}

int main(void) {
    sigset_t mask;

    /* —— 用例 1：阻塞 read 拿到 signalfd_siginfo ——
     * 信号必须先在 sigprocmask 里阻塞，否则会走默认动作（终止）而非被 signalfd 消费。*/
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) return fail("case1 block", "sigprocmask");

    int sfd = signalfd(-1, &mask, 0);
    if (sfd < 0) return fail("case1 create", "signalfd");

    pid_t child = fork();
    if (child < 0) return fail("case1 fork", "fork");
    if (child == 0) {
        /* 子：稍等让父进入阻塞 read，再发信号 */
        usleep(100 * 1000);
        kill(getppid(), SIGUSR1);
        _exit(0);
    }
    /* 父：阻塞 read signalfd */
    struct signalfd_siginfo si;
    ssize_t n = read(sfd, &si, sizeof(si));
    if (n != sizeof(si)) {
        int e = errno;
        int status;
        wait(&status);
        return fail("case1 read", n < 0 ? strerror(e) : "short read");
    }
    if (si.ssi_signo != (uint32_t)SIGUSR1) {
        int status; wait(&status);
        fprintf(stderr, "FAIL case1: ssi_signo=%u\n", si.ssi_signo);
        return 1;
    }
    /* ssi_pid 应为发送方（子进程）的 pid */
    if (si.ssi_pid != (uint32_t)child) {
        int status; wait(&status);
        fprintf(stderr, "FAIL case1: ssi_pid=%u expected=%d\n", si.ssi_pid, child);
        return 1;
    }
    /* ssi_code 应为 SI_USER（kill 发起） */
    if (si.ssi_code != SI_USER) {
        int status; wait(&status);
        fprintf(stderr, "FAIL case1: ssi_code=%d expected SI_USER=%d\n", si.ssi_code, SI_USER);
        return 1;
    }
    /* 回收子 */
    int status; wait(&status);

    /* —— 用例 2：多信号排队 ——
     * 注意：标准信号（1-31）会合并——同一信号多次 pending 只排一个。要测排队语义
     * 必须用不同信号。这里 SIGUSR1 已被 case1 阻塞，再阻塞 SIGUSR2，分别 kill 一次，
     * 两次 read 各得一个 siginfo。*/
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) return fail("case2 block", "sigprocmask");
    /* 把 mask 更新到 signalfd（同时监听两个信号）*/
    if (signalfd(sfd, &mask, 0) != sfd) return fail("case2 update", "signalfd update");
    if (kill(getpid(), SIGUSR1) < 0) return fail("case2 kill1", "kill");
    if (kill(getpid(), SIGUSR2) < 0) return fail("case2 kill2", "kill");
    /* 两个不同信号都入 pending 队列，signalfd 分流时各消费一个。read 第一次：*/
    n = read(sfd, &si, sizeof(si));
    if (n != sizeof(si) || si.ssi_signo != (uint32_t)SIGUSR1) {
        return fail("case2 read1", "expected SIGUSR1");
    }
    /* read 第二次：拿到 SIGUSR2。*/
    n = read(sfd, &si, sizeof(si));
    if (n != sizeof(si) || si.ssi_signo != (uint32_t)SIGUSR2) {
        return fail("case2 read2", "expected SIGUSR2");
    }

    /* —— 用例 3：SFD_NONBLOCK + 空队列 -> EAGAIN —— */
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) return fail("case3 block", "sigprocmask");
    int sfd2 = signalfd(-1, &mask, SFD_NONBLOCK);
    if (sfd2 < 0) return fail("case3 create", "signalfd SFD_NONBLOCK");
    n = read(sfd2, &si, sizeof(si));
    if (n != -1 || errno != EAGAIN) {
        return fail("case3 read", "expected EAGAIN");
    }
    close(sfd2);

    /* —— 用例 4：poll 一个 signalfd ——
     * 空时 timeout=0 返回 0；信号入队后返回 1 且 POLLIN。*/
    struct pollfd pfd = { .fd = sfd, .events = POLLIN, .revents = 0 };
    int rc = poll(&pfd, 1, 0);
    if (rc != 0 || pfd.revents != 0) {
        return fail("case4 poll empty", "expected 0 ready");
    }
    kill(getpid(), SIGUSR1);
    pfd.revents = 0;
    rc = poll(&pfd, 1, 1000);
    if (rc != 1 || !(pfd.revents & POLLIN)) {
        return fail("case4 poll ready", "expected POLLIN");
    }
    /* 消费掉刚入队的那个 SIGUSR1 */
    n = read(sfd, &si, sizeof(si));
    if (n != sizeof(si)) return fail("case4 drain", "read after poll");

    /* —— 用例 5：用既有 fd 更新 mask ——
     * sfd 原本监听 SIGUSR1；改成监听 SIGUSR2 后，SIGUSR1 不再被消费（走默认=无动作
     * 因无 handler 但 SIGUSR1 默认是 term——危险！为安全先恢复 SIGUSR1 的 handler
     * 或保持阻塞使其滞留队列）。
     * 改为更安全的检验：把 mask 切到 SIGUSR2 后 kill SIGUSR2，read 到 SIGUSR2。*/
    sigset_t mask2;
    sigemptyset(&mask2);
    sigaddset(&mask2, SIGUSR2);
    /* SIGUSR2 已在用例 3 阻塞 */
    int sfd_upd = signalfd(sfd, &mask2, 0);
    if (sfd_upd != sfd) {
        return fail("case5 update", "signalfd update should return same fd");
    }
    kill(getpid(), SIGUSR2);
    n = read(sfd, &si, sizeof(si));
    if (n != sizeof(si) || si.ssi_signo != (uint32_t)SIGUSR2) {
        return fail("case5 read", "expected SIGUSR2 after mask update");
    }

    /* —— 用例 6：fork 后子进程的 signalfd 独立 ——
     * 父 sfd 仍监听 SIGUSR2。fork 出子进程，子继承 sfd（dup 出的独立 fd）和注册条目。
     * 子给自己发 SIGUSR2 -> 应能从自己的 sfd 读到；父给自己发 SIGUSR2 也应能从父 sfd 读到。
     * 双方互不干扰。*/
    sigemptyset(&mask);  /* 父 mask 用变量，子进程独立用 */
    pid_t c6 = fork();
    if (c6 < 0) return fail("case6 fork", "fork");
    if (c6 == 0) {
        /* 子：给自己发 SIGUSR2，从自己的 sfd 读 */
        kill(getpid(), SIGUSR2);
        struct signalfd_siginfo csi;
        ssize_t cn = read(sfd, &csi, sizeof(csi));
        if (cn != (ssize_t)sizeof(csi) || csi.ssi_signo != (uint32_t)SIGUSR2) {
            _exit(11);
        }
        _exit(0);
    }
    /* 父：同时给自己发 SIGUSR2，从父 sfd 读 */
    kill(getpid(), SIGUSR2);
    n = read(sfd, &si, sizeof(si));
    if (n != sizeof(si) || si.ssi_signo != (uint32_t)SIGUSR2) {
        return fail("case6 parent read", "expected SIGUSR2");
    }
    int status6;
    wait(&status6);
    if (!WIFEXITED(status6) || WEXITSTATUS(status6) != 0) {
        fprintf(stderr, "FAIL case6 child: status=%d\n", status6);
        return 1;
    }

    /* —— 用例 7：对 signalfd 的非法操作被拦截 ——
     * signalfd 只支持 read/poll/close/epoll 等。write/pwrite/pread/writev/ftruncate
     * 在 Linux 下应失败（EINVAL 或 ESPIPE），bpfvm 需对齐——否则 write 会污染内部 pipe，
     * 让后续 read 读到非 siginfo 数据。每项检查 errno 与 Linux 实测值一致。*/
    {
        int rc;
        rc = (int)write(sfd, "x", 1);
        if (rc != -1 || errno != EINVAL) {
            fprintf(stderr, "FAIL case7 write: rc=%d errno=%d (want EINVAL)\n", rc, errno);
            return 1;
        }
        rc = (int)pwrite(sfd, "x", 1, 0);
        if (rc != -1 || errno != ESPIPE) {
            fprintf(stderr, "FAIL case7 pwrite: rc=%d errno=%d (want ESPIPE)\n", rc, errno);
            return 1;
        }
        rc = (int)writev(sfd, (struct iovec[]){{(char*)"x", 1}}, 1);
        if (rc != -1 || errno != EINVAL) {
            fprintf(stderr, "FAIL case7 writev: rc=%d errno=%d (want EINVAL)\n", rc, errno);
            return 1;
        }
        rc = (int)pread(sfd, (char[1]){0}, 1, 0);
        if (rc != -1 || errno != ESPIPE) {
            fprintf(stderr, "FAIL case7 pread: rc=%d errno=%d (want ESPIPE)\n", rc, errno);
            return 1;
        }
        rc = ftruncate(sfd, 0);
        if (rc != -1 || errno != EINVAL) {
            fprintf(stderr, "FAIL case7 ftruncate: rc=%d errno=%d (want EINVAL)\n", rc, errno);
            return 1;
        }
    }

    /* —— 用例 8：close 后资源清理（防 fd 泄漏与 fd 表膨胀）——
     * 反复 signalfd() + close() 多次。若内部 pipe write_fd 或读端 host fd 泄漏，
     * allocate_fd() 的最小可用 fd 号会单调上升（fd 表里全是已死条目）；
     * 若 SignalFd 析构没关 write_fd，host 进程最终会 EMFILE。判定：循环后新分配的
     * fd 号应回到循环前的低位（说明老 fd 被完全回收，未泄漏）。*/
    int fd_before = signalfd(-1, &mask, 0);
    if (fd_before < 0) return fail("case8 baseline", "signalfd");
    close(fd_before);
    for (int i = 0; i < 50; i++) {
        int x = signalfd(-1, &mask, 0);
        if (x < 0) return fail("case8 loop", "signalfd iteration");
        if (close(x) < 0) return fail("case8 loop", "close iteration");
    }
    int fd_after = signalfd(-1, &mask, 0);
    if (fd_after < 0) return fail("case8 verify", "signalfd after loop");
    if (fd_after != fd_before) {
        fprintf(stderr, "FAIL case8: fd leaked — first=%d, after 50 close/recreate=%d "
                        "(expected equal: fd table must recycle)\n", fd_before, fd_after);
        return 1;
    }
    close(fd_after);

    /* —— 用例 9：SIGCHLD 的 ssi_code / ssi_status ——
     * 阻塞 SIGCHLD + signalfd 监听。fork 两个子：一个 _exit(42) 正常退出，
     * 一个被 SIGKILL 杀。父从 signalfd 读 SIGCHLD，验证：
     *   CLD_EXITED + ssi_status == 42（正常退出码）
     *   CLD_KILLED + ssi_status == 9 （SIGKILL 信号号）
     * 对齐 Linux siginfo 语义。注意 ssi_status 是【原始值】，不是 wait4 的 (code<<8|sig)。
     *
     * 【串行化 fork/read/reap】SIGCHLD 是标准信号会合并：若两个子都在父第一次 read
     * 前退出（负载下父被调度延迟即触发），两次 exit 只 pending 一个 SIGCHLD，
     * 第二次 read 会永久阻塞->卡死；且 A/B 谁先退出不确定，固定顺序假设也会偶发失败。
     * 故一次只 outstanding 一个子：fork A -> read A 的 SIGCHLD -> waitpid 回收 A ->
     * 再 fork B -> read B 的 SIGCHLD -> 回收 B。任一时刻只有一个未回收子，SIGCHLD 不
     * 合并、顺序确定。read 在前、waitpid 在后只回收已 zombie 的子（SIGCHLD 已被
     * signalfd 消费，waitpid 不与 signalfd 争抢）。*/
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) return fail("case9 block", "sigprocmask");
    int sfd_chld = signalfd(-1, &mask, 0);
    if (sfd_chld < 0) return fail("case9 create", "signalfd");

    struct signalfd_siginfo s9;

    /* 子 A：正常退出，退出码 42 */
    pid_t ca = fork();
    if (ca < 0) return fail("case9 forkA", "fork");
    if (ca == 0) _exit(42);
    n = read(sfd_chld, &s9, sizeof(s9));
    if (n != sizeof(s9) || s9.ssi_signo != SIGCHLD || s9.ssi_code != CLD_EXITED || s9.ssi_status != 42) {
        fprintf(stderr, "FAIL case9 readA: n=%zd signo=%u code=%d status=%d "
                        "(want CLD_EXITED/42)\n", n, s9.ssi_signo, s9.ssi_code, s9.ssi_status);
        return 1;
    }
    if (s9.ssi_pid != (uint32_t)ca) {
        fprintf(stderr, "FAIL case9 readA: ssi_pid=%u expected=%d\n", s9.ssi_pid, ca);
        return 1;
    }
    /* A 已 zombie（read 拿到 CLD_EXITED 即证明），阻塞 waitpid 立即回收，不与 signalfd 争抢。*/
    int sa;
    if (waitpid(ca, &sa, 0) != ca || !WIFEXITED(sa) || WEXITSTATUS(sa) != 42) {
        return fail("case9 reapA", "waitpid");
    }

    /* 子 B：被 SIGKILL 杀 */
    pid_t cb = fork();
    if (cb < 0) return fail("case9 forkB", "fork");
    if (cb == 0) {
        raise(SIGKILL);
        _exit(99);   /* 不会到达 */
    }
    n = read(sfd_chld, &s9, sizeof(s9));
    if (n != sizeof(s9) || s9.ssi_signo != SIGCHLD || s9.ssi_code != CLD_KILLED || s9.ssi_status != SIGKILL) {
        fprintf(stderr, "FAIL case9 readB: n=%zd signo=%u code=%d status=%d "
                        "(want CLD_KILLED/9)\n", n, s9.ssi_signo, s9.ssi_code, s9.ssi_status);
        return 1;
    }
    if (s9.ssi_pid != (uint32_t)cb) {
        fprintf(stderr, "FAIL case9 readB: ssi_pid=%u expected=%d\n", s9.ssi_pid, cb);
        return 1;
    }
    int sb;
    if (waitpid(cb, &sb, 0) != cb || !WIFSIGNALED(sb) || WTERMSIG(sb) != SIGKILL) {
        return fail("case9 reapB", "waitpid");
    }
    close(sfd_chld);

    close(sfd);
    printf("test_signalfd OK\n");
    return 0;
}
