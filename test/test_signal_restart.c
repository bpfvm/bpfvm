/* SA_RESTART 自动重启系统调用（ERESTARTSYS 语义）回归测试。
 *
 * 可重启的阻塞系统调用被信号打断时，bpfvm 应：
 *   - 若打断信号的 sigaction 设了 SA_RESTART：重启系统调用（对用户完全透明，
 *     看不到 EINTR），系统调用在满足条件时正常返回；
 *   - 若未设 SA_RESTART：向用户态返回 -1/EINTR。
 * 对齐 Linux 内核 ERESTARTSYS 语义。
 *
 * 场景构造：父进程阻塞 read 一个空管道。一个 signaler 子进程延时给父进程发
 * SIGUSR1，随后向管道写一字节。
 *   - SA_RESTART：父进程 read 被信号打断 → handler 返回 → 自动重启 read → 读到
 *     signaler 写入的字节，返回 1（不是 -EINTR）。
 *   - 无 SA_RESTART：父进程 read 被信号打断 → 返回 -1/EINTR。
 *
 * 两个分支都符合预期才 exit(0)。用 fork 子进程而非 alarm，避免与测试框架的
 * 信号设施冲突，且时序可控。
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>

static volatile sig_atomic_t handler_called = 0;

static void on_sigusr1(int sig) {
    (void)sig;
    handler_called++;
}

/* signaler 子进程：等父进程进入阻塞 read 后给父进程发 SIGUSR1，
 * 再稍等让父进程跑完 handler（重启或返回 EINTR），最后向管道写一字节。 */
static void signaler(pid_t parent, int write_fd) {
    usleep(100 * 1000);          /* 100ms：确保父进程已阻塞在 read 上 */
    kill(parent, SIGUSR1);
    usleep(50 * 1000);           /* 50ms：让父进程处理信号 */
    char c = 'Z';
    if (write(write_fd, &c, 1) != 1) {
        _exit(20);
    }
    _exit(0);
}

/* 一次测试：sa_restart 决定期望行为。
 *   sa_restart=1：期望 read 重启后读到字节，返回 1。
 *   sa_restart=0：期望 read 返回 -1 且 errno=EINTR。
 * 返回 0 表示符合预期，非 0 为失败码。 */
static int run_case(int sa_restart) {
    int pfd[2];
    if (pipe(pfd) < 0) {
        printf("FAIL: pipe failed errno=%d\n", errno);
        return 1;
    }

    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) {
        printf("FAIL: fork failed errno=%d\n", errno);
        return 2;
    }
    if (child == 0) {
        close(pfd[0]);
        signaler(parent, pfd[1]);
        /* not reached */
    }
    /* 父进程 */
    close(pfd[1]);
    handler_called = 0;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigusr1;
    sigemptyset(&sa.sa_mask);
    if (sa_restart) {
        sa.sa_flags = SA_RESTART;
    } else {
        sa.sa_flags = 0;
    }
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        printf("FAIL: sigaction failed errno=%d\n", errno);
        return 3;
    }

    char c = 0;
    ssize_t n = read(pfd[0], &c, 1);

    if (sa_restart) {
        /* 期望：信号打断 read 后自动重启，最终读到 signaler 写入的字节。 */
        if (n != 1) {
            printf("FAIL: SA_RESTART read returned %zd errno=%d (expected restart -> 1)\n",
                   n, errno);
            return 4;
        }
        if (handler_called < 1) {
            printf("FAIL: SA_RESTART handler not invoked\n");
            return 5;
        }
        if (c != 'Z') {
            printf("FAIL: SA_RESTART wrong byte 0x%02x\n", (unsigned char)c);
            return 6;
        }
    } else {
        /* 期望：信号打断 read 后返回 -1/EINTR。 */
        if (n != -1 || errno != EINTR) {
            printf("FAIL: no-SA_RESTART read returned %zd errno=%d (expected -1/EINTR)\n",
                   n, errno);
            return 7;
        }
        if (handler_called < 1) {
            printf("FAIL: no-SA_RESTART handler not invoked\n");
            return 8;
        }
        /* 消费 signaler 写入的字节，避免它因管道写端关闭收到 SIGPIPE 前 exit(0)
         * 干净退出（此处父进程读走即可）。 */
        char tmp;
        while (read(pfd[0], &tmp, 1) > 0) { /* drain */ }
    }

    close(pfd[0]);
    /* 回收 signaler 子进程。 */
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) continue;
        break;
    }
    return 0;
}

int main(void) {
    int rc;
    if ((rc = run_case(/*sa_restart=*/1)) != 0) {
        return rc;
    }
    if ((rc = run_case(/*sa_restart=*/0)) != 0) {
        return rc;
    }
    printf("signal_restart ok\n");
    return 0;
}
