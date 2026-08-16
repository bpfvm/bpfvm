// test_poll.c — 验证 bpfvm 的 poll() 系统调用。
// 覆盖：就绪 fd（POLLIN）、超时（返回 0）、非法 fd（POLLNVAL）、
// 负 timeout+POLLNVAL（立即返回不死锁）、负 fd 跳过、n=0 纯睡眠、
// 以及被信号打断返回 -1/EINTR。全部断言通过返回 0。

#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>

/* 用例 7：SIGUSR1 handler，空操作即可（无 SA_RESTART -> poll 不重启，返回 EINTR） */
static void on_usr1(int sig) {
    (void)sig;
}

int main(void)
{
    int pipefd[2];

    /* —— 用例 1：管道写端写入后，读端应立刻 POLLIN —— */
    if (pipe2(pipefd, 0) != 0) {
        perror("pipe2");
        return 1;
    }
    char c = 'x';
    if (write(pipefd[1], &c, 1) != 1) {
        perror("write");
        return 1;
    }
    struct pollfd pfd_ready = {
        .fd = pipefd[0],
        .events = POLLIN,
        .revents = 0,
    };
    int rc1 = poll(&pfd_ready, 1, 1000);  /* 1s 上限，但应立即就绪 */
    if (rc1 < 0) {
        perror("poll ready");
        return 1;
    }
    if (rc1 != 1 || !(pfd_ready.revents & POLLIN)) {
        fprintf(stderr, "FAIL ready: rc=%d revents=0x%x\n", rc1, pfd_ready.revents);
        return 1;
    }
    close(pipefd[0]);
    close(pipefd[1]);

    /* —— 用例 2：空管道 + 短超时应返回 0，且 revents 清零 —— */
    if (pipe2(pipefd, 0) != 0) {
        perror("pipe2");
        return 1;
    }
    struct pollfd pfd_timeout = {
        .fd = pipefd[0],
        .events = POLLIN,
        .revents = 0,
    };
    int rc2 = poll(&pfd_timeout, 1, 50);  /* 50ms 超时 */
    if (rc2 < 0) {
        perror("poll timeout");
        return 1;
    }
    if (rc2 != 0 || pfd_timeout.revents != 0) {
        fprintf(stderr, "FAIL timeout: rc=%d revents=0x%x\n", rc2, pfd_timeout.revents);
        return 1;
    }
    close(pipefd[0]);
    close(pipefd[1]);

    /* —— 用例 3：非法 fd 应得 POLLNVAL，且返回值 >= 1 —— */
    struct pollfd pfd_bad = {
        .fd = 999,  /* 几乎必然未打开 */
        .events = POLLIN,
        .revents = 0,
    };
    int rc3 = poll(&pfd_bad, 1, 0);  /* 非阻塞探测 */
    if (rc3 < 0) {
        perror("poll nval");
        return 1;
    }
    if (rc3 < 1 || !(pfd_bad.revents & POLLNVAL)) {
        fprintf(stderr, "FAIL nval: rc=%d revents=0x%x\n", rc3, pfd_bad.revents);
        return 1;
    }

    /* —— 用例 4：负 timeout(永久阻塞) + 非法 fd -> POLLNVAL 应立即返回，不得挂死 —— */
    struct pollfd pfd_nval_block = {
        .fd = 998,  /* 非法 fd */
        .events = POLLIN,
        .revents = 0,
    };
    int rc4 = poll(&pfd_nval_block, 1, -1);  /* 永久阻塞请求，但 POLLNVAL 应立即就绪 */
    if (rc4 < 0) {
        perror("poll nval block");
        return 1;
    }
    if (rc4 < 1 || !(pfd_nval_block.revents & POLLNVAL)) {
        fprintf(stderr, "FAIL nval-block: rc=%d revents=0x%x\n", rc4, pfd_nval_block.revents);
        return 1;
    }

    /* —— 用例 5：负 fd 条目应被 poll 忽略（revents 清零，返回 0）—— */
    struct pollfd pfd_negfd = {
        .fd = -1,
        .events = POLLIN,
        .revents = 0xffff,  /* 故意置非零，验证会被清成 0 */
    };
    int rc5 = poll(&pfd_negfd, 1, 0);
    if (rc5 < 0) {
        perror("poll negfd");
        return 1;
    }
    if (rc5 != 0 || pfd_negfd.revents != 0) {
        fprintf(stderr, "FAIL negfd: rc=%d revents=0x%x\n", rc5, pfd_negfd.revents);
        return 1;
    }

    /* —— 用例 6：n=0 纯睡眠（fds=NULL，timeout 短）应返回 0 —— */
    int rc6 = poll(NULL, 0, 20);
    if (rc6 < 0) {
        perror("poll null");
        return 1;
    }
    if (rc6 != 0) {
        fprintf(stderr, "FAIL null: rc=%d\n", rc6);
        return 1;
    }

    /* —— 用例 7：阻塞中的 poll 被信号打断应返回 -1/EINTR ——
     * 父进程对空管道 poll（永久阻塞），fork 子进程 1s 后给父进程发 SIGUSR1。
     * 这是 poll 设计的重点路径：queue_signal 的 pthread_kill(SIGUSR1) 把宿主 poll
     * 踢出 EINTR，do_poll 翻译成 -EINTR 返回，随后 safepoint 投递信号给 handler。 */
    struct sigaction sa = {0};
    sa.sa_handler = on_usr1;    /* 空 handler，安装即可（无 SA_RESTART -> poll 不重启） */
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        perror("sigaction");
        return 1;
    }
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        /* 子进程：稍等确保父进程已进入 poll，再发信号 */
        sleep(1);
        kill(getppid(), SIGUSR1);
        _exit(0);
    }
    /* 父进程：在空管道上永久阻塞 poll，预期被子进程的 SIGUSR1 打断 */
    if (pipe2(pipefd, 0) != 0) {
        perror("pipe2");
        return 1;
    }
    struct pollfd pfd_block = {
        .fd = pipefd[0],
        .events = POLLIN,
        .revents = 0,
    };
    int rc7 = poll(&pfd_block, 1, -1);  /* 永久阻塞，应被 EINTR 打断 */
    int saved_errno = errno;
    /* 无论 poll 返回什么，都先回收子进程 */
    int status;
    wait(&status);
    close(pipefd[0]);
    close(pipefd[1]);
    if (rc7 != -1 || saved_errno != EINTR) {
        fprintf(stderr, "FAIL eintr: rc=%d errno=%d\n", rc7, saved_errno);
        return 1;
    }

    printf("test_poll OK\n");
    return 0;
}
