#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <stdlib.h>

#define MARKER_BEFORE "test_sigstop_before"
#define MARKER_AFTER  "test_sigstop_after"

static int file_exists(const char *path) {
    return access(path, 0) == 0;
}

static void touch(const char *path) {
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) close(fd);
}

int main(void) {
    unlink(MARKER_BEFORE);
    unlink(MARKER_AFTER);

    /* sigaction must reject SIGSTOP */
    struct sigaction sa = {0};
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGSTOP, &sa, NULL) == 0) {
        printf("FAIL: sigaction(SIGSTOP) should have failed\n");
        return 1;
    }
    printf("sigaction(SIGSTOP) correctly rejected\n");

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        touch(MARKER_BEFORE);
        kill(getpid(), SIGSTOP);
        /* Only reached after SIGCONT */
        touch(MARKER_AFTER);
        _exit(42);
    }

    /* 等子进程真正进入 SIGSTOP 态：waitpid(WUNTRACED) 在子进程停止后返回，
     * WIFSTOPPED 为真。这是 VM/内核保证的状态同步，取代原先「轮询 before-marker
     * 文件 + sleep(1) 保险」—— 既更快又消除了「marker 存在但子进程还没执行到
     * SIGSTOP」的竞态窗口。
     * 此时子进程刚执行过 touch(MARKER_BEFORE)，尚未到 touch(MARKER_AFTER)：
     * before-marker 必然存在、after-marker 必然不存在（SIGCONT 还没发）。 */
    int stop_status;
    if (waitpid(pid, &stop_status, WUNTRACED) != pid || !WIFSTOPPED(stop_status)) {
        printf("FAIL: child did not stop (status=0x%x)\n", stop_status);
        unlink(MARKER_BEFORE);
        unlink(MARKER_AFTER);
        return 1;
    }

    /* Child must be stopped: before-marker exists, after-marker does not */
    if (!file_exists(MARKER_BEFORE)) {
        printf("FAIL: before-marker not found\n");
        unlink(MARKER_BEFORE);
        unlink(MARKER_AFTER);
        return 1;
    }
    if (file_exists(MARKER_AFTER)) {
        printf("FAIL: after-marker exists before SIGCONT, child was not stopped\n");
        unlink(MARKER_BEFORE);
        unlink(MARKER_AFTER);
        return 1;
    }
    printf("Child is stopped (before-marker exists, after-marker absent)\n");

    kill(pid, SIGCONT);

    int status;
    waitpid(pid, &status, 0);
    int code = (status >> 8) & 0xff;
    printf("Child exited with %d\n", code);

    if (!file_exists(MARKER_AFTER)) {
        printf("FAIL: after-marker not found after child exited\n");
        unlink(MARKER_BEFORE);
        return 1;
    }

    unlink(MARKER_BEFORE);
    unlink(MARKER_AFTER);
    return (code == 42) ? 0 : 1;
}
