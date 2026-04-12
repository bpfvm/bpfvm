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

    /* Wait for child to create the before-marker and enter SIGSTOP */
    while (!file_exists(MARKER_BEFORE)) {
        sleep(1);
    }
    sleep(1);

    /* Child must be stopped: before-marker exists, after-marker does not */
    if (!file_exists(MARKER_BEFORE)) {
        printf("FAIL: before-marker not found\n");
        return 1;
    }
    if (file_exists(MARKER_AFTER)) {
        printf("FAIL: after-marker exists before SIGCONT, child was not stopped\n");
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
