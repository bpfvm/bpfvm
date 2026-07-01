#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

int main(void) {
    int pipefd[2];
    if (pipe(pipefd) != 0) { printf("pipe failed\n"); return 1; }

    pid_t parent_pgid = getpgrp();
    pid_t child = fork();
    if (child < 0) {
        printf("fork failed\n");
        return 1;
    }
    if (child == 0) {
        close(pipefd[0]);
        if (setpgid(0, 0) != 0) {
            printf("child setpgid failed errno=%d\n", errno);
            _exit(1);
        }
        if (getpgrp() != getpid()) {
            printf("child pgrp %d != pid %d\n", getpgrp(), getpid());
            _exit(1);
        }
        /* 通知父进程 setpgid 已完成 */
        char ok = 1;
        write(pipefd[1], &ok, 1);
        _exit(0);
    }

    close(pipefd[1]);
    /* 等子进程 setpgid 完成 */
    char ok = 0;
    read(pipefd[0], &ok, 1);
    close(pipefd[0]);

    if (getpgid(child) == parent_pgid) {
        printf("child still in parent pgrp\n");
        return 1;
    }
    if (getpgid(child) != child) {
        printf("child pgid %d != child pid %d\n", getpgid(child), child);
        return 1;
    }

    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        printf("waitpid failed\n");
        return 1;
    }
    if (status != 0) {
        printf("child status %d\n", status);
        return 1;
    }
    printf("setpgid ok\n");
    return 0;
}
