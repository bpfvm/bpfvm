#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

int main(void) {
    pid_t child = fork();
    if (child < 0) {
        printf("fork failed\n");
        return 1;
    }
    if (child == 0) {
        /* 子进程创建新会话：成为会话 leader + 进程组 leader */
        pid_t sid = setsid();
        if (sid < 0) {
            printf("setsid failed errno=%d\n", errno);
            _exit(1);
        }
        if (sid != getpid()) {
            printf("sid %d != pid %d\n", sid, getpid());
            _exit(1);
        }
        if (getsid(0) != getpid()) {
            printf("getsid %d != pid %d\n", getsid(0), getpid());
            _exit(1);
        }
        if (getpgrp() != getpid()) {
            printf("pgrp %d != pid %d\n", getpgrp(), getpid());
            _exit(1);
        }
        /* 再次 setsid 应失败（已是 session leader） */
        if (setsid() >= 0) {
            printf("second setsid succeeded unexpectedly\n");
            _exit(1);
        }
        _exit(0);
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
    printf("setsid ok\n");
    return 0;
}
