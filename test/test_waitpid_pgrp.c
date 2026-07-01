#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

/* pid 1 是 session leader，不能 setpgid。用中间进程创建新进程组。 */
int main(void) {
    pid_t inter = fork();
    if (inter < 0) { printf("fork failed\n"); return 1; }
    if (inter == 0) {
        setpgid(0, 0);
        pid_t first = fork();
        if (first < 0) _exit(1);
        if (first == 0) _exit(11);

        pid_t second = fork();
        if (second < 0) _exit(1);
        if (second == 0) _exit(22);

        /* waitpid(0) 等同进程组任意子进程：first 和 second 都继承 inter 的 pgrp */
        int collected = 0;
        int statuses[2] = {0, 0};
        for (int i = 0; i < 2; i++) {
            int status = 0;
            pid_t w = waitpid(0, &status, 0);
            if (w <= 0) _exit(100 + i);
            collected++;
            if (w == first) statuses[0] = (status >> 8) & 0xff;
            else if (w == second) statuses[1] = (status >> 8) & 0xff;
        }
        if (collected != 2) _exit(50);
        if (statuses[0] != 11 || statuses[1] != 22) _exit(51);
        _exit(0);
    }

    int status = 0;
    waitpid(inter, &status, 0);
    if (status != 0) {
        printf("inter status %d\n", status);
        return 1;
    }
    printf("waitpid pgrp ok\n");
    return 0;
}
