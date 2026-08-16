/* waitid() 回归测试。
 *
 * waitid 用独立 ABI（idtype, id, siginfo*, options），与 wait4/waitpid 参数布局
 * 完全不同。本测试验证 VM 的 do_waitid handler 正确：
 *   -  fork 子进程正常退出 -> waitid(WEXITED) 报告 si_code==CLD_EXITED、
 *      si_signo==SIGCHLD、si_pid==child、si_status==退出码（原始值，非 wait4 状态字）。
 *   -  fork 子进程被 SIGKILL -> si_code==CLD_KILLED、si_status==SIGKILL（原始信号号）。
 *   -  P_ALL 等任意子进程。
 *
 * 注意 si_status 语义：对 SIGCHLD 事件，si_status 存【原始值】（退出码/信号号），
 * 不是 wait4 的 (code<<8|sig) 状态字，故不能套用 WEXITSTATUS/WTERMSIG 宏——这与
 * Linux 实测一致（_exit(42)->si_status=42，SIGKILL->si_status=9）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>

int main(void) {
    /* --- 1) 正常退出 + P_PID --- */
    pid_t child = fork();
    if (child < 0) {
        printf("fork failed\n");
        return 1;
    }
    if (child == 0) {
        _exit(42);
    }

    siginfo_t si;
    memset(&si, 0, sizeof(si));
    int r = waitid(P_PID, child, &si, WEXITED);
    if (r != 0) {
        printf("waitid(P_PID) returned %d errno=%d\n", r, errno);
        return 1;
    }
    if (si.si_signo != SIGCHLD) {
        printf("si_signo=%d expected SIGCHLD(%d)\n", si.si_signo, SIGCHLD);
        return 1;
    }
    if (si.si_code != CLD_EXITED) {
        printf("si_code=%d expected CLD_EXITED(%d)\n", si.si_code, CLD_EXITED);
        return 1;
    }
    if (si.si_pid != child) {
        printf("si_pid=%d expected %d\n", si.si_pid, child);
        return 1;
    }
    if (si.si_status != 42) {
        printf("si_status=%d expected 42 (raw exit code)\n", si.si_status);
        return 1;
    }
    printf("waitid(P_PID, WEXITED) ok\n");

    /* --- 2) SIGKILL + P_ALL --- */
    /* 同步管道：子进程进入死循环后通知父进程，取代盲等 sleep(2) */
    int syncfd[2];
    if (pipe(syncfd) < 0) {
        printf("sync pipe failed\n");
        return 1;
    }
    pid_t child2 = fork();
    if (child2 < 0) {
        printf("fork2 failed\n");
        return 1;
    }
    if (child2 == 0) {
        /* 死循环等待被杀 */
        close(syncfd[0]);
        /* 通知父进程：已进入死循环，可发 SIGKILL */
        write(syncfd[1], "x", 1);
        close(syncfd[1]);
        while (1) {
        }
        _exit(0);
    }
    /* 等子进程确认进入死循环（同步，不再依赖固定 sleep）*/
    close(syncfd[1]);
    char ack;
    if (read(syncfd[0], &ack, 1) != 1) {
        printf("child2 sync failed\n");
        return 1;
    }
    close(syncfd[0]);
    if (kill(child2, SIGKILL) != 0) {
        printf("kill failed\n");
        return 1;
    }

    memset(&si, 0, sizeof(si));
    r = waitid(P_ALL, 0, &si, WEXITED);
    if (r != 0) {
        printf("waitid(P_ALL) returned %d errno=%d\n", r, errno);
        return 1;
    }
    if (si.si_signo != SIGCHLD) {
        printf("si_signo=%d expected SIGCHLD\n", si.si_signo);
        return 1;
    }
    if (si.si_code != CLD_KILLED) {
        printf("si_code=%d expected CLD_KILLED(%d)\n", si.si_code, CLD_KILLED);
        return 1;
    }
    if (si.si_pid != child2) {
        printf("si_pid=%d expected %d\n", si.si_pid, child2);
        return 1;
    }
    if (si.si_status != SIGKILL) {
        printf("si_status=%d expected SIGKILL(%d) (raw sig)\n", si.si_status, SIGKILL);
        return 1;
    }
    printf("waitid(P_ALL, CLD_KILLED) ok\n");

    printf("waitid ok\n");
    return 0;
}
