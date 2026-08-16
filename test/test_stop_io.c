/* 验证阻塞中的 read 被 SIGTSTP+SIGCONT 快速连续后仍正确阻塞（新模型：STOP 不踢 host syscall）。
 * 父进程 stop->立即 cont（不给子进程 CPU），子进程的 read 应从未被 EINTR 打断，
 * 继续等数据。这验证了"STOP 不踢 host syscall，CONT 先到则无事发生过"。
 *
 * 对照：旧模型下 stop+cont 快速连续会误返回 EINTR（VM_STOPPED 被 CONT 清，
 * read 查不到标志），read 提前退出。
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

int main(void) {
    setvbuf(stderr, NULL, _IONBF, 0);
    int fd[2];
    if(pipe(fd) < 0) return 1;

    /* 同步管道：子进程进入阻塞 read 前通知父进程，取代盲等 usleep(1s) */
    int syncfd[2];
    if (pipe(syncfd) < 0) return 1;

    pid_t pid = fork();
    if(pid == 0) {
        /* 子：阻塞 read，stop+cont 后应仍阻塞。收到数据后正常退出。 */
        close(fd[1]);
        close(syncfd[0]);
        /* 通知父进程：fd 已就绪，即将进入阻塞 read */
        write(syncfd[1], "x", 1);
        close(syncfd[1]);
        char buf[16];
        int rc = read(fd[0], buf, sizeof buf);
        _exit(rc >= 0 ? 0 : 1);
    }
    close(fd[0]);

    /* 等子进程确认即将进入阻塞 read（同步，不再依赖固定 usleep）*/
    close(syncfd[1]);
    char ack;
    if (read(syncfd[0], &ack, 1) != 1) {
        close(fd[1]);
        return 1;
    }
    close(syncfd[0]);

    /* 快速连续 stop+cont，不给子进程 CPU 处理中间状态 */
    kill(pid, SIGTSTP);
    kill(pid, SIGCONT);

    /* cont 后子应仍阻塞。观察窗口：若 stop+cont 误触发了 EINTR，子进程会几乎
     * 立即退出（微秒级）；旧代码用 1s 裕量过大，50ms 足以观察到提前退出。 */
    usleep(50000);
    int st;
    int rc = waitpid(pid, &st, WNOHANG);
    if(rc == pid) {
        printf("FAIL: child exited early (read returned EINTR during stop+cont)\n");
        close(fd[1]);
        return 1;
    }
    /* 子仍阻塞 -> 正确。写数据让它完成。 */
    write(fd[1], "x", 1);
    close(fd[1]);
    waitpid(pid, &st, 0);
    printf("PASS: read survived stop+cont, still blocked until data\n");
    return 0;
}
