/* 验证阻塞中的 read 被 SIGTSTP+SIGCONT 快速连续后仍正确阻塞（新模型：STOP 不踢 host syscall）。
 * 父进程 stop→立即 cont（不给子进程 CPU），子进程的 read 应从未被 EINTR 打断，
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

    pid_t pid = fork();
    if(pid == 0) {
        /* 子：阻塞 read，stop+cont 后应仍阻塞。收到数据后正常退出。 */
        close(fd[1]);
        char buf[16];
        int rc = read(fd[0], buf, sizeof buf);
        _exit(rc >= 0 ? 0 : 1);
    }
    close(fd[0]);

    /* 等 1s 让子进入 read 阻塞 */
    usleep(1000000);
    /* 快速连续 stop+cont，不给子进程 CPU 处理中间状态 */
    kill(pid, SIGTSTP);
    kill(pid, SIGCONT);

    /* cont 后子应仍阻塞。等 1s 检查是否提前退出。 */
    usleep(1000000);
    int st;
    int rc = waitpid(pid, &st, WNOHANG);
    if(rc == pid) {
        printf("FAIL: child exited early (read returned EINTR during stop+cont)\n");
        close(fd[1]);
        return 1;
    }
    /* 子仍阻塞 → 正确。写数据让它完成。 */
    write(fd[1], "x", 1);
    close(fd[1]);
    waitpid(pid, &st, 0);
    printf("PASS: read survived stop+cont, still blocked until data\n");
    return 0;
}
