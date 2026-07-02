/* job-control 停止/恢复 + waitpid(WUNTRACED) 回归测试。
 *
 * 覆盖 SIGTSTP → 子进程停止 → 父进程经 SIGCHLD 唤醒 → waitpid(WUNTRACED) 报告
 * WIFSTOPPED / WSTOPSIG==SIGTSTP → kill(SIGCONT) 恢复 → 再 waitpid 报告退出 的完整链路。
 * 这是 dash 等交互式 shell 实现 CTRL+Z / fg 的核心机制。
 *
 * 关键点：子进程的 SIGTSTP 是它自己 raise 的（模拟收到 tty 信号停止），父进程靠
 * waitpid(WUNTRACED) 拿到停止状态，而非阻塞轮询。验证 bpfvm 的 stop_process +
 * notify_parent_sigchld + do_waitpid 的 WUNTRACED 支持。
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

int main(void) {
    pid_t child = fork();
    if (child < 0) {
        printf("fork failed\n");
        return 1;
    }
    if (child == 0) {
        /* 子进程：raise SIGTSTP 停止自己。bpfvm 的 stop_process 会设 tg 停止状态 +
         * 给父投 SIGCHLD。被 SIGCONT 恢复后继续往下走 exit(0)。 */
        raise(SIGTSTP);
        _exit(0);
    }

    /* 父进程：waitpid(WUNTRACED) 应被 SIGCHLD 唤醒并报告子进程已停止。 */
    int status = 0;
    pid_t r = waitpid(child, &status, WUNTRACED);
    if (r != child) {
        printf("waitpid(WUNTRACED) returned %d errno=%d\n", r, errno);
        return 1;
    }
    if (!WIFSTOPPED(status)) {
        printf("expected WIFSTOPPED, got status=0x%x\n", status);
        return 1;
    }
    if (WSTOPSIG(status) != SIGTSTP) {
        printf("WSTOPSIG=%d expected %d\n", WSTOPSIG(status), SIGTSTP);
        return 1;
    }

    /* 恢复子进程：kill SIGCONT。子进程 raise(SIGTSTP) 返回后 _exit(0)。 */
    if (kill(child, SIGCONT) < 0) {
        printf("kill SIGCONT failed errno=%d\n", errno);
        return 1;
    }

    /* 再 waitpid：应报告子进程退出，WIFEXITED，退出码 0。 */
    status = 0;
    r = waitpid(child, &status, 0);
    if (r != child) {
        printf("waitpid(exit) returned %d errno=%d\n", r, errno);
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("expected exit 0, got status=0x%x\n", status);
        return 1;
    }

    printf("wait_stop ok\n");
    return 0;
}
