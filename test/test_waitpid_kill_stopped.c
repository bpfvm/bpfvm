/* kill 已停止的子进程，waitpid 必须报告 WIFSIGNALED 而非 WIFSTOPPED。
 *
 * 覆盖 shell 作业控制 `kill %1` / `kill -9 %1` 的两条回归路径，各一组 case：
 *
 *   case 1  stop=SIGSTOP  kill=SIGKILL
 *     回归 do_waitpid 的 exited/stopped 优先级（src/posix/process.cpp）：
 *     子进程被 SIGKILL 终止后 fini 设 tg->exited，但 tg->stopped 不被清除（只有
 *     SIGCONT 清）。若先判 stopped 会误报 WIFSTOPPED、不 erase pid_map，父进程
 *     （如 dash `kill -9 %1`）永不回收作业。
 *     SIGKILL 绕过 handle_signals：queue_signal 直接置 VM_KILLED，停止态也能被杀，
 *     不依赖 SIGCONT 唤醒。
 *
 *   case 2  stop=SIGTSTP  kill=SIGTERM + SIGCONT
 *     回归「停止态下信号挂起 + SIGCONT 唤醒后投递」的内核语义（kernel/signal.c:
 *     do_signal_stop / get_signal）。bash 对 `kill %1` 实际发的是一对系统调用
 *       kill(-pgid, SIGTERM);   // 停止态收 SIGTERM：不终结，挂入 pending 队列
 *       kill(-pgid, SIGCONT);   // 唤醒：清 TASK_STOPPED、返回用户态前投递 pending
 *     （strace 实测：bash 5.x `kill %1` 的两个 kill(2) 调用）。
 *
 *     因此本用例先发 SIGTERM 再紧跟 SIGCONT，期望 WIFSIGNALED/SIGTERM。这同时回归
 *     safepoint 的 stop-wait 循环（src/insn.cpp）：
 *       - SIGTERM 走 queue_signal 的 else 分支：push pending + 置 VM_SIGNAL_PENDING
 *         + wakeup，但不清 VM_STOPPED；停止态下 safepoint 不投递它。
 *       - SIGCONT 清 VM_STOPPED + wakeup，safepoint 退出 stop 循环返回用户态前必须
 *         重判 VM_SIGNAL_PENDING 并投递挂起的 SIGTERM，否则 SIGTERM 永远滞留队列。
 *
 * 两组都用 WNOHANG 轮询 + 超时，避免 bug 未修复时测试卡死在 waitpid。
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <errno.h>

/* 前置声明：reap_expect_signaled 定义在 case 函数之后。 */
static int reap_expect_signaled(pid_t child, int *status_out, int expected_sig);

/* case 1：SIGKILL 直接终结停止态子进程。
 * SIGKILL 绕过 handle_signals，queue_signal 直接置 VM_KILLED，无需 SIGCONT。 */
static int test_kill_stopped_sigkill(int stop_sig) {
    pid_t child = fork();
    if (child < 0) {
        printf("fork failed\n");
        return 1;
    }
    if (child == 0) {
        /* 子进程：停止自己（SIGSTOP 不可捕获；SIGTSTP 默认动作停止，模拟 Ctrl+Z）。 */
        raise(stop_sig);
        _exit(0);  /* 不应到达：被 SIGKILL 终止 */
    }

    /* 父进程：先确认子进程已停止。 */
    int status = 0;
    pid_t r = waitpid(child, &status, WUNTRACED);
    if (r != child || !WIFSTOPPED(status) || WSTOPSIG(status) != stop_sig) {
        printf("expected WIFSTOPPED/%d, r=%d status=0x%x errno=%d\n",
               stop_sig, r, status, errno);
        return 1;
    }

    /* 给已停止的子进程投 SIGKILL（不先 SIGCONT 恢复）。 */
    if (kill(child, SIGKILL) < 0) {
        printf("kill SIGKILL failed errno=%d\n", errno);
        return 1;
    }

    if (reap_expect_signaled(child, &status, SIGKILL) != 0) return 1;
    return 0;
}

/* case 2：bash `kill %1` 的真实行为 —— SIGTERM 紧跟 SIGCONT。
 * 停止态收 SIGTERM 只挂起不终结；SIGCONT 唤醒后返回用户态前投递 pending SIGTERM。
 * 回归 safepoint 退出 stop 循环时重判 VM_SIGNAL_PENDING 投递挂起信号的逻辑。 */
static int test_kill_stopped_sigterm_cont(int stop_sig) {
    pid_t child = fork();
    if (child < 0) {
        printf("fork failed\n");
        return 1;
    }
    if (child == 0) {
        /* 子进程：停止自己（SIGTSTP 默认动作停止，模拟 Ctrl+Z）。 */
        raise(stop_sig);
        _exit(0);  /* 不应到达：被 SIGTERM 终止 */
    }

    /* 父进程：先确认子进程已停止。 */
    int status = 0;
    pid_t r = waitpid(child, &status, WUNTRACED);
    if (r != child || !WIFSTOPPED(status) || WSTOPSIG(status) != stop_sig) {
        printf("expected WIFSTOPPED/%d, r=%d status=0x%x errno=%d\n",
               stop_sig, r, status, errno);
        return 1;
    }

    /* bash 行为：先 SIGTERM（停止态挂起 pending），紧接 SIGCONT（唤醒后投递）。
     * 若只发 SIGTERM 不发 SIGCONT，真实 Linux 上进程也永远不会被终结 ——
     * 这正是 bash `kill %1` 要发一对 kill(2) 的原因（strace 实测确认）。 */
    if (kill(child, SIGTERM) < 0) {
        printf("kill SIGTERM failed errno=%d\n", errno);
        return 1;
    }
    if (kill(child, SIGCONT) < 0) {
        printf("kill SIGCONT failed errno=%d\n", errno);
        return 1;
    }

    if (reap_expect_signaled(child, &status, SIGTERM) != 0) return 1;
    return 0;
}

/* 轮询 waitpid(WNOHANG)，最多约 5 秒。bug 未修复时子进程未被终止，
 * waitpid 恒返回 0（exited=false，stop_reported 已被首次 waitpid 消费）。
 * 成功回收后断言 WIFSIGNALED && WTERMSIG==expected_sig。 */
static int reap_expect_signaled(pid_t child, int *status_out, int expected_sig) {
    pid_t got = 0;
    int status = 0;
    for (int i = 0; i < 50; i++) {
        status = 0;
        got = waitpid(child, &status, WNOHANG);
        if (got == child || got < 0) break;
        struct timespec ts = {0, 100 * 1000 * 1000};  /* 100ms */
        nanosleep(&ts, NULL);
    }

    if (got != child) {
        printf("waitpid did not collect child (got=%d errno=%d) — "
               "did not terminate stopped child\n", got, errno);
        return 1;
    }
    if (!WIFSIGNALED(status) || WTERMSIG(status) != expected_sig) {
        printf("expected WIFSIGNALED/%d, got status=0x%x\n", expected_sig, status);
        return 1;
    }
    *status_out = status;
    return 0;
}

int main(void) {
    printf("[case] stop=SIGSTOP kill=SIGKILL\n");
    if (test_kill_stopped_sigkill(SIGSTOP)) return 1;
    printf("[case] stop=SIGTSTP kill=SIGTERM+SIGCONT\n");
    if (test_kill_stopped_sigterm_cont(SIGTSTP)) return 1;

    printf("waitpid_kill_stopped ok\n");
    return 0;
}
