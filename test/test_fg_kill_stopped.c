/* 停止态作业 SIGCONT 唤醒后挂起信号及时投递回归测试（Bug 3，仅 JIT 模式）。
 *
 * POSIX/Linux：进程被 SIGTSTP 停止（TASK_STOPPED）期间收到的非停止信号（如
 * SIGTERM）挂入 pending 队列、不投递；经 SIGCONT 唤醒恢复运行时，在返回用户态
 * 前（get_signal）投递挂起信号。dash `kill %1` 后 `fg %1` 的正确语义即依赖此：
 * kill 发的 SIGTERM 停止态挂起，fg 发的 SIGCONT 唤醒后立即投递 SIGTERM 终结作业。
 *
 * 回归（src/insn.cpp safepoint，仅 JIT 模式）：queue_signal(SIGCONT) 清 VM_STOPPED、
 * 唤醒 stop-wait 循环，但循环退出后未重新调用 handle_signals。挂起的 SIGTERM 滞留
 * 队列，子进程已先执行到用户代码（nanosleep）。迟到的 SIGTERM 撞上阻塞的 nanosleep，
 * 若被 SA_RESTART 重启则被丢弃，作业永不被杀。解释器模式每条指令前都 safepoint，
 * 故能在 nanosleep 前投递；JIT 模式 safepoint 检查点稀疏，故复现。
 *
 * 注：这是 dash `fg` 不生效的次要因素；主因（SIGTTOU+SIG_IGN 死循环）见
 * test_bg_write_tty.c。本用例独立验证信号投递时序。
 *
 * 流程：子进程 raise(SIGTSTP) 停 -> 父 SIGTERM(挂起)+SIGCONT(唤醒) -> 轮询 waitpid，
 * 期望 5 秒内被 SIGTERM 杀；回归（JIT 模式）时子进程卡在 nanosleep，5 秒超时。
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <errno.h>

int main(void) {
    pid_t child = fork();
    if(child < 0) {
        printf("fork failed\n");
        return 1;
    }
    if(child == 0) {
        raise(SIGTSTP);
        /* 被 SIGCONT 恢复后立即长 sleep —— 等同 dash 场景的 `sleep 30`。
         * 正确：SIGCONT 后 SIGTERM 在此前投递，本行不到达；
         * 回归（JIT）：SIGTERM 迟到，进入 nanosleep 被丢弃。 */
        struct timespec ts = {30, 0};
        nanosleep(&ts, NULL);
        _exit(0);
    }

    int status = 0;
    pid_t r = waitpid(child, &status, WUNTRACED);
    if(r != child || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTSTP) {
        printf("expected WIFSTOPPED/SIGTSTP, r=%d status=0x%x errno=%d\n",
               r, status, errno);
        return 1;
    }

    /* kill %1：SIGTERM（停止态挂起）。 */
    if(kill(child, SIGTERM) < 0) {
        printf("kill SIGTERM failed errno=%d\n", errno);
        return 1;
    }
    /* fg %1：SIGCONT 唤醒 —— 恢复后应在返回用户态前投递挂起的 SIGTERM。 */
    if(kill(child, SIGCONT) < 0) {
        printf("kill SIGCONT failed errno=%d\n", errno);
        return 1;
    }

    /* 轮询 5 秒：正确 1 秒内即被 SIGTERM 杀回收。 */
    pid_t got = 0;
    for(int i = 0; i < 50; i++) {
        status = 0;
        got = waitpid(child, &status, WNOHANG);
        if(got == child || got < 0) break;
        struct timespec ts = {0, 100 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }

    if(got != child) {
        printf("FAIL: child not collected in 5s — SIGTERM not delivered before "
               "nanosleep after SIGCONT (Bug 3, JIT only)\n");
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
        return 1;
    }
    if(!WIFSIGNALED(status) || WTERMSIG(status) != SIGTERM) {
        printf("expected WIFSIGNALED/SIGTERM, got status=0x%x\n", status);
        return 1;
    }

    printf("fg_kill_stopped ok\n");
    return 0;
}
