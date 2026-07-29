#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <string.h>

/* 验证修复后，该中断的信号仍能中断阻塞调用，可忽略信号不再误中断。
 * 用 WNOHANG 判断子进程是否提前退出。 */
static volatile sig_atomic_t got = 0;
static void h(int s){ (void)s; got = 1; }

/* kind: 0=nanosleep 1=read 2=poll ; setup: 是否安装 SIGUSR1 handler */
static int run_case(int kind, int setup, int sig){
    int fd[2]; pipe(fd);
    pid_t pid = fork();
    if(pid==0){
        if(setup){ struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_handler=h; sigaction(SIGUSR1,&sa,0); }
        /* 阻塞时长 = 各 kind 的退出兜底（信号中断在前）：必须大于父侧等待 + 观察窗口，
         * 否则可忽略信号那组子进程会因超时正常退出，被误判为"提前退出"。
         * 父侧 usleep(50ms)+观察 100ms=150ms，故 1s 裕量充足（原 2s 裕量过大）。
         * 注意：不能在进入阻塞前用 pipe 同步通知父进程——SIGUSR1(caught) 这组要求
         * 信号在子进程已处于阻塞调用期间到达，而通知→真正进入阻塞之间有指令窗口，
         * 信号提前到达会被 handler 消化掉而不打断后续阻塞调用，造成误判。 */
        if(kind==0){ struct timespec ts={1,0},rem={0}; nanosleep(&ts,&rem); _exit(0); }
        if(kind==1){ close(fd[1]); char buf[16]; read(fd[0],buf,sizeof buf); _exit(0); }
        if(kind==2){ close(fd[1]); struct pollfd pf={.fd=fd[0],.events=POLLIN}; poll(&pf,1,1000); _exit(0); }
        _exit(99);
    }
    /* 等子进程进入阻塞态。无法用 pipe 精确同步（见上注），保留短延迟；50ms 足够
     * 让子进程跑完 sigaction + 进入 nanosleep/read/poll（原 100ms 裕量过大）。 */
    usleep(50000);
    kill(pid, sig);
    /* 观察窗口：被中断的子进程几乎立刻退出，100ms 足以观察到提前退出（原 200ms）。 */
    usleep(100000);
    int st;
    int rc = waitpid(pid, &st, WNOHANG);
    int early = (rc == pid);
    if(!early){ kill(pid,SIGKILL); waitpid(pid,&st,0); }
    close(fd[0]); close(fd[1]);
    return early;
}
int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    /* 1. 可忽略信号不应中断（修复目标）*/
    int ign_ok = 1;
    for(int k=0;k<3;k++) if(run_case(k, 0, SIGCONT)) ign_ok = 0;
    printf("SIGCONT (default Cont) ignored, not interrupting: %s\n", ign_ok?"PASS":"FAIL");

    /* 2. 默认 Ign 的 SIGCHLD 不应中断 */
    int chld_ok = 1;
    for(int k=0;k<3;k++) if(run_case(k, 0, SIGCHLD)) chld_ok = 0;
    printf("SIGCHLD (default Ign) ignored, not interrupting: %s\n", chld_ok?"PASS":"FAIL");

    /* 3. 已 catch 的 SIGUSR1 必须中断 */
    int catch_ok = 1;
    for(int k=0;k<3;k++) if(!run_case(k, 1, SIGUSR1)) catch_ok = 0;
    printf("SIGUSR1 (caught) interrupts: %s\n", catch_ok?"PASS":"FAIL");

    /* 4. 默认 Term 的 SIGTERM 必须中断（终止进程）*/
    int term_ok = 1;
    for(int k=0;k<3;k++) if(!run_case(k, 0, SIGTERM)) term_ok = 0;
    printf("SIGTERM (default Term) interrupts: %s\n", term_ok?"PASS":"FAIL");

    return (ign_ok&&chld_ok&&catch_ok&&term_ok) ? 0 : 1;
}
