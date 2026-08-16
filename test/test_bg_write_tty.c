/* 后台进程组写控制终端的信号语义回归测试（Bug 1 + Bug 2）。
 *
 * 覆盖 src/posix/file_io.cpp 的 tty_bg_check 两个缺陷：
 *
 *   Bug 1（写分支不检查 TOSTOP）：后台组写控制终端时，POSIX 规定仅当 termios
 *     c_lflag & TOSTOP 才产生 SIGTTOU；默认 TOSTOP=0，写照常进行。当前实现
 *     无条件对后台写投 SIGTTOU。
 *
 *   Bug 2（SIG_IGN 不执行 I/O）：当 SIGTTOU 被设为 SIG_IGN 时，POSIX 规定信号
 *     被忽略、I/O 照常完成（返回写入的字节数）。当前实现在 SIG_IGN 时令 write
 *     返回 0 且不真正写，导致上层（musl write 包装）重试 -> 又触发 -> 死循环。
 *
 * 本用例自建 pty（open("/dev/ptmx") + ioctl(TIOCSPTLCK/TIOCGPTN) + open("/dev/pts/N")）。
 * 因测试进程已是进程组长（bpfvm/真机 启动的首个 guest），setsid 会 EPERM，故 fork
 * 出一个中间子进程当会话 leader + 控制终端持有者（前台组），它再 fork 孙进程：
 *   - 孙进程 setpgid 到独立后台组、对 SIGTTOU 设 SIG_IGN，写控制终端；
 *   - 正确行为：write 返回写入字节数(>0)，孙进程正常退出 0；
 *   - Bug 2 回归：write 返回 0 -> musl 重试 -> 死循环，孙进程卡住（靠 alarm 兜底）。
 *
 * 孙进程的退出码经 leader 透传回 main。TOSTOP=0 + SIG_IGN 时正确应通过；
 * Bug 1 单独（SIG_DFL）的覆盖见 test_bg_write_tostop.c。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <signal.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

static int make_pty(int *master_out, int *slave_out) {
    int master = open("/dev/ptmx", O_RDWR);
    if(master < 0) return -1;
    int unlock = 0;
    if(ioctl(master, 0x40045431 /*TIOCSPTLCK*/, &unlock) != 0) return -1;
    int ptn = 0;
    if(ioctl(master, 0x80045430 /*TIOCGPTN*/, &ptn) != 0) return -1;
    char name[32];
    snprintf(name, sizeof(name), "/dev/pts/%d", ptn);
    int slave = open(name, O_RDWR | O_NOCTTY);
    if(slave < 0) return -1;
    *master_out = master;
    *slave_out = slave;
    return 0;
}

/* 会话 leader：建 pty、绑 ctty（成为前台组），fork 后台组孙进程写 ctty。
 * 退出码：0=正确；1=孙进程卡住(Bug2 死循环)；2=write 返回<=0；其他=构造失败。 */
static int leader_main(void) {
    int master, slave;
    if(make_pty(&master, &slave) != 0) return 3;

    struct termios t;
    if(tcgetattr(slave, &t) != 0) return 3;
    if(t.c_lflag & TOSTOP) {              /* 确保默认 TOSTOP=0 */
        t.c_lflag &= ~TOSTOP;
        tcsetattr(slave, TCSANOW, &t);
    }
    if(ioctl(slave, 0x540E /*TIOCSCTTY*/, 0) != 0) return 3;

    pid_t grand = fork();
    if(grand < 0) return 3;
    if(grand == 0) {
        if(setpgid(0, 0) < 0) _exit(4);   /* 后台组 */
        signal(SIGTTOU, SIG_IGN);         /* 忽略 SIGTTOU：应使写照常完成 */
        /* alarm 兜底：Bug2 回归时 write 返回 0 -> musl 重试死循环，3 秒后强退。 */
        signal(SIGALRM, _exit);
        alarm(3);
        const char *msg = "bg write\n";
        ssize_t w = write(slave, msg, strlen(msg));
        alarm(0);
        _exit(w > 0 ? 0 : 2);             /* 写成功(>0)->0；返回0/失败->2 */
    }
    setpgid(grand, grand);

    int status = 0;
    pid_t r = 0;
    for(int i = 0; i < 50 && r == 0; i++) {   /* 轮询 5 秒 */
        r = waitpid(grand, &status, WNOHANG);
        struct timespec ts = {0, 100 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    if(r != grand) {
        printf("FAIL: grandchild stuck in write loop (Bug 2: SIG_IGN write returns 0)\n");
        kill(grand, SIGKILL);
        waitpid(grand, &status, 0);
        return 1;
    }
    if(WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("bg_write_tty_ign ok\n");
        return 0;
    }
    if(WIFSIGNALED(status)) {
        printf("FAIL: grandchild killed by SIG%d\n", WTERMSIG(status));
        return 1;
    }
    printf("FAIL: grandchild exit code=%d (write returned <=0)\n", WEXITSTATUS(status));
    return 2;
}

int main(void) {
    /* 测试进程已是组长，fork 出 leader 子进程建新会话。 */
    pid_t leader = fork();
    if(leader < 0) {
        printf("fork leader failed\n");
        return 1;
    }
    if(leader == 0) {
        if(setsid() < 0) _exit(5);
        _exit(leader_main());
    }
    int status = 0;
    waitpid(leader, &status, 0);
    if(WIFEXITED(status)) return WEXITSTATUS(status);
    return 1;
}
