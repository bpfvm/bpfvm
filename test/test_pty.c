/* PTY / 控制终端语义测试。
 *
 * 覆盖：
 *   - 自建 pty：open("/dev/ptmx") + ioctl(TIOCSPTLCK/TIOCGPTN) + open("/dev/pts/N")
 *   - slave 是 tty：isatty(slave)==1
 *   - tcgetattr 读出 termios（验证 TCGETS）
 *   - tcsetattr 切 ICANON/ECHO off（验证 TCSETS）并读回验证
 *   - TIOCGWINSZ 读出非 0 行列
 *   - TIOCGPGRP == 自身 pgrp（验证前台组初始化）
 *   - 深层路径：fork->子 setsid()+TIOCSCTTY 建新会话并绑 ctty，再 tcsetpgrp/tcgetpgrp
 *     往返，覆盖 session/ctty/前台组语义
 *
 * 运行：bpfvm --pty test_pty.out / bpfvm test_pty.out   均可。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <errno.h>

/* 自建一对 pty，master/slave 双向返回。对齐 test_openpty.c 的低层调用序列，
 * 显式覆盖 open("/dev/ptmx") + TIOCSPTLCK + TIOCGPTN + open("/dev/pts/N") 拦截点。 */
static int make_pty(int *master_out, int *slave_out) {
    int master = open("/dev/ptmx", O_RDWR);
    if(master < 0) return -1;
    int unlock = 0;
    if(ioctl(master, 0x40045431 /*TIOCSPTLCK*/, &unlock) != 0) {
        close(master); return -1;
    }
    int ptn = 0;
    if(ioctl(master, 0x80045430 /*TIOCGPTN*/, &ptn) != 0) {
        close(master); return -1;
    }
    char name[32];
    snprintf(name, sizeof(name), "/dev/pts/%d", ptn);
    int slave = open(name, O_RDWR | O_NOCTTY);
    if(slave < 0) {
        close(master); return -1;
    }
    *master_out = master;
    *slave_out = slave;
    return 0;
}

/* 会话 leader：建 pty、绑 ctty（成为前台组），fork 孙进程做 setsid/TIOCSCTTY 抢夺
 * 断言。退出码：0=正确；非 0=各步失败码。 */
static int leader_main(void) {
    int master, slave;
    if(make_pty(&master, &slave) != 0) {
        printf("make_pty failed\n");
        return 1;
    }

    /* isatty：slave 是真 tty。 */
    if(!isatty(slave)) {
        printf("slave not a tty\n");
        return 1;
    }

    /* tcgetattr / TCGETS */
    struct termios t;
    if(tcgetattr(slave, &t) != 0) {
        printf("tcgetattr failed errno=%d\n", errno);
        return 1;
    }

    /* 切 ICANON/ECHO off / TCSETS，再读回验证。*/
    t.c_lflag &= ~ICANON;
    t.c_lflag &= ~ECHO;
    if(tcsetattr(slave, TCSANOW, &t) != 0) {
        printf("tcsetattr failed errno=%d\n", errno);
        return 1;
    }
    struct termios t2;
    if(tcgetattr(slave, &t2) != 0) {
        printf("tcgetattr(2) failed errno=%d\n", errno);
        return 1;
    }
    if((t2.c_lflag & ICANON) != 0) {
        printf("ICANON still set after tcsetattr: lflag=0x%x\n", t2.c_lflag);
        return 1;
    }

    /* 绑控制终端：leader setsid 后是新 session leader，TIOCSCTTY 成功，前台组=自身。 */
    if(ioctl(slave, 0x540E /*TIOCSCTTY*/, 0) != 0) {
        printf("TIOCSCTTY failed errno=%d\n", errno);
        return 1;
    }

    /* winsize：先 TIOCSWINSZ 设一个非 0 值（自建 pty 默认 winsize 可能 0），再读回。 */
    struct winsize ws_set;
    memset(&ws_set, 0, sizeof(ws_set));
    ws_set.ws_row = 24;
    ws_set.ws_col = 80;
    if(ioctl(slave, TIOCSWINSZ, &ws_set) != 0) {
        printf("TIOCSWINSZ failed errno=%d\n", errno);
        return 1;
    }
    struct winsize ws;
    if(ioctl(slave, TIOCGWINSZ, &ws) != 0) {
        printf("TIOCGWINSZ failed errno=%d\n", errno);
        return 1;
    }
    if(ws.ws_row == 0 || ws.ws_col == 0) {
        printf("pty: winsize zero row=%d col=%d\n", ws.ws_row, ws.ws_col);
        return 1;
    }

    /* 前台进程组：getpgrp() == tcgetpgrp(slave)（leader 绑 ctty 后自身即前台组）。 */
    pid_t me = getpgrp();
    int pgrp = 0;
    if(ioctl(slave, TIOCGPGRP, &pgrp) != 0) {
        printf("TIOCGPGRP failed errno=%d\n", errno);
        return 1;
    }
    if(pgrp != me) {
        printf("tcgetpgrp %d != getpgrp %d\n", pgrp, me);
        return 1;
    }

    /* 深层路径：fork->孙 setsid() 建新会话，再对同一 slave 做 TIOCSCTTY 抢夺。
     * POSIX：孙 setsid 后新 session 无 ctty；继承的 slave fd 仍是 leader session 的
     * ctty（同一 pty slave），非 force 抢应失败 EPERM（一个 tty 同时只属一个 session）；
     * force=1 抢夺应成功。验证多 session 的 ctty 占用语义。 */
    pid_t child = fork();
    if(child < 0) {
        printf("fork failed\n");
        return 1;
    }
    if(child == 0) {
        pid_t sid = setsid();
        if(sid < 0) {
            printf("child setsid failed errno=%d\n", errno);
            _exit(1);
        }
        /* 非 force 抢：slave 已是 leader session 的 ctty -> EPERM */
        if(ioctl(slave, TIOCSCTTY, 0) == 0) {
            printf("child TIOCSCTTY(non-force) unexpectedly succeeded\n");
            _exit(1);
        }
        /* force=1 抢夺：bpfvm 合成 pty 允许（对齐 POSIX 抢夺语义）；Linux 真机内核对
         * TIOCSCTTY 的 stealing 严格要求 CAP_SYS_ADMIN 且目标 tty 无活动引用，普通用户
         * 甚至 root 也被 EPERM 拒绝。这是 bpfvm 有意放宽的语义（无 uid/CAP 模型），
         * 故 force 抢断言只在 __bpf__ 下检查；后续依赖抢夺成功的 tcsetpgrp/TIOCGPGRP
         * 往返同样只在 __bpf__ 下执行。 */
#ifdef __bpf__
        if(ioctl(slave, TIOCSCTTY, 1) != 0) {
            printf("child TIOCSCTTY(force) failed errno=%d\n", errno);
            _exit(1);
        }
        /* 设自身为前台组 */
        if(tcsetpgrp(slave, getpgrp()) != 0) {
            printf("child tcsetpgrp failed errno=%d\n", errno);
            _exit(1);
        }
        /* 读回应等于自身 pgrp */
        int fg = 0;
        if(ioctl(slave, TIOCGPGRP, &fg) != 0) {
            printf("child TIOCGPGRP failed errno=%d\n", errno);
            _exit(1);
        }
        if(fg != getpgrp()) {
            printf("child fg %d != pgrp %d\n", fg, getpgrp());
            _exit(1);
        }
#endif
        _exit(0);
    }
    int st = 0;
    if(waitpid(child, &st, 0) != child) {
        printf("waitpid failed\n");
        return 1;
    }
    if(st != 0) {
        printf("child status %d\n", st);
        return 1;
    }

    /* 先报告成功再关 master：close(master) 对齐 Linux pty_close -> tty_vhangup，向该
     * ctty 前台组（leader 自身）投 SIGHUP，默认动作终止 leader。故 printf 必须在
     * close(master) 之前完成，否则被 SIGHUP 打断跑不到。close(slave) 不触发 SIGHUP。 */
    printf("pty ok row=%d col=%d pgrp=%d\n", ws.ws_row, ws.ws_col, pgrp);
    close(slave);
    close(master);
    return 0;
}

int main(void) {
    /* 测试进程已是组长（bpfvm/真机 启动的首个 guest），setsid 会 EPERM，故 fork
     * 出一个中间子进程当会话 leader，由它建 pty、绑 ctty、跑深层断言。 */
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
    if(waitpid(leader, &status, 0) != leader) {
        printf("waitpid leader failed\n");
        return 1;
    }
    /* leader 正常退出：返回其退出码。
     * leader 被 SIGHUP 杀：也算成功。因为 leader_main 在 close(master) 前已 printf 完
     * 成功信息并 return 0，随后的 close(master) 对齐 Linux pty_close -> 向 ctty 前台组
     * 投 SIGHUP，leader 自身正是前台组，故被 SIGHUP 终止——这是预期的 Linux 语义，
     * 不是断言失败（断言失败会先 _exit 非 0，走 WIFEXITED 分支返回非 0）。 */
    if(WIFEXITED(status)) return WEXITSTATUS(status);
    if(WIFSIGNALED(status) && WTERMSIG(status) == SIGHUP) return 0;
    return 1;
}
