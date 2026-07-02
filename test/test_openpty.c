/* posix_openpt/openpty 路径回归（tmux 等终端复用器的最小用例）。
 *
 * 覆盖 guest 通过 open("/dev/ptmx") + ioctl(TIOCSPTLCK/TIOCGPTN) + open("/dev/pts/N")
 * 创建 pty 并 master↔slave 互通：这正是 tmux 给每个 pane 开 pty 的调用序列。
 * bpfvm 在 do_openat 拦截 /dev/ptmx 与 /dev/pts/N，合成 host pty（ldisc 全交 host 内核）。
 *
 * 直接用低层调用（不经 libc 的 openpty 包装），以显式覆盖拦截点：
 *   1. open("/dev/ptmx", O_RDWR)            → master fd
 *   2. unlockpt(master)  = ioctl(TIOCSPTLCK,&zero)
 *   3. ptsname(master)   = ioctl(TIOCGPTN,&n) + 拼路径
 *   4. open("/dev/pts/N",O_RDWR|O_NOCTTY)    → slave fd
 *   5. write(master) / read(slave) 验证字节互通
 *   6. slave 是 tty：isatty(slave)==1, tcgetattr 成功
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>

int main(void) {
    int master = open("/dev/ptmx", O_RDWR);
    if (master < 0) {
        printf("open /dev/ptmx failed errno=%d\n", errno);
        return 1;
    }

    int unlock = 0;
    if (ioctl(master, 0x40045431 /*TIOCSPTLCK*/, &unlock) != 0) {  /* unlockpt */
        printf("TIOCSPTLCK(unlock) failed errno=%d\n", errno);
        return 1;
    }

    int ptn = 0;
    if (ioctl(master, 0x80045430 /*TIOCGPTN*/, &ptn) != 0) {       /* ptsname 的核心 */
        printf("TIOCGPTN failed errno=%d\n", errno);
        return 1;
    }

    char slave_name[32];
    snprintf(slave_name, sizeof(slave_name), "/dev/pts/%d", ptn);
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
        printf("open %s failed errno=%d\n", slave_name, errno);
        return 1;
    }

    /* isatty + tcgetattr：slave 是真 tty。 */
    if (!isatty(slave)) {
        printf("slave not a tty\n");
        return 1;
    }
    struct termios t;
    if (tcgetattr(slave, &t) != 0) {
        printf("tcgetattr failed errno=%d\n", errno);
        return 1;
    }

    /* 字节互通：写 master，从 slave 读（slave 非默认 ICANON 时会逐字节）。
     * 默认 ICANON 下需换行才交付，这里先把 slave 切 raw 以便单字节互通验证。 */
    cfmakeraw(&t);
    tcsetattr(slave, TCSANOW, &t);

    const char *msg = "hi-pty";
    if (write(master, msg, 6) != 6) {
        printf("write master failed errno=%d\n", errno);
        return 1;
    }
    char buf[16] = {0};
    ssize_t r = read(slave, buf, sizeof(buf));
    if (r != 6 || memcmp(buf, msg, 6) != 0) {
        printf("slave read got %zd: %.*s\n", r, (int)r, buf);
        return 1;
    }

    /* 反向：写 slave，从 master 读。 */
    if (write(slave, "ok", 2) != 2) {
        printf("write slave failed errno=%d\n", errno);
        return 1;
    }
    char buf2[16] = {0};
    r = read(master, buf2, sizeof(buf2));
    if (r != 2 || memcmp(buf2, "ok", 2) != 0) {
        printf("master read got %zd: %.*s\n", r, (int)r, buf2);
        return 1;
    }

    close(slave);
    close(master);
    printf("openpty ok ptn=%d\n", ptn);
    return 0;
}
