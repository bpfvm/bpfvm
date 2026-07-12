/* 模拟 shell 的 Ctrl+C 行为：阻塞 read stdin，SIGINT handler 用 siglongjmp 跳出。
 * 对比 host 和 VM：Ctrl+C 后应该回到 "循环读取" 而不是退出。
 * 用 sigsetjmp/siglongjmp 模拟 ash 的 exception 机制。
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <setjmp.h>

static sigjmp_buf jmpbuf;
static volatile sig_atomic_t got_signal = 0;

static void handler(int s) {
    got_signal = s;
    /* 模拟 ash raise_interrupt: 直接 siglongjmp */
    siglongjmp(jmpbuf, 1);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  /* 无 SA_RESTART */
    sigaction(SIGINT, &sa, NULL);

    int loop = 0;
    for (;;) {
        int r = sigsetjmp(jmpbuf, 1);
        if (r != 0) {
            /* siglongjmp 回来 */
            printf("[caught signal, got=%d, loop=%d]\n", got_signal, loop);
            fflush(stdout);
            got_signal = 0;
        }
        loop++;
        printf("loop %d: waiting input (pid=%d)\n", loop, getpid());
        fflush(stdout);

        char buf[64];
        /* 阻塞 read */
        ssize_t n = read(0, buf, sizeof(buf));
        printf("loop %d: read returned %zd", loop, n);
        if (n < 0) printf(" errno=%d(%s)", errno, strerror(errno));
        printf("\n");
        fflush(stdout);
        if (n <= 0) {
            printf("loop %d: EOF/error, exiting\n", loop);
            fflush(stdout);
            break;
        }
        if (n > 0 && buf[0] == 'q') {
            printf("quit\n");
            break;
        }
        printf("loop %d: got data: ", loop);
        fflush(stdout);
        write(1, buf, n);
    }
    return 0;
}
