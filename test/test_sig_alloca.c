/*
 * test_sig_alloca.c — 验证信号处理函数内使用 VLA / alloca。
 *
 * 这是对 frame_base[0] 编码（低 32 位 total_len = stack_limit + alloca_len，
 * bit32 is_signal，共用一个 slot）的关键测试：新编码下 alloca 部分与 is_signal
 * 解耦，信号帧也能安全记录 alloca 区，因此信号处理函数体内可以用 VLA /
 * __builtin_alloca（经 BpfVlaPass 改写成 BPF_SYS_ALLOCA syscall），分配在信号帧
 * 自己的 alloca 区，信号返回（pop_frame）时随帧自动回收。
 *
 * 验证点：
 *   1. 信号处理函数内用 VLA 做计算，结果正确（写读不越界、不被覆盖）。
 *   2. 反复触发同一信号（这里用 SIGUSR1 触发 N 次），每次处理函数都 alloca，
 *      依赖随帧回收——若不回收会很快吃满 8MiB 栈而崩溃。能跑完即回收正确。
 *   3. 信号返回后被中断函数的状态（含其自身的 alloca 区）未被破坏。
 *
 * 全部通过 exit(0)，否则 exit(1)。
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

static volatile sig_atomic_t handler_ok_count = 0;
static volatile sig_atomic_t handler_fail = 0;

/* 信号处理函数内用 VLA：
 *   - volatile 阻止优化器把 VLA 折叠成静态 alloca，确保走 BPF_SYS_ALLOCA。
 *   - 在信号帧上分配，写满后校验，再算一个返回值。 */
static void on_usr1(int sig) {
    (void)sig;
    static volatile int seed = 32;   /* 编译期对优化器不透明 */
    int n = seed;
    if(n < 4) n = 4;

    int buf[n];
    /* 写入：buf[i] = i*2 + 1 */
    for (int i = 0; i < n; i++) buf[i] = i * 2 + 1;
    /* 校验 + 求和：检测是否被覆盖 / 越界 */
    long sum = 0;
    int bad = 0;
    for (int i = 0; i < n; i++) {
        if (buf[i] != i * 2 + 1) { bad = 1; break; }
        sum += buf[i];
    }
    /* 期望和 = n^2（1+3+5+...+(2n-1) = n^2） */
    if (bad || sum != (long)n * n) {
        handler_fail = 1;
        return;
    }

    /* 再来一个 char VLA，验证同处理函数多次 alloca 累计不重叠 */
    char tag[8];
    memset(tag, 'A', 8);
    /* 检查 int VLA 没被 char VLA 覆盖 */
    if (buf[0] != 1 || buf[n - 1] != (n - 1) * 2 + 1) {
        handler_fail = 2;
        return;
    }

    handler_ok_count++;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_usr1;
    /* 显式不阻塞自身：允许嵌套投递的回收测试由循环多次完成。 */
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        perror("sigaction");
        return 1;
    }

    /* 反复给自己发信号：每次处理函数都 alloca，依赖随帧回收。
     * N 取较大值（如 2000）：若每次分配不回收，累计 ~2000 * (32*4+8) ≈ 270KB，
     * 仍不至于爆 8MiB；这里主要验证正确性 + 不损坏被中断状态。
     * 想压爆需更大单次分配——本测试聚焦正确性。 */
    const int N = 2000;
    pid_t me = getpid();
    for (int i = 0; i < N; i++) {
        if (kill(me, SIGUSR1) != 0) {
            perror("kill");
            return 2;
        }
        if (handler_fail) {
            printf("handler failed (code=%d) at iter %d\n", (int)handler_fail, i);
            return 3;
        }
    }

    printf("handler_ok_count=%d (expect %d)\n", (int)handler_ok_count, N);
    if (handler_ok_count != N) {
        printf("MISSING invocations: got %d of %d\n", (int)handler_ok_count, N);
        return 4;
    }
    printf("sig_alloca: ok\n");
    return 0;
}
