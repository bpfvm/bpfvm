/* 测量多线程 exec 时 executor 等待 sibling 退出的唤醒延迟。
 *
 * 关键：在 child 内、execve 前后各取一次 CLOCK_MONOTONIC 时间戳，
 * 把"exec 前阻塞等待 sibling 退出"的耗时单独打印出来（executor 在替换地址
 * 空间前必须等同组其它线程退出，这段是我们要测的）。execve 成功后控制流
 * 不返回（被新程序替换），所以必须用 execve 的目标程序打印"exec 后"时间戳。
 *
 * 因此本测试 exec 的目标选成"打印时间戳"的简单程序。这里用 execve 自身路径
 * 可控的方式：目标程序读环境变量里的起始时间戳，算出 exec 的总墙钟耗时。
 *
 * 不依赖任何外部 .out，避免 cwd/相对路径问题——目标用绝对或同目录固定名。
 * 由于本测试在 child 内已 fork，目标名固定为 argv[0] 同目录下的 "exec_target"。
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <time.h>
#include <string.h>

/* worker：长睡眠，被 SIGKILL 后在 safepoint/信号处退出。
 * 不忙循环——忙循环 worker 退出极快，可能掩盖"executor 先阻塞则必卡超时"的 bug。 */
static void *worker(void *arg) {
    (void)arg;
    struct timespec ts = {10, 0};
    nanosleep(&ts, NULL);
    return NULL;
}

/* 把纳秒时间戳写进环境变量，供 exec 后的目标程序读取计算 elapsed。
 * 用 static 缓冲：putenv 不拷贝字符串、直接存指针，局部 buffer 函数返回即失效，
 * execve 前 getenv 会拿到悬垂/被覆盖内容（host 上实测返 NULL）。 */
static void stamp_env(const struct timespec *t) {
    static char buf[64];
    snprintf(buf, sizeof(buf), "EXEC_T0=%ld", (long)(t->tv_sec * 1000000000L + t->tv_nsec));
    putenv(buf);
}

int main(int argc, char **argv) {
    /* 被 exec 的目标模式：argv[1]=="--measured" 时打印本进程的启动时间差。 */
    if(argc > 1 && strcmp(argv[1], "--measured") == 0) {
        const char *e = getenv("EXEC_T0");
        if(!e) {
            return 0x11;
        }
        long t0 = atol(e);
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ns = (long)(now.tv_sec * 1000000000L + now.tv_nsec) - t0;
        printf("exec elapsed: %.6f s\n", elapsed_ns / 1e9);
        return elapsed_ns > 1e9 ? 0x11 : 0x22;  /* 固定退出码，父进程据此判定 exec 成功 */
    }

    pid_t pid = fork();
    if(pid < 0) { printf("fork failed\n"); return 1; }
    if(pid == 0) {
        pthread_t t;
        pthread_create(&t, NULL, worker, NULL);
        /* 给 worker 进入 nanosleep 的时间 */
        struct timespec d = {0, 50000000};
        nanosleep(&d, NULL);

        /* 取 exec 前时间戳，写环境变量。exec 会继承环境。 */
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        stamp_env(&t0);

        /* exec 自身（re-exec 本程序，带 --measured）。用 /proc/self/exe 避免路径问题。 */
        char *const av[] = {"exec_latency_target", "--measured", NULL};
        execve("/proc/self/exe", av, environ);
        perror("execve");
        _exit(51);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if(WIFEXITED(status) && WEXITSTATUS(status) == 0x22) {
        printf("OK\n");
    } else {
        printf("FAIL status=%d (WEXITSTATUS=%d)\n", status, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }
    return 0;
}
