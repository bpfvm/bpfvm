// fork + exec 只读段生命周期回归：父进程 fork 出长跑子进程后立即 execve 自身替换
// 镜像。旧 text/rodata 宿主页必须经引用计数存活（fork 时转入 cow_data 共享给子进程），
// 否则父 exec 释放旧 RO 页，仍在运行的子进程继续取指/读常量即 use-after-unmap，
// 整进程以宿主 SIGSEGV（139）退出。
//
// 形态：无参运行 = 旧镜像：fork 长跑子进程（持续执行代码+读 rodata，退出码 7），
// 然后 execve("/proc/self/exe", {self, child_pid})。带参运行 = exec 后的新镜像：
// waitpid(child) 直到它以 7 退出。
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

extern char** environ;

static const char rodata_str[] = "constant payload for fork/exec ro lifetime test";

__attribute__((noinline)) static int touch_ro(void) {
    // 跨页读 rodata，强迫 text 与只读数据段都真实走访存
    return rodata_str[0] + rodata_str[sizeof(rodata_str) - 2];
}

int main(int argc, char** argv) {
    if (argc > 1) {
        // exec 后的新镜像：回收旧镜像 fork 的子进程
        pid_t child = (pid_t)atoi(argv[1]);
        for (int i = 0; i < 100; i++) {
            int st = 0;
            pid_t r = waitpid(child, &st, WNOHANG);
            if (r == child) {
                if (WIFEXITED(st) && WEXITSTATUS(st) == 7) {
                    printf("fork exec ro lifetime ok\n");
                    return 0;
                }
                return 9;  // 子进程异常退出
            }
            if (r < 0) {
                return 8;  // 子进程丢失
            }
            usleep(20000);
        }
        return 8;  // 2s 内未退出
    }

    pid_t child = fork();
    if (child == 0) {
        // 子进程活得比父进程的 exec 更久：持续执行自身代码并读 rodata
        volatile long s = 0;
        for (int i = 0; i < 300; i++) {
            s += touch_ro();
            usleep(1000);
        }
        if (s == 0x7fffffff00000000L) {
            return 1;  // 消除"结果未用"优化；正常不可能命中
        }
        return 7;
    }
    if (child < 0) {
        return 5;
    }

    char pbuf[16];
    snprintf(pbuf, sizeof(pbuf), "%d", (int)child);
    char* nargv[3] = { argv[0], pbuf, NULL };
    // 透传当前 environ：动态链接变体（.linked PIE）依赖 LD_LIBRARY_PATH 找 ldso
    execve("/proc/self/exe", nargv, environ);
    return 6;  // exec 不应返回
}
