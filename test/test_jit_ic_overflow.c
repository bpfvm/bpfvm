/* 间接调用 IC 快路径的栈溢出回归测试。
 *
 * 递归经 volatile 函数指针间接自调用：目标编译后调用点 IC 槽被填，后续调用走
 * JIT 内联 push_frame 快路径。guest 栈（16MB）耗尽时必须由快路径的显式
 * frame_base < STACK_BASE 检查干净地置 VM_KILLED（子进程表现为被 SIGKILL 杀死），
 * 不得在退出路径上留下失衡的宿主栈导致宿主 SIGSEGV：快路径的 entry/frame
 * 不得压宿主栈跨越 .overflow 与 mem-access abort 出口——vm_exit 定长弹栈，
 * SP 失衡会弹到垃圾地址，段错误现场 ret 跳进 guest 地址。
 *
 * 帧设计：8KB 数组 + volatile 下标令其整体驻留栈帧且只写帧顶（帧底越过
 * STACK_BASE 不会先触发写违例），溢出由调用点的 push_frame 检查发现；深度仅
 * 16MB/8KB ~= 2K 层，JIT 嵌套每层占宿主栈 ~64B，远不触宿主栈上限。
 * 宿主对照（host 变体）不打穿原生栈：浅层递归验证调用逻辑本身。
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

typedef int (*fn)(int);

static fn volatile next;

enum { PAD = 8192 };

static int rec(int n) {
    char pad[PAD];
    volatile int idx = PAD - 64;   /* volatile：下标不可折叠，整个数组必须驻留栈帧 */
    pad[idx] = (char)n;
    if (n <= 0) return 0;
    fn f = next;
    return f(n - 1) + pad[idx];
}

int main(void) {
    next = rec;
#ifdef __BPF__
    int depth = 1 << 20;   /* 必然耗尽 16MB guest 栈 */
#else
    int depth = 64;        /* 宿主只验证浅层调用逻辑，不打穿原生栈 */
#endif
    pid_t pid = fork();
    if (pid == 0) {
        rec(depth);        /* guest：必触发栈溢出 -> VM_KILLED；host：正常返回 */
        _exit(0);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) {
        printf("waitpid failed\n");
        return 1;
    }
#ifdef __BPF__
    /* 违例退出码 128+SIGKILL 经 VM 的 waitpid 模拟按 shell 惯例还原为"信号 9 杀死"；
     * 快路径失衡崩宿主则表现为信号 11（SIGSEGV） */
    if (!WIFSIGNALED(st) || WTERMSIG(st) != SIGKILL) {
        printf("child not killed by SIGKILL (exit %d, signal %d)\n",
               WIFEXITED(st) ? WEXITSTATUS(st) : -1,
               WIFSIGNALED(st) ? WTERMSIG(st) : 0);
        return 1;
    }
#else
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("child exit %d, signal %d\n",
               WIFEXITED(st) ? WEXITSTATUS(st) : -1,
               WIFSIGNALED(st) ? WTERMSIG(st) : 0);
        return 1;
    }
#endif
    printf("ok\n");
    return 0;
}
