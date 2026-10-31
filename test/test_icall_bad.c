/* 间接调用 IC 的垃圾目标回归测试：哨兵相撞不得崩宿主。
 *
 * 快路径按 tag==target 判命中后直接 call slot->entry。未填槽的 tag 哨兵与
 * guest 的垃圾函数指针值（空指针 / -1）相撞时 entry==nullptr，命中路径必须
 * 空判落 .slow，走 helper 的 mmu 校验干净拒绝（VM_KILLED），不得直接 call
 * nullptr 崩宿主。
 *
 * 触发形态：调用点从未执行、但被热循环头 OSR 一并编入片段（BFS 覆盖冷分支），
 * 首次执行即传垃圾目标 -> 未填槽 + tag 相撞。目标经 volatile 变量传入——
 * 常量函数指针会被 clang 降成 call imm（syscall 通道），到不了 callx。
 * guest 期望子进程被 SIGKILL（内存违例）；host 对照打穿原生栈是 SIGSEGV。
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

typedef int (*fn)(int);
static fn volatile next;
static int s;

/* 目标必须取自 volatile 读：既保 guest 的 callx 形态，也防 host -O1 内联后
 * 把常量空指针调用当 UB 折叠掉（子进程正常返回，测试失效） */
static int trigger(void) {
    for (volatile int i = 0; i < 300000; i++) {
        s += i;
        if (i == 299999) {          /* 调用点首次执行发生在 JIT 片段内 */
            fn f = next;
            s += f(1);
        }
    }
    return s & 0x7f;
}

static int run_case(unsigned long garbage, int expect_sig) {
    next = (fn)garbage;
    pid_t pid = fork();
    if (pid < 0) {
        printf("fork failed\n");
        return 1;
    }
    if (pid == 0) {
        _exit(trigger());
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) {
        printf("waitpid failed\n");
        return 1;
    }
    if (!WIFSIGNALED(st) || WTERMSIG(st) != expect_sig) {
        printf("child not killed by signal %d (exit %d, signal %d)\n",
               expect_sig, WIFEXITED(st) ? WEXITSTATUS(st) : -1,
               WIFSIGNALED(st) ? WTERMSIG(st) : 0);
        return 1;
    }
    return 0;
}

int main(void) {
#ifdef __BPF__
    /* guest：两种垃圾目标都必须被 VM 干净拒绝（SIGKILL），宿主不得段错误
     * （SIGSEGV=11 即哨兵相撞崩宿主的回归形态） */
    if (run_case(0, SIGKILL)) return 1;
    if (run_case(~0UL, SIGKILL)) return 1;
#else
    /* host 对照：原生调用空指针/-1 是 SIGSEGV，验证测试形态本身有效 */
    if (run_case(0, SIGSEGV)) return 1;
#endif
    printf("ok\n");
    return 0;
}
