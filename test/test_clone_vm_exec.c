// 裸 clone(CLONE_VM) + 子 execve：exec"换新 mm"语义的通用回归，不经 posix_spawn。
// CLONE_VM 使父子共享同一地址空间；子 exec 必须只替换自己的空间（内核语义：
// execve 装新 mm，对旧 mm 只减引用），父在子 exec 后继续在旧地址空间上运行。
// musl 的 vfork 退化为 fork，stdlib 中仅 posix_spawn 与裸 clone 走
// CLONE_VM-without-CLONE_THREAD；本用例直接构造后者，失败模式为父恢复执行时
// 踩已释放页（SIGSEGV）或读到被换掉的地址空间（金丝雀校验失败）。
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>

extern char **environ;

#define STK_SIZE (512 * 1024)

static int child_fn(void *arg) {
    char *const cargv[] = { "clonevm-arg1", "clonevm-arg2", NULL };
    execve((const char *)arg, cargv, environ);
    _exit(126);   /* exec 失败 */
}

/* FNV-1a：对金丝雀区域取指纹 */
static unsigned long fnv(const void *p, size_t n) {
    const unsigned char *b = p;
    unsigned long h = 1469598103934665603UL;
    for (size_t i = 0; i < n; i++) {
        h ^= b[i];
        h *= 1099511628211UL;
    }
    return h;
}

int main(void) {
    /* 按 BPF_TEST_VARIANT 选择 helper 变体（.out 静态 / .linked 动态 / .host 宿主） */
    const char *variant = getenv("BPF_TEST_VARIANT");
    if (!variant || !*variant) variant = "out";
    static char target[128];
    snprintf(target, sizeof(target), "test/test_arg.%s", variant);

    /* 金丝雀：堆 / 栈 / 只读数据各一份，子 exec 前后指纹必须一致 */
    char *heap_c = strdup("clone-vm-canary-heap");
    static const char ro_c[] = "clone-vm-canary-rodata";
    volatile unsigned char stk_c[64];
    for (size_t i = 0; i < sizeof(stk_c); i++) {
        stk_c[i] = (unsigned char)(i * 37 + 5);
    }
    unsigned long want = fnv(heap_c, 21) ^ fnv(ro_c, sizeof(ro_c))
                       ^ fnv((const void *)stk_c, sizeof(stk_c));

    /* CLOEXEC 同步 pipe：子 exec 即 EOF，强制父恰好在 exec 之后恢复执行 guest 代码
     * （waitpid 全程睡眠在宿主侧、不触碰 guest 内存，验不出地址空间破坏）。 */
    int p[2];
    if (pipe2(p, O_CLOEXEC) != 0) {
        printf("FAIL: pipe2 (errno=%d)\n", errno);
        return 1;
    }

    char *stk = malloc(STK_SIZE);
    if (!stk) {
        printf("FAIL: malloc child stack\n");
        return 1;
    }
    /* 栈顶留 16 字节余量：clone 包装对栈顶对齐再 -8，VM 在该处写哨兵帧 */
    pid_t pid = clone(child_fn, stk + STK_SIZE - 16, CLONE_VM | SIGCHLD, (void *)target);
    if (pid < 0) {
        printf("FAIL: clone (errno=%d)\n", errno);
        return 1;
    }
    close(p[1]);
    if (read(p[0], &(int){0}, sizeof(int)) != 0) {
        printf("FAIL: unexpected sync data\n");
        return 1;
    }

    /* 子已 exec（或已退出）：父此刻必须在完好的旧地址空间上继续运行 */
    unsigned long got = fnv(heap_c, 21) ^ fnv(ro_c, sizeof(ro_c))
                      ^ fnv((const void *)stk_c, sizeof(stk_c));
    if (got != want) {
        printf("FAIL: parent address space corrupted after child exec\n");
        return 1;
    }
    printf("parent address space intact after child exec\n");

    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0x22) {
        printf("FAIL: child status=0x%x (expected exit 0x22)\n", status);
        return 1;
    }
    close(p[0]);
    free(stk);
    free(heap_c);
    printf("clone(CLONE_VM)+exec ok\n");
    return 0;
}
