#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

int main(void) {
    /* 按 BPF_TEST_VARIANT 选择 exec 的 helper 变体（.out 静态 / .linked 动态）。
       helper(test_arg) 自身留在 BPF_TEST_HELPERS，由本测试驱动运行。 */
    const char *variant = getenv("BPF_TEST_VARIANT");
    if (!variant || !*variant) variant = "out";
    char target[128];
    snprintf(target, sizeof(target), "test/test_arg.%s", variant);

    printf("fork+execve launcher: before fork (target=%s)\n", target);
    char *const argv[] = { "test.out", "arg1", "arg2", NULL };
    char *const envp[] = { "FOO=bar", "HELLO=world", NULL };
    int pid = fork();
    if(pid == 0) {
        printf("child: before execve\n");
        int rc = execve(target, (char *const*)argv, (char *const*)envp);
        printf("child: execve failed: %d\n", rc);
        return rc;
    }
    printf("parent: fork pid=%d\n", pid);
    int status = 0;
    int rc = waitpid(-1, &status, 0);
    if(rc < 0) {
        printf("parent: waitpid failed: %d\n", rc);
        return rc;
    }
    int exit_code = (status >> 8) & 0xff;
    printf("parent: child %d exit code=%d\n", rc, exit_code);
    /* test_arg 返回 0x22(34)；校验 _start→exit 的退出码传递 */
    if (exit_code != 0x22) {
        printf("FAIL: expected 0x22(34), got %d\n", exit_code);
        return 1;
    }
    return 0;
}
