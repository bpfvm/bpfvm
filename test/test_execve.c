#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("fork+execve launcher: before fork\n");
    char *const argv[] = { "test.out", "arg1", "arg2", NULL };
    char *const envp[] = { "FOO=bar", "HELLO=world", NULL };
    int pid = fork();
    if(pid == 0) {
        printf("child: before execve\n");
        int rc = execve("test/test_arg.out", (char *const*)argv, (char *const*)envp);
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
