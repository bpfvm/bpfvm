#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char** argv) {
    int fd_cloexec = open("cloexec_check.tmp", O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd_cloexec < 0) {
        printf("Parent: Failed to open cloexec file: %s\n", strerror(errno));
        return 1;
    }

    int fd_keep = open("keep_check.tmp", O_WRONLY | O_CREAT, 0644);
    if (fd_keep < 0) {
        printf("Parent: Failed to open keep file: %s\n", strerror(errno));
        return 1;
    }

    char fd1_str[16];
    char fd2_str[16];
    snprintf(fd1_str, sizeof(fd1_str), "%d", fd_cloexec);
    snprintf(fd2_str, sizeof(fd2_str), "%d", fd_keep);

    /* 按 BPF_TEST_VARIANT 选择 child 变体（.out / .linked） */
    const char *variant = getenv("BPF_TEST_VARIANT");
    if (!variant || !*variant) variant = "out";
    char target[128];
    snprintf(target, sizeof(target), "test/test_cloexec_child.%s", variant);

    char *const new_argv[] = { target, fd1_str, fd2_str, NULL };
    /* envp 透传父进程 LD_LIBRARY_PATH（动态变体的 child 需要它定位 ldso/libc.so）。
     * execve 用 envp 整体替换环境，不继承父 environ，故必须显式带上——与真实 shell
     * 行为一致（bash/dash 会把自己 environ 里的 LD_LIBRARY_PATH 透传给子进程）。
     * 动态构造避免数组字面量里出现"中间的 NULL"（见 test_fexecve.c 同名注释）。*/
    char ldpath_var[280];
    const char *lp = getenv("LD_LIBRARY_PATH");
    char *new_envp[3];
    int en = 0;
    if (lp && *lp) {
        snprintf(ldpath_var, sizeof(ldpath_var), "LD_LIBRARY_PATH=%s", lp);
        new_envp[en++] = ldpath_var;
    }
    new_envp[en] = NULL;

    printf("Parent: fd_cloexec=%d, fd_keep=%d. Executing child %s...\n",
           fd_cloexec, fd_keep, target);

    execve(target, new_argv, new_envp);

    // Should not reach here
    printf("Parent: Execve failed: %s\n", strerror(errno));
    return 1;
}
