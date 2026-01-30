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

    char *const new_argv[] = { "test/test_cloexec_child.out", fd1_str, fd2_str, NULL };
    char *const new_envp[] = { NULL };

    printf("Parent: fd_cloexec=%d, fd_keep=%d. Executing child...\n", fd_cloexec, fd_keep);

    execve("test/test_cloexec_child.out", new_argv, new_envp);

    // Should not reach here
    printf("Parent: Execve failed: %s\n", strerror(errno));
    return 1;
}
