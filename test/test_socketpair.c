// test_socketpair.c — 验证 bpfvm 的 socketpair()。
// AF_UNIX/SOCK_STREAM 全双工对：父子各持一端，双向 send/recv。
// 覆盖：socketpair/send/recv/shutdown。

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>

int main(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("socketpair"); return 1;
    }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }

    if (pid == 0) {
        /* 子持 sv[1]：先收后发。 */
        close(sv[0]);
        char buf[64] = {0};
        ssize_t n = recv(sv[1], buf, sizeof(buf) - 1, 0);
        if (n < 0) { perror("child recv"); _exit(1); }
        if (strcmp(buf, "parent->child") != 0) {
            fprintf(stderr, "FAIL child: got '%s'\n", buf); _exit(1);
        }
        const char *r = "child->parent";
        if (send(sv[1], r, strlen(r), 0) != (ssize_t)strlen(r)) {
            perror("child send"); _exit(1);
        }
        shutdown(sv[1], SHUT_WR);
        close(sv[1]);
        _exit(0);
    }

    /* 父持 sv[0]：先发后收。 */
    const char *m = "parent->child";
    if (send(sv[0], m, strlen(m), 0) != (ssize_t)strlen(m)) {
        perror("parent send"); return 1;
    }
    char buf[64] = {0};
    ssize_t n = recv(sv[0], buf, sizeof(buf) - 1, 0);
    if (n < 0) { perror("parent recv"); return 1; }
    if (strcmp(buf, "child->parent") != 0) {
        fprintf(stderr, "FAIL parent: got '%s'\n", buf); return 1;
    }

    int status = 0;
    waitpid(pid, &status, 0);
    close(sv[0]);
    close(sv[1]);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL: child status=%d\n", status);
        return 1;
    }
    printf("test_socketpair OK\n");
    return 0;
}
