// test_socket_fdpass.c — 验证 bpfvm 的 sendmsg/recvmsg。
// 用例 1：scatter-gather 数据收发（多个 iov），无 cmsg。覆盖 DNS 的 recvmsg 收 UDP 响应路径。
// 用例 2：SCM_RIGHTS fd 传递——父把 pipe 写端经 AF_UNIX 传给子，子往收到的 fd 写、
//         父从 pipe 读端读，验证 fd 跨进程传递 + 数据可达。这是 VM 边界 fd 翻译的核心风险点。
// 覆盖：sendmsg/recvmsg（iov + SCM_RIGHTS）。

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>

/* 用例 1：sendmsg/recvmsg 的 scatter-gather 数据路径（iov 数组，无 cmsg）。 */
static int test_scatter_gather(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("socketpair"); return 1;
    }

    /* 发送端：2 个 iov，拼成 "hello-" + "world"。 */
    struct iovec sv_iov[2] = {
        { .iov_base = (char *)"hello-", .iov_len = 6 },
        { .iov_base = (char *)"world",  .iov_len = 5 },
    };
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = sv_iov;
    msg.msg_iovlen = 2;
    if (sendmsg(sv[0], &msg, 0) != 11) {
        perror("sendmsg"); return 1;
    }

    /* 接收端：用 2 个 iov 接，分桶验证 scatter-gather 正确性。 */
    char a[7] = {0}, b[6] = {0};
    struct iovec rv_iov[2] = {
        { .iov_base = a, .iov_len = sizeof(a) - 1 },
        { .iov_base = b, .iov_len = sizeof(b) - 1 },
    };
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = rv_iov;
    msg.msg_iovlen = 2;
    ssize_t n = recvmsg(sv[1], &msg, 0);
    if (n != 11) {
        fprintf(stderr, "FAIL recvmsg: got %zd\n", n); return 1;
    }
    if (strcmp(a, "hello-") != 0 || strcmp(b, "world") != 0) {
        fprintf(stderr, "FAIL scatter: a='%s' b='%s'\n", a, b); return 1;
    }
    close(sv[0]);
    close(sv[1]);
    return 0;
}

/* 用例 2：SCM_RIGHTS —— 父把 pipe 写端 pfd[1] 传给子，子写、父从 pfd[0] 读。 */
static int test_fd_pass(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("socketpair"); return 1;
    }
    int pfd[2];
    if (pipe(pfd) < 0) { perror("pipe"); return 1; }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }

    if (pid == 0) {
        /* 子：收 fd，往收到的 fd 写。 */
        close(sv[0]);
        close(pfd[0]);
        close(pfd[1]);

        struct msghdr msg;
        memset(&msg, 0, sizeof msg);
        char buf[64] = {0};
        struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        union { struct cmsghdr hdr; char buf[CMSG_SPACE(sizeof(int))]; } cmsg_buf;
        memset(&cmsg_buf, 0, sizeof cmsg_buf);
        msg.msg_control = cmsg_buf.buf;
        msg.msg_controllen = sizeof cmsg_buf.buf;

        ssize_t n = recvmsg(sv[1], &msg, 0);
        if (n < 0) { perror("child recvmsg"); _exit(1); }

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
            fprintf(stderr, "FAIL child: no SCM_RIGHTS\n"); _exit(1);
        }
        int passed_fd = -1;
        memcpy(&passed_fd, CMSG_DATA(cmsg), sizeof(int));
        if (passed_fd < 0) {
            fprintf(stderr, "FAIL child: bad passed fd %d\n", passed_fd); _exit(1);
        }
        const char *m = "passed!";
        if (write(passed_fd, m, strlen(m)) != (ssize_t)strlen(m)) {
            perror("child write"); _exit(1);
        }
        close(passed_fd);
        close(sv[1]);
        _exit(0);
    }

    /* 父：传 pfd[1]（pipe 写端）给子，从 pfd[0] 读验证。 */
    close(sv[1]);
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    const char *payload = "x";
    struct iovec iov = { (void *)payload, 1 };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    union { struct cmsghdr hdr; char buf[CMSG_SPACE(sizeof(int))]; } cmsg_buf;
    memset(&cmsg_buf, 0, sizeof cmsg_buf);
    msg.msg_control = cmsg_buf.buf;
    msg.msg_controllen = sizeof cmsg_buf.buf;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &pfd[1], sizeof(int));

    if (sendmsg(sv[0], &msg, 0) < 0) {
        perror("parent sendmsg"); return 1;
    }
    close(pfd[1]);   /* 父关掉写端，让子写后 EOF */

    char rbuf[64] = {0};
    ssize_t n = read(pfd[0], rbuf, sizeof(rbuf) - 1);
    if (n < 0) { perror("parent read"); return 1; }
    if (strcmp(rbuf, "passed!") != 0) {
        fprintf(stderr, "FAIL parent: got '%s'\n", rbuf); return 1;
    }

    int status = 0;
    waitpid(pid, &status, 0);
    close(sv[0]);
    close(pfd[0]);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL: child status=%d\n", status);
        return 1;
    }
    return 0;
}

int main(void)
{
    int rc;
    if ((rc = test_scatter_gather()) != 0) return rc;
    if ((rc = test_fd_pass()) != 0) return rc;
    printf("test_socket_fdpass OK\n");
    return 0;
}
