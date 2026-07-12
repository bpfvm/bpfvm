// test_socket_tcp.c — 验证 bpfvm 的 BSD socket API（TCP）。
// 场景：父进程 socket→bind(127.0.0.1:0)→listen→accept4；
//       子进程 connect→send→recv（echo 回环）。
// 覆盖：socket/bind/listen/accept4/connect/sendto(=send)/recvfrom(=recv)/
//       setsockopt(SO_REUSEADDR)/getsockname（取端口）/shutdown。
// 全部断言通过返回 0。

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>

int main(void)
{
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }

    int on = 1;
    if (setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        perror("setsockopt SO_REUSEADDR"); return 1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;                 /* 让内核选端口，getsockname 取回 */
    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }

    socklen_t addrlen = sizeof(addr);
    if (getsockname(srv, (struct sockaddr*)&addr, &addrlen) < 0) {
        perror("getsockname"); return 1;
    }
    int port = ntohs(addr.sin_port);
    if (port == 0) {
        fprintf(stderr, "FAIL: getsockname returned port 0\n");
        return 1;
    }

    if (listen(srv, 1) < 0) { perror("listen"); return 1; }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }

    if (pid == 0) {
        /* 子：客户端。关掉监听 fd，连服务器，发后收 echo。 */
        close(srv);
        int c = socket(AF_INET, SOCK_STREAM, 0);
        if (c < 0) { perror("child socket"); _exit(1); }

        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons(port);
        if (connect(c, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
            perror("connect"); _exit(1);
        }

        const char *msg = "hello-tcp";
        if (send(c, msg, strlen(msg), 0) != (ssize_t)strlen(msg)) {
            perror("send"); _exit(1);
        }
        /* 给对端机会回写后再 shutdown 写端，触发服务端 recv 返回 0 */
        shutdown(c, SHUT_WR);

        char buf[64] = {0};
        ssize_t n = recv(c, buf, sizeof(buf) - 1, 0);
        if (n < 0) { perror("child recv"); _exit(1); }
        if (strcmp(buf, "HELLO-TCP") != 0) {
            fprintf(stderr, "FAIL child echo: got '%s'\n", buf);
            _exit(1);
        }
        close(c);
        _exit(0);
    }

    /* 父：接受连接，收到后转大写回写。 */
    int cli = accept4(srv, NULL, NULL, 0);
    if (cli < 0) { perror("accept4"); return 1; }

    char buf[64] = {0};
    ssize_t n = recv(cli, buf, sizeof(buf) - 1, 0);
    if (n < 0) { perror("server recv"); return 1; }
    if (n != 9 || strcmp(buf, "hello-tcp") != 0) {
        fprintf(stderr, "FAIL server recv: got '%s' (%zd bytes)\n", buf, n);
        return 1;
    }
    for (ssize_t i = 0; i < n; ++i) {
        if (buf[i] >= 'a' && buf[i] <= 'z') buf[i] -= 32;
    }
    if (send(cli, buf, strlen(buf), 0) != (ssize_t)strlen(buf)) {
        perror("server send"); return 1;
    }

    int status = 0;
    waitpid(pid, &status, 0);
    close(cli);
    close(srv);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL: child status=%d\n", status);
        return 1;
    }
    printf("test_socket_tcp OK\n");
    return 0;
}
