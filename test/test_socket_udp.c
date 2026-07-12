// test_socket_udp.c — 验证 bpfvm 的 BSD socket API（UDP）。
// 两个 UDP socket bind 到 127.0.0.1:0，用 sendto/recvfrom 互通。
// 覆盖：socket(DGRAM)/bind/getsockname/sendto(带地址)/recvfrom(带地址)。
// 用父子分工避免单一 socket 自收自发（UDP 无连接，需显式对端地址）。

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
    int a = socket(AF_INET, SOCK_DGRAM, 0);
    if (a < 0) { perror("socket a"); return 1; }
    int b = socket(AF_INET, SOCK_DGRAM, 0);
    if (b < 0) { perror("socket b"); return 1; }

    struct sockaddr_in sa = {0}, sb = {0};
    sa.sin_family = sb.sin_family = AF_INET;
    sa.sin_addr.s_addr = sb.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = sb.sin_port = 0;

    if (bind(a, (struct sockaddr*)&sa, sizeof(sa)) < 0) { perror("bind a"); return 1; }
    if (bind(b, (struct sockaddr*)&sb, sizeof(sb)) < 0) { perror("bind b"); return 1; }

    socklen_t la = sizeof(sa), lb = sizeof(sb);
    if (getsockname(a, (struct sockaddr*)&sa, &la) < 0) { perror("getsockname a"); return 1; }
    if (getsockname(b, (struct sockaddr*)&sb, &lb) < 0) { perror("getsockname b"); return 1; }
    /* 两端口必须不同（否则 bind 会因 SO_REUSEADDR 未设而失败，这里两 socket 都用 port 0） */
    if (ntohs(sa.sin_port) == ntohs(sb.sin_port)) {
        fprintf(stderr, "FAIL: kernel assigned same port %d\n", ntohs(sa.sin_port));
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }

    if (pid == 0) {
        /* 子：持 b，收一条，回一条。 */
        close(a);
        char buf[64] = {0};
        struct sockaddr_in from = {0};
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(b, buf, sizeof(buf) - 1, 0, (struct sockaddr*)&from, &fromlen);
        if (n < 0) { perror("child recvfrom"); _exit(1); }
        if (strcmp(buf, "ping") != 0) {
            fprintf(stderr, "FAIL child: got '%s'\n", buf); _exit(1);
        }
        const char *reply = "pong";
        if (sendto(b, reply, strlen(reply), 0, (struct sockaddr*)&from, fromlen)
            != (ssize_t)strlen(reply)) {
            perror("child sendto"); _exit(1);
        }
        close(b);
        _exit(0);
    }

    /* 父：持 a，发 ping 到 b，收 pong。 */
    const char *msg = "ping";
    if (sendto(a, msg, strlen(msg), 0, (struct sockaddr*)&sb, sizeof(sb))
        != (ssize_t)strlen(msg)) {
        perror("sendto"); return 1;
    }

    char buf[64] = {0};
    struct sockaddr_in from = {0};
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(a, buf, sizeof(buf) - 1, 0, (struct sockaddr*)&from, &fromlen);
    if (n < 0) { perror("recvfrom"); return 1; }
    if (strcmp(buf, "pong") != 0) {
        fprintf(stderr, "FAIL parent: got '%s'\n", buf); return 1;
    }
    /* from 应是 b 的地址 */
    if (from.sin_port != sb.sin_port) {
        fprintf(stderr, "FAIL parent: source port mismatch\n");
        return 1;
    }

    int status = 0;
    waitpid(pid, &status, 0);
    close(a);
    close(b);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL: child status=%d\n", status);
        return 1;
    }
    printf("test_socket_udp OK\n");
    return 0;
}
