// test_epoll.c — 验证 bpfvm 的 epoll API。
// 重点：epoll_event.data 是 opaque（用户存什么 wait 就返回什么）——用自定义 token
// 校验 data 透传，这是 guest/host epoll_event 布局差异（16B vs 12B）的核心风险点。
// 覆盖：epoll_create1/epoll_ctl(ADD/MOD/DEL)/epoll_wait、data.u64 透传、
//       多 fd（pipe + socketpair）混合监听、EPOLLOUT 就绪。

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>

int main(void)
{
    int ep = epoll_create1(0);
    if (ep < 0) { perror("epoll_create1"); return 1; }

    /* 两个被监听 fd：一个 pipe（读端），一个 socketpair（一端）。 */
    int pfd[2];
    if (pipe2(pfd, 0) < 0) { perror("pipe2"); return 1; }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); return 1; }

    /* —— 用例 1：ADD 两个 fd，data.u64 存自定义 token —— */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u64 = 0xAAAA1111BBBB2222ULL;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, pfd[0], &ev) < 0) {
        perror("epoll_ctl ADD pipe"); return 1;
    }
    ev.events = EPOLLOUT;                       /* 可写必立刻就绪 */
    ev.data.u64 = 0xCCCC3333DDDD4444ULL;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, sv[0], &ev) < 0) {
        perror("epoll_ctl ADD sv"); return 1;
    }

    /* —— 用例 2：两 fd 都应就绪（pipe 无数据 → 仅 EPOLLOUT 的 sv 就绪；先写 pipe 让它也 IN）—— */
    char c = 'x';
    if (write(pfd[1], &c, 1) != 1) { perror("write pipe"); return 1; }

    struct epoll_event out[4];
    int n = epoll_wait(ep, out, 4, 1000);
    if (n < 0) { perror("epoll_wait"); return 1; }
    if (n != 2) {
        fprintf(stderr, "FAIL: epoll_wait returned %d events, expected 2\n", n);
        return 1;
    }
    /* 校验两个 token 都返回了（顺序无关）。这是验证 16B↔12B 布局拷贝正确的关键。 */
    int got1 = 0, got2 = 0;
    for (int i = 0; i < n; ++i) {
        if (out[i].data.u64 == 0xAAAA1111BBBB2222ULL) got1 = 1;
        if (out[i].data.u64 == 0xCCCC3333DDDD4444ULL) got2 = 1;
    }
    if (!got1 || !got2) {
        fprintf(stderr, "FAIL: data token lost (got1=%d got2=%d)\n", got1, got2);
        return 1;
    }

    /* —— 用例 3：EPOLL_CTL_DEL 移除 pipe，再 wait 只剩 sv —— */
    if (epoll_ctl(ep, EPOLL_CTL_DEL, pfd[0], &ev) < 0) {
        perror("epoll_ctl DEL pipe"); return 1;
    }
    n = epoll_wait(ep, out, 4, 100);
    if (n != 1 || out[0].data.u64 != 0xCCCC3333DDDD4444ULL) {
        fprintf(stderr, "FAIL: after DEL, n=%d token=0x%llx\n",
                n, (unsigned long long)out[0].data.u64);
        return 1;
    }

    /* —— 用例 4：MOD 把 sv 改成 EPOLLIN，未写入 → 不就绪 → wait 超时返回 0 —— */
    ev.events = EPOLLIN;
    ev.data.u64 = 0xEEEE5555FFFF6666ULL;
    if (epoll_ctl(ep, EPOLL_CTL_MOD, sv[0], &ev) < 0) {
        perror("epoll_ctl MOD sv"); return 1;
    }
    n = epoll_wait(ep, out, 4, 100);   /* 100ms，应超时 */
    if (n != 0) {
        fprintf(stderr, "FAIL: after MOD to EPOLLIN, expected timeout(0), got %d\n", n);
        return 1;
    }

    /* —— 用例 5：往 sv[1] 写入 → sv[0] EPOLLIN 就绪，且 token 是 MOD 后的新值 —— */
    if (write(sv[1], &c, 1) != 1) { perror("write sv"); return 1; }
    n = epoll_wait(ep, out, 4, 1000);
    if (n != 1 || out[0].data.u64 != 0xEEEE5555FFFF6666ULL
        || !(out[0].events & EPOLLIN)) {
        fprintf(stderr, "FAIL: after write, n=%d token=0x%llx events=0x%x\n",
                n, (unsigned long long)out[0].data.u64, out[0].events);
        return 1;
    }

    close(ep);
    close(pfd[0]); close(pfd[1]);
    close(sv[0]); close(sv[1]);
    printf("test_epoll OK\n");
    return 0;
}
