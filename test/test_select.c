// test_select.c — 验证 bpfvm 的 select/pselect6 实现（OpenSSL s_client 依赖）。
//
// 覆盖：
//   1. pipe + select 读端就绪：写一字节后 select 应返回 1 且 fd 在 readfds 里。
//   2. select 超时：空 pipe 上 select(tv=100ms) 应返回 0（无就绪），耗时应≥100ms。
//   3. select 写端就绪：pipe 写端几乎总是就绪（缓冲未满），select 应返回≥1。
//   4. select NULL timeout（永久阻塞）的 0-fd 集合不测（会挂死）；改测 EINVAL 路径可选。
//
// OpenSSL 的 BIO_socket_wait 直接调 select()，故本测试守护 s_client/s_server 的可用性。
// 对 host（glibc）同样成立，故 host 对照也通过。

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <time.h>

static int fails = 0;

/* 用 clock_gettime 测量耗时，避免依赖 host 的 gettimeofday 精度 */
static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(void) {
    int pfd[2];
    if (pipe(pfd) < 0) { printf("FAIL: pipe: %s\n", strerror(errno)); return 1; }

    /* 1. 读端就绪 */
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(pfd[0], &rfds);
        /* 一开始空 pipe：select(0 超时) 应返回 0 */
        struct timeval tv = {0, 0};
        int rc = select(pfd[0] + 1, &rfds, NULL, NULL, &tv);
        if (rc != 0) {
            printf("FAIL select empty pipe: 期望 0，得到 %d (%s)\n", rc, strerror(errno));
            fails++;
        } else {
            /* 写一字节后再 select，应返回 1 且 rfds 仍 set */
            if (write(pfd[1], "x", 1) != 1) {
                printf("FAIL write: %s\n", strerror(errno)); fails++;
            } else {
                FD_ZERO(&rfds);
                FD_SET(pfd[0], &rfds);
                tv.tv_sec = 0; tv.tv_usec = 100000;  /* 100ms */
                rc = select(pfd[0] + 1, &rfds, NULL, NULL, &tv);
                if (rc != 1 || !FD_ISSET(pfd[0], &rfds)) {
                    printf("FAIL select ready: 期望 1 & set，得到 %d\n", rc); fails++;
                } else {
                    printf("PASS select read-ready\n");
                }
                /* 排空，避免影响后续 */
                char buf[8]; read(pfd[0], buf, 1);
            }
        }
    }

    /* 2. 超时 */
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(pfd[0], &rfds);  /* pipe 现在空 */
        struct timeval tv = {0, 100000};  /* 100ms */
        double t0 = now_s();
        int rc = select(pfd[0] + 1, &rfds, NULL, NULL, &tv);
        double dt = now_s() - t0;
        if (rc != 0) {
            printf("FAIL select timeout rc: 期望 0，得到 %d\n", rc); fails++;
        } else if (dt < 0.09) {
            printf("FAIL select timeout: 仅 %.3fs，疑似没等\n", dt); fails++;
        } else {
            printf("PASS select timeout (%.3fs)\n", dt);
        }
    }

    /* 3. 写端就绪 */
    {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(pfd[1], &wfds);
        struct timeval tv = {0, 0};
        int rc = select(pfd[1] + 1, NULL, &wfds, NULL, &tv);
        if (rc < 1 || !FD_ISSET(pfd[1], &wfds)) {
            printf("FAIL select write-ready: 期望≥1 & set，得到 %d\n", rc); fails++;
        } else {
            printf("PASS select write-ready\n");
        }
    }

    close(pfd[0]);
    close(pfd[1]);

    if (fails == 0) { printf("=== ALL PASS ===\n"); return 0; }
    printf("=== %d FAIL(s) ===\n", fails);
    return 1;
}
