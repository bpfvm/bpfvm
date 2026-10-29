// 批量新 syscall 冒烟：fsync/fdatasync、uname、sysinfo、ppoll、sendfile、eventfd、
// getrlimit/prlimit（Python resource/os/platform/shutil 模块的后端）。
// host 变体在宿主直接跑，断言只写两侧一致的部分（如 machine 值不强校验）。
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>
#include <sys/eventfd.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#define CHECK(cond, name) do { \
    if(!(cond)) { printf("FAIL: %s (errno=%d)\n", name, errno); return 1; } \
} while(0)

int main(void) {
    int fd, rc;

    /* fsync/fdatasync：写临时文件后同步 */
    fd = open("sysmisc.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0, "open tmp");
    CHECK(write(fd, "hello", 5) == 5, "write tmp");
    CHECK(fsync(fd) == 0, "fsync");
    CHECK(fdatasync(fd) == 0, "fdatasync");
    CHECK(lseek(fd, 0, SEEK_SET) == 0, "lseek back");

    /* sendfile：tmp -> dst，校验内容一致 */
    int dst = open("sysmisc_dst.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(dst >= 0, "open dst");
    rc = (int)sendfile(dst, fd, NULL, 5);
    CHECK(rc == 5, "sendfile 5 bytes");
    char buf[16] = {0};
    CHECK(lseek(dst, 0, SEEK_SET) == 0, "lseek dst");
    CHECK(read(dst, buf, 5) == 5, "read dst");
    CHECK(strcmp(buf, "hello") == 0, "sendfile content");
    /* 带 offset 参数的形态：读入偏移、内核推进后写回 */
    off_t off = 0;
    CHECK(lseek(dst, 0, SEEK_SET) == 0, "lseek dst 2");
    CHECK(sendfile(dst, fd, &off, 5) == 5, "sendfile with offset");
    CHECK(off == 5, "offset advanced");
    close(dst);
    close(fd);
    unlink("sysmisc.tmp");
    unlink("sysmisc_dst.tmp");

    /* uname/sysinfo */
    struct utsname uts;
    CHECK(uname(&uts) == 0, "uname");
    CHECK(uts.sysname[0] != '\0', "uname sysname");
    printf("uname: %s %s %s %s %s\n", uts.sysname, uts.nodename, uts.release, uts.version, uts.machine);
    struct sysinfo si;
    CHECK(sysinfo(&si) == 0, "sysinfo");
    CHECK(si.totalram > 0, "sysinfo totalram");
    printf("sysinfo: procs=%u totalram=%llu MB\n", si.procs, (unsigned long long)(si.totalram / 1024 / 1024));

    /* ppoll：无数据管道读端 + 30ms 超时 -> 返回 0 且耗时不小于 25ms */
    int p[2];
    CHECK(pipe(p) == 0, "pipe");
    struct pollfd pfd = { .fd = p[0], .events = POLLIN, .revents = 0 };
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 30 * 1000 * 1000 };
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    rc = ppoll(&pfd, 1, &ts, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    CHECK(rc == 0, "ppoll timeout");
    uint64_t el = (uint64_t)((int64_t)(t1.tv_sec - t0.tv_sec) * 1000
                           + (int64_t)(t1.tv_nsec - t0.tv_nsec) / 1000000);
    CHECK(el >= 25 && el < 5000, "ppoll timed ~30ms");
    /* ppoll 阻塞路径被管道数据立即唤醒 */
    CHECK(write(p[1], "x", 1) == 1, "pipe write");
    pfd.revents = 0;
    ts.tv_sec = 5;
    ts.tv_nsec = 0;
    rc = ppoll(&pfd, 1, &ts, NULL);
    CHECK(rc == 1 && (pfd.revents & POLLIN), "ppoll ready");
    close(p[0]);
    close(p[1]);

    /* eventfd：计数器语义 */
    int efd = eventfd(0, 0);
    CHECK(efd >= 0, "eventfd");
    uint64_t one = 1;
    CHECK(write(efd, &one, 8) == 8, "eventfd write");
    uint64_t val = 0;
    CHECK(read(efd, &val, 8) == 8, "eventfd read");
    CHECK(val == 1, "eventfd counter");
    close(efd);

    /* getrlimit/prlimit：RLIMIT_NOFILE 查询路径 */
    struct rlimit rl;
    CHECK(getrlimit(RLIMIT_NOFILE, &rl) == 0, "getrlimit");
    CHECK(rl.rlim_cur > 2, "rlimit nofile cur");
    struct rlimit rl2;
    CHECK(prlimit(0, RLIMIT_NOFILE, NULL, &rl2) == 0, "prlimit query");
    CHECK(rl2.rlim_cur == rl.rlim_cur, "prlimit/getrlimit agree");
    printf("rlimit nofile: cur=%llu max=%llu\n",
           (unsigned long long)rl.rlim_cur, (unsigned long long)rl.rlim_max);

    printf("syscall misc ok\n");
    return 0;
}
