/* /proc 测试 - 精简版，逐步验证 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

static ssize_t read_file(const char* path, char* buf, size_t bufsiz) {
    int fd = open(path, O_RDONLY);
    if(fd < 0) return -1;
    ssize_t total = 0;
    while((size_t)total < bufsiz) {
        ssize_t n = read(fd, buf + total, bufsiz - total);
        if(n < 0) { close(fd); return -1; }
        if(n == 0) break;
        total += n;
    }
    close(fd);
    return total;
}

#define CHECK(expr, msg) do { if(!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while(0)

int main(void) {
    char buf[8192];
    ssize_t n;

    /* 逐个测，每个成功后立刻输出到 stderr 并 return 不同值 */
    n = read_file("/proc/cpuinfo", buf, sizeof(buf));
    CHECK(n > 0 && strstr(buf, "processor"), "cpuinfo");
    fprintf(stderr, "1:cpuinfo\n");

    n = read_file("/proc/meminfo", buf, sizeof(buf));
    CHECK(n > 0 && strstr(buf, "MemTotal"), "meminfo");
    fprintf(stderr, "2:meminfo\n");

    n = read_file("/proc/uptime", buf, sizeof(buf));
    CHECK(n > 0 && strchr(buf, '.'), "uptime");
    fprintf(stderr, "3:uptime\n");

    n = read_file("/proc/version", buf, sizeof(buf));
    CHECK(n > 0 && strstr(buf, "Linux"), "version");
    fprintf(stderr, "4:version\n");

    n = read_file("/proc/filesystems", buf, sizeof(buf));
    CHECK(n > 0 && strstr(buf, "proc"), "filesystems");
    fprintf(stderr, "5:filesystems\n");

    n = read_file("/proc/loadavg", buf, sizeof(buf));
    CHECK(n > 0, "loadavg");
    fprintf(stderr, "6:loadavg\n");

    n = read_file("/proc/mounts", buf, sizeof(buf));
    CHECK(n > 0 && strstr(buf, "proc"), "mounts");
    fprintf(stderr, "7:mounts\n");

    /* readlink 测试：/proc/self 是 magic symlink，readlink 返回纯 pid 数字 */
    char linkbuf[256];
    pid_t pid = getpid();
    ssize_t ln = readlink("/proc/self", linkbuf, sizeof(linkbuf));
    linkbuf[ln > 0 ? ln : 0] = '\0';
    char expect[64];
    snprintf(expect, sizeof(expect), "%d", (int)pid);
    CHECK(ln > 0 && strcmp(linkbuf, expect) == 0, "self link");
    fprintf(stderr, "8:self link\n");

    ln = readlink("/proc/self/exe", linkbuf, sizeof(linkbuf));
    CHECK(ln > 0, "exe link");
    fprintf(stderr, "9:exe link\n");

    ln = readlink("/proc/self/cwd", linkbuf, sizeof(linkbuf));
    CHECK(ln > 0, "cwd link");
    fprintf(stderr, "10:cwd link\n");

    /* [pid]/* 测试 */
    n = read_file("/proc/self/comm", buf, sizeof(buf));
    CHECK(n > 0 && strstr(buf, "test_proc"), "comm");
    fprintf(stderr, "11:comm\n");

    n = read_file("/proc/self/cmdline", buf, sizeof(buf));
    CHECK(n > 0 && memmem(buf, n, "test_proc", 9), "cmdline");
    fprintf(stderr, "12:cmdline\n");

    n = read_file("/proc/self/stat", buf, sizeof(buf));
    {
        char pidstr[32];
        snprintf(pidstr, sizeof(pidstr), "%d ", (int)pid);
        CHECK(n > 0 && strstr(buf, pidstr), "stat");
    }
    fprintf(stderr, "13:stat\n");

    n = read_file("/proc/self/status", buf, sizeof(buf));
    CHECK(n > 0 && strstr(buf, "Name:"), "status");
    fprintf(stderr, "14:status\n");

    n = read_file("/proc/self/maps", buf, sizeof(buf));
    CHECK(n >= 0, "maps");
    fprintf(stderr, "15:maps\n");

    /* readdir */
    DIR* d = opendir("/proc");
    CHECK(d != NULL, "opendir");
    int found_self = 0, found_pid = 0;
    struct dirent* e;
    char pidstr[32];
    snprintf(pidstr, sizeof(pidstr), "%d", (int)pid);
    while((e = readdir(d)) != NULL) {
        if(strcmp(e->d_name, "self") == 0) found_self = 1;
        if(strcmp(e->d_name, pidstr) == 0) found_pid = 1;
    }
    closedir(d);
    CHECK(found_self && found_pid, "readdir");
    fprintf(stderr, "16:readdir\n");

    /* stat */
    struct stat st;
    CHECK(stat("/proc/self", &st) == 0 && S_ISDIR(st.st_mode), "stat self");
    fprintf(stderr, "17:stat self\n");
    CHECK(stat("/proc/cpuinfo", &st) == 0 && S_ISREG(st.st_mode), "stat cpuinfo");
    fprintf(stderr, "18:stat cpuinfo\n");

    /* lseek */
    {
        int fd = open("/proc/cpuinfo", O_RDONLY);
        char a[11] = {0}, b[11] = {0};
        CHECK(read(fd, a, 10) == 10, "lseek read1");
        CHECK(lseek(fd, 0, SEEK_SET) == 0, "lseek set");
        CHECK(read(fd, b, 10) == 10, "lseek read2");
        CHECK(strcmp(a, b) == 0, "lseek cmp");
        close(fd);
    }
    fprintf(stderr, "19:lseek\n");

    /* write returns error */
    {
        int fd = open("/proc/cpuinfo", O_WRONLY);
        CHECK(fd < 0, "write should fail");
    }
    fprintf(stderr, "20:write fail\n");

    fprintf(stderr, "ALL PASS\n");
    return 0;
}
