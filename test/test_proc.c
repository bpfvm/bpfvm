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

    /* /proc/mounts 是 magic symlink → self/mounts，故 /proc/self/mounts 也应可读。 */
    n = read_file("/proc/self/mounts", buf, sizeof(buf));
    CHECK(n > 0 && strstr(buf, "proc"), "self mounts");
    fprintf(stderr, "7a:self mounts\n");

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

    /* readlink 穿透 /proc 到 host 符号链接：root→/，再读 /lib（host 上常是 → usr/lib 的链接）。
       无 chroot 时 /proc/self/root/lib 即 host /lib，readlink 应返回其 target。 */
    ln = readlink("/proc/self/root/lib", linkbuf, sizeof(linkbuf));
    linkbuf[ln > 0 ? ln : 0] = '\0';
    CHECK(ln > 0, "root/lib readlink escapes proc");
    fprintf(stderr, "10a:root/lib readlink\n");

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

    /* lstat：/proc/self 是 magic symlink，lstat（不 follow）应报符号链接；
       stat（follow）应解析为目录。与 Linux 内核行为一致。 */
    CHECK(lstat("/proc/self", &st) == 0 && S_ISLNK(st.st_mode), "lstat self is link");
    fprintf(stderr, "18a:lstat self\n");
    CHECK(lstat("/proc/thread-self", &st) == 0 && S_ISLNK(st.st_mode), "lstat thread-self");
    fprintf(stderr, "18b:lstat thread-self\n");
    CHECK(lstat("/proc/mounts", &st) == 0 && S_ISLNK(st.st_mode), "lstat mounts");
    fprintf(stderr, "18c:lstat mounts\n");
    /* POSIX 尾斜杠语义：路径以 '/' 结尾时断言"这是目录"，lstat 也必须 follow。
       与 Linux 内核 path_lookupat 一致（尾斜杠强制 LOOKUP_FOLLOW）。 */
    CHECK(lstat("/proc/self/", &st) == 0 && S_ISDIR(st.st_mode), "lstat self/ follows (trailing slash)");
    fprintf(stderr, "18c2:lstat self/ trailing slash\n");

    /* follow-stat 真符号链接：stat（follow）解析为目标类型（exe→REG，cwd/root→DIR），
       lstat（不 follow）报符号链接。与 Linux 内核一致。 */
    CHECK(stat("/proc/self/exe", &st) == 0 && S_ISREG(st.st_mode), "stat exe is reg");
    fprintf(stderr, "18d:stat exe\n");
    CHECK(lstat("/proc/self/exe", &st) == 0 && S_ISLNK(st.st_mode), "lstat exe is link");
    fprintf(stderr, "18e:lstat exe\n");
    /* procfs 下所有节点（含符号链接）st_size 恒为 0——这是 procfs 的既定行为，
       与普通 fs 上"符号链接 st_size = target 串长"的惯例不同。与真实 Linux 一致。 */
    CHECK(lstat("/proc/self/exe", &st) == 0 && st.st_size == 0, "lstat exe size 0 (procfs)");
    fprintf(stderr, "18e2:lstat exe size 0\n");
    CHECK(lstat("/proc/self/cwd", &st) == 0 && st.st_size == 0, "lstat cwd size 0 (procfs)");
    fprintf(stderr, "18e3:lstat cwd size 0\n");
    CHECK(lstat("/proc/self/root", &st) == 0 && st.st_size == 0, "lstat root size 0 (procfs)");
    fprintf(stderr, "18e4:lstat root size 0\n");
    /* magic symlink 也应 size=0 */
    CHECK(lstat("/proc/self", &st) == 0 && st.st_size == 0, "lstat self size 0 (procfs)");
    fprintf(stderr, "18e5:lstat self size 0\n");
    /* 普通文件同样 size=0（procfs 文件无固定大小） */
    CHECK(stat("/proc/version", &st) == 0 && st.st_size == 0, "stat version size 0 (procfs)");
    fprintf(stderr, "18e6:stat version size 0\n");
    CHECK(stat("/proc/self/cwd", &st) == 0 && S_ISDIR(st.st_mode), "stat cwd is dir");
    fprintf(stderr, "18f:stat cwd\n");
    CHECK(stat("/proc/self/root", &st) == 0 && S_ISDIR(st.st_mode), "stat root is dir");
    fprintf(stderr, "18g:stat root\n");
    /* /proc/self/root 跳出 /proc 后接续 host 路径段：root→/，再走 /bin，应 follow 到目录 */
    CHECK(stat("/proc/self/root/bin", &st) == 0 && S_ISDIR(st.st_mode), "stat root/bin escapes proc");
    fprintf(stderr, "18h:stat root/bin\n");
    /* 尾斜杠：/proc/1/ 与 /proc/1 等价；/proc/self/ 是符号链接+尾斜杠，应 follow 到 [tgid] 目录 */
    CHECK(stat("/proc/self/", &st) == 0 && S_ISDIR(st.st_mode), "stat self/ trailing slash");
    fprintf(stderr, "18i:stat self/\n");

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
