/* /proc/[pid] 魔法链接测试：
 * - /proc/[pid]/fd：目录列举（fd 号 + d_type=LNK）、readlink（普通文件路径 /
 *   pipe:[ino]）、经 /proc/self/fd/N 与 /dev/fd/N 重开（open 语义：新 description 独立
 *   offset）、stat/lstat、O_NOFOLLOW=ELOOP、写模式重开（不走 procfs 的 EROFS）。
 * - /proc/[pid]/exe 生命周期：进程退出成僵尸后链接解析一律 ENOENT（Linux：mm 释放，
 *   exe fd 在 run() 退出时关闭置 -1）；写模式也是 ENOENT 而非 ETXTBSY（链接解析先于
 *   writecount）；存活期间 open 成功；僵尸的 lstat(NOFOLLOW) 仍是 S_IFLNK。
 * Linux 与 Android termux 行为一致，host 原生可跑。 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/wait.h>

#define CHECK(expr, msg) do { if(!(expr)) { fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno); return 1; } } while(0)

static const char* TMPFILE = "/tmp/bpfvm_test_proc_fd.data";

static ssize_t readlink_fmt(const char* fmt, int fd, char* buf, size_t bufsiz) {
    char p[64];
    snprintf(p, sizeof(p), fmt, fd);
    return readlink(p, buf, bufsiz);
}

/* 僵尸进程的 /proc/[pid]/exe：child 存活期间 open 成功，退出成僵尸后链接解析
 * 一律 ENOENT（而非 EBADF/ETXTBSY），lstat(NOFOLLOW) 仍是 S_IFLNK。 */
static int test_zombie_exe(void) {
    pid_t pid = fork();
    CHECK(pid >= 0, "fork zombie child");
    if(pid == 0) {
        usleep(100000);
        _exit(0);
    }
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/exe", (int)pid);

    int fd = open(p, O_RDONLY);
    CHECK(fd >= 0, "open exe of live child");
    close(fd);

    /* 轮询等 child 变僵尸：open 失败且 errno==ENOENT（而非 EBADF/错误内容） */
    int i, got_enoent = 0;
    for(i = 0; i < 100; i++) {
        errno = 0;
        fd = open(p, O_RDONLY);
        if(fd < 0) {
            got_enoent = (errno == ENOENT);
            break;
        }
        close(fd);
        usleep(100000);
    }
    CHECK(i < 100, "child became zombie in time");
    CHECK(got_enoent, "zombie exe open -> ENOENT");

    /* 僵尸的目录项仍在：lstat 报符号链接 */
    struct stat st;
    CHECK(lstat(p, &st) == 0 && S_ISLNK(st.st_mode), "zombie exe lstat is LNK");

    /* exe_file 已释放：一律 ENOENT，写模式也不例外（链接解析先于 ETXTBSY）。 */
    errno = 0;
    char buf[256];
    CHECK(readlink(p, buf, sizeof(buf)) < 0 && errno == ENOENT, "zombie exe readlink ENOENT");
    errno = 0;
    CHECK(stat(p, &st) < 0 && errno == ENOENT, "zombie exe stat ENOENT");
    errno = 0;
    CHECK(open(p, O_WRONLY) < 0 && errno == ENOENT, "zombie exe O_WRONLY ENOENT (not ETXTBSY)");

    CHECK(waitpid(pid, NULL, 0) == pid, "waitpid zombie child");
    return 0;
}

int main(void) {
    char buf[512];
    char fdpath[64];

    /* 准备一个已知内容的文件（O_RDWR 打开，后面测写模式重开） */
    int fd = open(TMPFILE, O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0, "open tmpfile");
    CHECK(write(fd, "hello proc fd", 13) == 13, "write tmpfile");
    CHECK(lseek(fd, 0, SEEK_SET) == 0, "rewind tmpfile");

    /* readlink：普通文件 fd 的链接 target 即打开时的路径 */
    ssize_t n = readlink_fmt("/proc/self/fd/%d", fd, buf, sizeof(buf));
    CHECK(n > 0, "readlink /proc/self/fd/N");
    buf[n > 0 ? n : 0] = '\0';
    CHECK(strcmp(buf, TMPFILE) == 0, "fd link target is path");

    /* opendir + readdir：条目名是 fd 号、d_type 是 LNK（数字 pid 路径与 self 等价） */
    char pidfd[64];
    snprintf(pidfd, sizeof(pidfd), "/proc/%d/fd", (int)getpid());
    DIR* d = opendir(pidfd);
    CHECK(d != NULL, "opendir /proc/<pid>/fd");
    char want[16];
    snprintf(want, sizeof(want), "%d", fd);
    int found = 0, all_link = 1;
    struct dirent* e;
    while((e = readdir(d)) != NULL) {
        if(strcmp(e->d_name, want) == 0) {
            found = 1;
            if(e->d_type != DT_LNK) all_link = 0;
        }
    }
    closedir(d);
    CHECK(found, "readdir finds fd entry");
    CHECK(all_link, "fd entries are symlinks");

    /* 经 /proc/self/fd/N 重开：读到相同内容（新 description 从 offset 0 起） */
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
    int fd2 = open(fdpath, O_RDONLY);
    CHECK(fd2 >= 0, "reopen via /proc/self/fd/N");
    memset(buf, 0, sizeof(buf));
    ssize_t m = read(fd2, buf, sizeof(buf) - 1);
    CHECK(m == 13 && strcmp(buf, "hello proc fd") == 0, "reopened fd reads from start");

    /* 重开的 fd 与原 fd 独立 seek：推进 fd2 不影响 fd */
    CHECK(lseek(fd2, 0, SEEK_END) >= 13, "seek reopened fd");
    char c = 0;
    CHECK(lseek(fd, 0, SEEK_SET) == 0 && read(fd, &c, 1) == 1 && c == 'h',
          "orig fd offset independent");

    /* stat（follow）= 目标文件属性；lstat（nofollow）= 符号链接 */
    struct stat st;
    CHECK(stat(fdpath, &st) == 0 && S_ISREG(st.st_mode), "stat fd link is reg");
    CHECK((st.st_mode & 0777) == 0644, "stat fd link mode");
    CHECK(lstat(fdpath, &st) == 0 && S_ISLNK(st.st_mode), "lstat fd link is lnk");

    /* O_NOFOLLOW：末段是 magic symlink -> ELOOP */
    errno = 0;
    CHECK(open(fdpath, O_RDONLY | O_NOFOLLOW) < 0 && errno == ELOOP, "O_NOFOLLOW ELOOP");

    /* 写模式重开 /proc/self/fd/N：不走 procfs 只读 EROFS，作用到目标文件 */
    int fdw = open(fdpath, O_WRONLY | O_TRUNC);
    CHECK(fdw >= 0, "reopen O_WRONLY|O_TRUNC");
    CHECK(write(fdw, "HELLO", 5) == 5, "write via reopened fd");
    CHECK(fstat(fd, &st) == 0 && st.st_size == 5, "O_TRUNC reached target file");
    close(fdw);

    /* /dev/fd/N 逃逸：经 /dev/fd（symlink -> /proc/self/fd）同样可重开 */
    snprintf(fdpath, sizeof(fdpath), "/dev/fd/%d", fd);
    int fd3 = open(fdpath, O_RDONLY);
    CHECK(fd3 >= 0, "open /dev/fd/N");
    memset(buf, 0, sizeof(buf));
    CHECK(read(fd3, buf, sizeof(buf) - 1) == 5 && strcmp(buf, "HELLO") == 0, "read via /dev/fd/N");
    close(fd3);

    /* pipe fd：readlink 报匿名对象 pipe:[ino]；fstat follow 报 FIFO */
    int p[2];
    CHECK(pipe(p) == 0, "pipe");
    n = readlink_fmt("/proc/self/fd/%d", p[0], buf, sizeof(buf));
    buf[n > 0 ? n : 0] = '\0';
    CHECK(n > 0 && strncmp(buf, "pipe:[", 6) == 0, "pipe link target");
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", p[0]);
    CHECK(stat(fdpath, &st) == 0 && S_ISFIFO(st.st_mode), "stat pipe fd link is fifo");
    /* 经 /proc/self/fd/N 重开 pipe 读端：与原 pipe 连通（写另一端可读到） */
    int pr = open(fdpath, O_RDONLY);
    CHECK(pr >= 0, "reopen pipe read end");
    CHECK(write(p[1], "x", 1) == 1, "write pipe end");
    char pc = 0;
    CHECK(read(pr, &pc, 1) == 1 && pc == 'x', "reopened pipe connected");
    close(pr);
    close(p[0]);
    close(p[1]);

    /* 匿名 fd 的展示：socket -> socket:[ino] + fstat SOCK；epoll -> anon_inode:[eventpoll]；
     * signalfd -> anon_inode:[signalfd]（老内核报 signalfd:[ino]，两种都认）+ fstat 无
     * 类型位（mode 仅权限 0600，与 Linux anon_inode 文件一致，不因 pipe 模拟误报 FIFO）。 */
    int sk = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(sk >= 0, "socket");
    n = readlink_fmt("/proc/self/fd/%d", sk, buf, sizeof(buf));
    buf[n > 0 ? n : 0] = '\0';
    CHECK(n > 0 && strncmp(buf, "socket:[", 8) == 0, "socket link target");
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", sk);
    CHECK(stat(fdpath, &st) == 0 && S_ISSOCK(st.st_mode), "stat socket fd link is sock");
    close(sk);

    int ep = epoll_create1(0);
    CHECK(ep >= 0, "epoll_create1");
    n = readlink_fmt("/proc/self/fd/%d", ep, buf, sizeof(buf));
    buf[n > 0 ? n : 0] = '\0';
    CHECK(n > 0 && strcmp(buf, "anon_inode:[eventpoll]") == 0, "epoll link target");
    close(ep);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    int sfd = signalfd(-1, &set, 0);
    CHECK(sfd >= 0, "signalfd");
    n = readlink_fmt("/proc/self/fd/%d", sfd, buf, sizeof(buf));
    buf[n > 0 ? n : 0] = '\0';
    CHECK(n > 0 && (strcmp(buf, "anon_inode:[signalfd]") == 0 ||
                    strncmp(buf, "signalfd:[", 10) == 0), "signalfd link target");
    CHECK(fstat(sfd, &st) == 0 && (st.st_mode & S_IFMT) == 0 && (st.st_mode & 0777) == 0600,
          "signalfd fstat anon-inode shape (no type bits)");
    /* anon_inode fd 不可经 /proc/self/fd 重开：Linux 报 EACCES */
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", sfd);
    errno = 0;
    CHECK(open(fdpath, O_RDONLY) < 0 && errno == EACCES, "signalfd reopen EACCES");
    close(sfd);

    /* 不存在的 fd 号 -> ENOENT */
    errno = 0;
    CHECK(open("/proc/self/fd/9999", O_RDONLY) < 0 && errno == ENOENT, "missing fd ENOENT");

    close(fd);
    close(fd2);
    unlink(TMPFILE);

    int zrc = test_zombie_exe();
    if(zrc) return zrc;
    fprintf(stderr, "ALL PASS\n");
    return 0;
}
