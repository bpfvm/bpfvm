/* /dev 合成设备层回归测试。
 *
 * 覆盖 bpfvm 对 /dev 路径下各项操作的拦截与合成：
 *   - 标准设备 I/O：/dev/null(写丢弃+读EOF)、/dev/zero(读全零)、/dev/urandom(读非全零)、
 *     /dev/full(写->ENOSPC)。
 *   - stat 一致性：stat("/dev/null") 成功且 S_ISCHR；fstat(opened fd) 同为字符设备。
 *   - std 符号链接：/dev/stdin 等指向 /proc/self/fd/N。procfs 已实现 [pid]/fd 目录，
 *     open follow 经 fd 链接重开目标 fd（与 host 一致）；readlink/lstat(NOFOLLOW) 正常。
 *   - readlink：/dev/stdin -> /proc/self/fd/0；/dev/null(非链接) -> EINVAL。
 *   - 目录列举：open("/dev")+getdents64 含 null/zero/ptmx/pts；stat("/dev") 是目录；
 *     lseek 回卷与按 d_off cookie 续读（rewinddir/seekdir 的底层机制）。
 *   - /dev/pts 动态：open("/dev/ptmx") 分配 pty 后 /dev/pts 列出该编号；master 关闭后
 *     节点立即消失（stat 得 ENOENT、列举不含）。
 *   - /dev/tty、/dev/console：open 行为一致（有 ctty->成功，无 ctty->ENXIO）。
 *   - rename/link 跨虚拟文件系统边界（host<->/proc、host<->/dev）-> EXDEV。
 *   - 封闭性契约：open("/dev/不存在") -> ENOENT。
 *     （不做 mkdir/unlink 修改类断言：host 变体以 root 运行时会真的改宿主 /dev。）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

/* getdents64 的内核 dirent 布局（与 VM 的 proc_linux_dirent64 二进制兼容）。
 * 用裸 syscall + 手动解析，以直接覆盖 do_getdents64 虚拟目录填充路径。 */
struct linux_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char d_name[];
};

/* 从 fd 当前位置读一批目录项，返回首项名（及 d_off）。裸 syscall 不经 libc DIR
 * 缓冲--lseek 后再调即从新位置开始，供目录 cookie 往返测试。 */
static int first_dirent(int fd, char* name, size_t namesz, long long* doff) {
    char dbuf[2048];
    int dn = (int)syscall(SYS_getdents64, fd, dbuf, sizeof(dbuf));
    if(dn <= 0) return -1;
    struct linux_dirent64* d = (struct linux_dirent64*)dbuf;
    snprintf(name, namesz, "%s", d->d_name);
    if(doff) *doff = d->d_off;
    return 0;
}

static int fail(const char* msg, int e) {
    printf("FAIL: %s errno=%d\n", msg, e);
    return 1;
}

int main(void) {
    /* 带尾斜杠应等价无尾斜杠（Linux path resolution 忽略非根尾斜杠）。 */
    {
        struct stat ds;
        if(stat("/dev/", &ds) != 0) return fail("stat /dev/ (trailing slash)", errno);
        if(!S_ISDIR(ds.st_mode)) return fail("stat /dev/ not DIR", 0);
        if(stat("/dev/pts/", &ds) != 0) return fail("stat /dev/pts/ (trailing slash)", errno);
        int dd = open("/dev/", O_RDONLY | O_DIRECTORY);
        if(dd < 0) return fail("open /dev/ (trailing slash)", errno);
        close(dd);
    }

    int fd, rc;
    struct stat st;
    char buf[256];

    /* -- 标准设备 I/O -- */
    fd = open("/dev/null", O_RDWR);
    if(fd < 0) return fail("open /dev/null", errno);
    if(write(fd, "abc", 3) != 3) return fail("write /dev/null", errno);
    if(read(fd, buf, 4) != 0) return fail("read /dev/null (expect EOF)", errno);
    close(fd);

    fd = open("/dev/zero", O_RDONLY);
    if(fd < 0) return fail("open /dev/zero", errno);
    memset(buf, 'x', 64);
    if(read(fd, buf, 64) != 64) return fail("read /dev/zero len", errno);
    for(int i = 0; i < 64; i++) if(buf[i] != 0) return fail("read /dev/zero nonzero", 0);
    close(fd);

    fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) return fail("open /dev/urandom", errno);
    memset(buf, 0, 256);
    if(read(fd, buf, 256) != 256) return fail("read /dev/urandom len", errno);
    int nonzero = 0;
    for(int i = 0; i < 256; i++) nonzero |= buf[i];
    if(!nonzero) return fail("read /dev/urandom all zero", 0);
    close(fd);

    fd = open("/dev/full", O_WRONLY);
    if(fd < 0) return fail("open /dev/full", errno);
    rc = (int)write(fd, "abc", 3);
    if(rc != -1 || errno != ENOSPC) return fail("write /dev/full (expect ENOSPC)", errno);
    close(fd);

    /* -- stat 一致性 -- */
    if(stat("/dev/null", &st) != 0) return fail("stat /dev/null", errno);
    if(!S_ISCHR(st.st_mode)) return fail("stat /dev/null not CHR", 0);
    if(stat("/dev/zero", &st) != 0) return fail("stat /dev/zero", errno);
    if(!S_ISCHR(st.st_mode)) return fail("stat /dev/zero not CHR", 0);
    fd = open("/dev/null", O_RDONLY);
    if(fstat(fd, &st) != 0) return fail("fstat /dev/null", errno);
    if(!S_ISCHR(st.st_mode)) return fail("fstat /dev/null not CHR", 0);
    close(fd);

    /* -- std 符号链接：指向 /proc/self/fd/N。procfs 已实现 [pid]/fd 目录 -> open follow
     * 经 fd 链接重开目标 fd（与 host 一致）。例外：stdout 本身是 socket 时（输出被
     * socket 捕获的运行环境），Linux 对 socket 的 /proc/self/fd 重开报 ENXIO，两变体
     * 行为一致，此时期望失败。lstat(NOFOLLOW) 都是 S_IFLNK（/dev 层直接给 target）。 */
    struct stat stio;
    fstat(1, &stio);
    int out_reopenable = !S_ISSOCK(stio.st_mode);
    fstat(2, &stio);
    int err_reopenable = !S_ISSOCK(stio.st_mode);
    fd = open("/dev/stdout", O_WRONLY);
    if(out_reopenable) {
        if(fd < 0) return fail("open /dev/stdout", errno);
        const char* m = "DEV_STDOUT_OK\n";
        if(write(fd, m, strlen(m)) != (long)strlen(m)) return fail("write /dev/stdout", errno);
        close(fd);
    } else {
        if(fd != -1) return fail("open /dev/stdout should fail on socket stdout", 0);
    }

    fd = open("/dev/stderr", O_WRONLY);
    if(err_reopenable) {
        if(fd < 0) return fail("open /dev/stderr", errno);
        close(fd);
    } else {
        if(fd != -1) return fail("open /dev/stderr should fail on socket stderr", 0);
    }

    int fd3 = open("/dev/null", O_RDWR);
    if(fd3 < 0) return fail("open fd3 (anchor)", errno);
    char path[32];
    snprintf(path, sizeof(path), "/dev/fd/%d", fd3);
    int fddup = open(path, O_RDWR);
    if(fddup < 0) return fail("open /dev/fd/N", errno);
    if(fddup == fd3) return fail("open /dev/fd/N returned same fd (not a dup)", 0);
    if(write(fddup, "x", 1) != 1) return fail("write /dev/fd/N dup", errno);
    close(fddup);
    /* lstat（NOFOLLOW）不 follow，两种变体都应得符号链接。 */
    struct stat lst;
    if(lstat("/dev/stdin", &lst) != 0) return fail("lstat /dev/stdin", errno);
    if(!S_ISLNK(lst.st_mode)) return fail("lstat /dev/stdin not LNK", 0);
    /* O_NOFOLLOW：末段是符号链接 -> ELOOP（虚拟链接层自查；host 内核同判）。 */
    fd = open("/dev/stdin", O_RDONLY | O_NOFOLLOW);
    if(fd != -1 || errno != ELOOP) return fail("open /dev/stdin O_NOFOLLOW (expect ELOOP)", errno);
    close(fd3);

    /* -- readlink -- */
    rc = (int)readlink("/dev/stdin", buf, sizeof(buf) - 1);
    if(rc < 0) return fail("readlink /dev/stdin", errno);
    buf[rc] = '\0';
    if(strcmp(buf, "/proc/self/fd/0") != 0) {
        printf("FAIL: readlink /dev/stdin got \"%s\"\n", buf);
        return 1;
    }
    if(readlink("/dev/null", buf, sizeof(buf)) != -1 || errno != EINVAL)
        return fail("readlink /dev/null (expect EINVAL)", errno);

    /* -- 目录列举：ls /dev -- */
    /* 循环 getdents64 直到 EOF（标准用法）：host /dev 真实条目多，单次缓冲读不完。 */
    fd = open("/dev", O_RDONLY | O_DIRECTORY);
    if(fd < 0) return fail("open /dev dir", errno);
    {
        int has_null = 0, has_zero = 0, has_ptmx = 0, has_pts = 0, has_stdin = 0;
        for(;;) {
            char dbuf[2048];
            int dn = (int)syscall(SYS_getdents64, fd, dbuf, sizeof(dbuf));
            if(dn < 0) return fail("getdents /dev", errno);
            if(dn == 0) break;   // EOF
            for(int pos = 0; pos < dn; ) {
                struct linux_dirent64* d = (struct linux_dirent64*)(dbuf + pos);
                if(strcmp(d->d_name, "null") == 0)  has_null = 1;
                if(strcmp(d->d_name, "zero") == 0)  has_zero = 1;
                if(strcmp(d->d_name, "ptmx") == 0)  has_ptmx = 1;
                if(strcmp(d->d_name, "pts") == 0)   has_pts = 1;
                if(strcmp(d->d_name, "stdin") == 0) has_stdin = 1;
                pos += d->d_reclen;
            }
        }
        if(!has_null)  return fail("/dev missing null", 0);
        if(!has_zero)  return fail("/dev missing zero", 0);
        if(!has_ptmx)  return fail("/dev missing ptmx", 0);
        if(!has_pts)   return fail("/dev missing pts", 0);
        if(!has_stdin) return fail("/dev missing stdin", 0);
    }
    close(fd);
    if(stat("/dev", &st) != 0) return fail("stat /dev", errno);
    if(!S_ISDIR(st.st_mode)) return fail("stat /dev not DIR", 0);

    /* -- 目录 lseek cookie：lseek 回到某条目的 d_off 后，下一次 getdents 从其
     *    后一项继续；lseek(0) 回卷到首条目。即 rewinddir/seekdir 的底层机制。 */
    {
        char dbuf[2048];
        fd = open("/dev", O_RDONLY | O_DIRECTORY);
        if(fd < 0) return fail("open /dev dir (lseek)", errno);
        int dn = (int)syscall(SYS_getdents64, fd, dbuf, sizeof(dbuf));
        if(dn <= 0) return fail("getdents /dev (lseek setup)", errno);
        struct linux_dirent64* e1 = (struct linux_dirent64*)dbuf;
        if(dn <= e1->d_reclen) return fail("getdents batch has <2 entries", 0);
        struct linux_dirent64* e2 = (struct linux_dirent64*)(dbuf + e1->d_reclen);
        char n1[256], n2[256], n[256];
        snprintf(n1, sizeof(n1), "%s", e1->d_name);
        snprintf(n2, sizeof(n2), "%s", e2->d_name);
        if(lseek(fd, 0, SEEK_SET) != 0) return fail("lseek /dev rewind to 0", errno);
        if(first_dirent(fd, n, sizeof(n), NULL) != 0) return fail("getdents after rewind", errno);
        if(strcmp(n, n1) != 0) { printf("FAIL: rewind first entry=%s want %s\n", n, n1); return 1; }
        if(lseek(fd, e1->d_off, SEEK_SET) != e1->d_off) return fail("lseek /dev to d_off cookie", errno);
        if(first_dirent(fd, n, sizeof(n), NULL) != 0) return fail("getdents after cookie seek", errno);
        if(strcmp(n, n2) != 0) { printf("FAIL: cookie resume first entry=%s want %s\n", n, n2); return 1; }
        close(fd);
    }

    /* -- /dev/pts 动态：open("/dev/ptmx") 分配 pty 后，/dev/pts 应列出该 pts 编号
     *    （host devpts 同此行为）。 */
    {
        int m = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if(m < 0) return fail("open /dev/ptmx", errno);
        int ptn = 0;
        if(ioctl(m, TIOCGPTN, &ptn) != 0) return fail("TIOCGPTN", errno);
        int dfd = open("/dev/pts", O_RDONLY | O_DIRECTORY);
        if(dfd < 0) return fail("open /dev/pts dir", errno);
        char want[32];
        snprintf(want, sizeof(want), "%d", ptn);
        int found = 0;
        for(;;) {
            char dbuf[2048];
            int dn = (int)syscall(SYS_getdents64, dfd, dbuf, sizeof(dbuf));
            if(dn <= 0) break;
            for(int pos = 0; pos < dn; ) {
                struct linux_dirent64* d = (struct linux_dirent64*)(dbuf + pos);
                if(strcmp(d->d_name, want) == 0) found = 1;
                pos += d->d_reclen;
            }
        }
        close(dfd);
        /* 后缀须整串数字："/dev/pts/<N>x" 应 ENOENT。 */
        snprintf(path, sizeof(path), "/dev/pts/%dx", ptn);
        int bad = open(path, O_RDWR);
        if(bad != -1 || errno != ENOENT) return fail("open /dev/pts/<N>x (expect ENOENT)", errno);
        close(m);
        if(!found) { printf("FAIL: /dev/pts missing pts %d\n", ptn); return 1; }
        /* master 关闭 -> 节点应立即消失（对齐 devpts：master 关即删节点；已开 slave fd
         * 不受影响，但 stat/列举不再可见）。host 变体同断言（真实 devpts 同此行为）。 */
        snprintf(path, sizeof(path), "/dev/pts/%d", ptn);
        if(stat(path, &st) != -1 || errno != ENOENT)
            return fail("stat /dev/pts/N after master close (expect ENOENT)", errno);
        dfd = open("/dev/pts", O_RDONLY | O_DIRECTORY);
        if(dfd < 0) return fail("reopen /dev/pts dir (ghost check)", errno);
        int ghost = 0;
        for(;;) {
            char dbuf[2048];
            int dn = (int)syscall(SYS_getdents64, dfd, dbuf, sizeof(dbuf));
            if(dn <= 0) break;
            for(int pos = 0; pos < dn; ) {
                struct linux_dirent64* d = (struct linux_dirent64*)(dbuf + pos);
                if(strcmp(d->d_name, want) == 0) ghost = 1;
                pos += d->d_reclen;
            }
        }
        close(dfd);
        if(ghost) { printf("FAIL: /dev/pts still lists pts %d after master close\n", ptn); return 1; }
    }

    /* -- /dev/tty、/dev/console：stat 为字符设备（HostChr 走 host 绝对路径）。
     *    open 的 ctty 合成语义由 test_pty 覆盖。 */
    if(stat("/dev/tty", &st) != 0) return fail("stat /dev/tty", errno);
    if(!S_ISCHR(st.st_mode)) return fail("stat /dev/tty not CHR", 0);
    if(stat("/dev/console", &st) != 0) return fail("stat /dev/console", errno);
    if(!S_ISCHR(st.st_mode)) return fail("stat /dev/console not CHR", 0);

    /* -- rename/link 跨文件系统边界 -> EXDEV -- */
    /* host fs、/proc、/dev 互为独立"文件系统"（对齐 Linux 跨挂载点判 EXDEV）。
     * 锚点文件建在 cwd（host 变体 cwd 可写，chroot rootfs 下 cwd 也可写，不依赖 /tmp）。
     * link host->/proc 不断言：宿主 procfs 对不存在条目的 lookup 先失败返回 ENOENT，
     * 与 VM 的统一 EXDEV 不一致。 */
    {
        int src = open("xdev_src.tmp", O_CREAT | O_RDWR | O_TRUNC, 0600);
        if(src < 0) return fail("create xdev anchor", errno);
        close(src);
        if(rename("xdev_src.tmp", "/proc/__xdev") != -1 || errno != EXDEV)
            return fail("rename host->/proc (expect EXDEV)", errno);
        if(rename("/dev/null", "xdev_dst.tmp") != -1 || errno != EXDEV)
            return fail("rename /dev->host (expect EXDEV)", errno);
        if(rename("/proc/uptime", "xdev_dst.tmp") != -1 || errno != EXDEV)
            return fail("rename /proc->host (expect EXDEV)", errno);
        if(link("xdev_src.tmp", "/dev/__xdev") != -1 || errno != EXDEV)
            return fail("link host->/dev (expect EXDEV)", errno);
        if(link("/dev/null", "xdev_dst.tmp") != -1 || errno != EXDEV)
            return fail("link /dev->host (expect EXDEV)", errno);
        if(unlink("xdev_src.tmp") != 0) return fail("unlink xdev anchor", errno);
    }

    /* -- 封闭性契约：open 未知设备 -> ENOENT -- */
    fd = open("/dev/bpfvm_no_such_device", O_RDWR);
    if(fd != -1 || errno != ENOENT) return fail("open /dev/nonexistent (expect ENOENT)", errno);

    printf("test_dev: ALL OK\n");
    return 0;
}
