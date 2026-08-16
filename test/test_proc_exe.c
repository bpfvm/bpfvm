/* /proc/self/exe 魔法链接测试：
 * - open 穿透符号链接，读到真实 ELF 文件内容（防回归：旧实现 open 返回空内容的
 *   /proc fd，read 立即 EOF，依赖 re-exec 的 multi-call 二进制如 busybox 查找失败）。
 * - readlink 绝对路径、fstat REG、O_NOFOLLOW=ELOOP、写模式 ETXTBSY（Linux
 *   i_writecount：正被执行的文件拒绝写打开）。
 * - exec 已删文件（Linux 经 /proc 魔法链接解析到进程钉住的 struct file，路径已删
 *   仍可 exec）：FdLinkGen 路径 execve("/proc/self/fd/N")；ExeLinkGen 路径子进程 A
 *   先 exec 已删副本，B 再 execve("/proc/A/exe")；fd 直连路径 C fexecve(keep,
 *   AT_EMPTY_PATH)（dup 表项底层 host fd，不经路径重解析）。
 * host 变体行为一致（readlink 对已删 exe 带 " (deleted)" 后缀，前缀匹配兼容）。 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/wait.h>
#if defined(__ANDROID__)
#include <sys/syscall.h>
/* bionic 不暴露 fexecve() wrapper，用 execveat(AT_EMPTY_PATH) 等价实现。 */
static int fexecve(int fd, char *const argv[], char *const envp[]) {
    return (int)syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
}
#endif

#define TMP "/tmp/bpfvm_test_proc_exe.bin"

#define CHECK(expr, msg) do { if(!(expr)) { fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno); exit(1); } } while(0)

int main(int argc, char* argv[]) {
    /* 子映像入口：argv[1] 标记。sleeper = 已删副本的运行进程（存活供 /proc/A/exe
     * 解析）；其余打印标记退出。 */
    if(argc > 1) {
        if(strcmp(argv[1], "sleeper") == 0) {
            usleep(1000000);
            return 0;
        }
        printf("EXEC-OK %s\n", argv[1]);
        return 0;
    }

    int fd = open("/proc/self/exe", O_RDONLY);
    if(fd < 0) {
        fprintf(stderr, "FAIL: open /proc/self/exe: errno=%d\n", errno);
        return 1;
    }

    /* 必须能读到真实 ELF header（非空、magic 正确）。 */
    Elf64_Ehdr eh;
    ssize_t n = read(fd, &eh, sizeof eh);
    struct stat st;
    int fst_ok = fstat(fd, &st);
    close(fd);
    if(n < (ssize_t)SELFMAG || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "FAIL: read got %zd bytes, e_ident=%02x%02x%02x%02x (not ELF)\n",
                n, eh.e_ident[0], eh.e_ident[1], eh.e_ident[2], eh.e_ident[3]);
        return 1;
    }
    if(fst_ok != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "FAIL: fstat /proc/self/exe not REG (rc=%d mode=%o)\n",
                fst_ok, st.st_mode);
        return 1;
    }

    /* readlink 报绝对路径。 */
    char buf[512];
    ssize_t l = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if(l <= 0 || buf[0] != '/') {
        fprintf(stderr, "FAIL: readlink /proc/self/exe -> %zd errno=%d\n", l, errno);
        return 1;
    }

    /* O_NOFOLLOW：末段是魔法链接 -> ELOOP。 */
    errno = 0;
    if(open("/proc/self/exe", O_RDONLY | O_NOFOLLOW) >= 0 || errno != ELOOP) {
        fprintf(stderr, "FAIL: O_NOFOLLOW expect ELOOP, got errno=%d\n", errno);
        return 1;
    }
    /* 写模式：正被执行的文件 -> ETXTBSY。 */
    errno = 0;
    if(open("/proc/self/exe", O_WRONLY) >= 0 || errno != ETXTBSY) {
        fprintf(stderr, "FAIL: O_WRONLY expect ETXTBSY, got errno=%d\n", errno);
        return 1;
    }
    errno = 0;
    if(open("/proc/self/exe", O_RDWR) >= 0 || errno != ETXTBSY) {
        fprintf(stderr, "FAIL: O_RDWR expect ETXTBSY, got errno=%d\n", errno);
        return 1;
    }
    fprintf(stderr, "OK: /proc/self/exe open+read -> valid ELF\n");

    /* 复制自身（源经 /proc/self/exe 读）到 TMP，重开留 fd 后删除。 */
    int in = open("/proc/self/exe", O_RDONLY);
    CHECK(in >= 0, "open /proc/self/exe for copy");
    int out = open(TMP, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    CHECK(out >= 0, "create tmp copy");
    char cbuf[2048];
    ssize_t cn;
    while((cn = read(in, cbuf, sizeof(cbuf))) > 0) {
        CHECK(write(out, cbuf, cn) == cn, "write tmp copy");
    }
    CHECK(cn == 0, "read src EOF");
    close(in);
    close(out);
    int keep = open(TMP, O_RDONLY);
    CHECK(keep >= 0, "reopen tmp copy");
    CHECK(unlink(TMP) == 0, "unlink tmp copy");

    /* 动态构造 envp：转发 LD_LIBRARY_PATH（动态变体 re-exec 需要 ldso 搜索路径）。 */
    char ldpath_var[280];
    const char* lp = getenv("LD_LIBRARY_PATH");
    char* envp[2];
    int en = 0;
    if(lp && *lp) {
        snprintf(ldpath_var, sizeof(ldpath_var), "LD_LIBRARY_PATH=%s", lp);
        envp[en++] = ldpath_var;
    }
    envp[en] = NULL;

    /* A 经 /proc/self/fd/N exec 已删副本（FdLinkGen 路径）。 */
    char fdpath[64];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", keep);
    char* av_sleeper[] = {"unlinked", "sleeper", NULL};
    pid_t a = fork();
    CHECK(a >= 0, "fork A");
    if(a == 0) {
        execve(fdpath, av_sleeper, envp);
        _exit(111);
    }

    /* 等 A 换成已删副本：readlink /proc/A/exe 变为 TMP（host 带 " (deleted)" 后缀，前缀匹配）。 */
    char apath[64], lb[512];
    snprintf(apath, sizeof(apath), "/proc/%d/exe", (int)a);
    int i;
    for(i = 0; i < 100; i++) {
        ssize_t rl = readlink(apath, lb, sizeof(lb) - 1);
        if(rl > 0) {
            lb[rl] = '\0';
            if(strncmp(lb, TMP, strlen(TMP)) == 0) break;
        }
        usleep(20000);
    }
    CHECK(i < 100, "A exec'd deleted copy in time");

    /* follow stat 直连底层文件：exe 已删除仍成功（Linux 跳到进程钉住的 dentry）。 */
    struct stat ast;
    CHECK(stat(apath, &ast) == 0 && S_ISREG(ast.st_mode), "stat deleted exe");
    CHECK((ast.st_mode & 0777) == 0755 && ast.st_size > 0, "stat deleted exe attrs");

    /* B 经 /proc/A/exe exec A 正在执行的同一已删文件（ExeLinkGen 路径）。 */
    char* av_child[] = {"unlinked", "via-exe", NULL};
    pid_t b = fork();
    CHECK(b >= 0, "fork B");
    if(b == 0) {
        execve(apath, av_child, envp);
        _exit(112);
    }
    int wst;
    CHECK(waitpid(b, &wst, 0) == b && WIFEXITED(wst) && WEXITSTATUS(wst) == 0,
          "B exec via /proc/A/exe");

    /* C 经 fexecve（execveat AT_EMPTY_PATH）exec 已删副本（fd 直连路径）：dup 表项底层
     * host fd 加载，不经路径重解析——keep 经 fork 共享给 C，Linux 语义下同样成功。 */
    char* av_fexec[] = {"unlinked", "via-fexecve", NULL};
    pid_t c = fork();
    CHECK(c >= 0, "fork C");
    if(c == 0) {
        fexecve(keep, av_fexec, envp);
        _exit(113);
    }
    CHECK(waitpid(c, &wst, 0) == c && WIFEXITED(wst) && WEXITSTATUS(wst) == 0,
          "C fexecve deleted file");

    CHECK(waitpid(a, &wst, 0) == a && WIFEXITED(wst) && WEXITSTATUS(wst) == 0,
          "A sleeper exited");
    fprintf(stderr, "ALL PASS\n");
    return 0;
}
