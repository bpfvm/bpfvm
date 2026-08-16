/* fexecve() 回归测试。
 *
 * musl 的 fexecve 先试 SYS_execveat(fd,"",argv,envp,AT_EMPTY_PATH)。VM 现已实现
 * AT_EMPTY_PATH：直取 fd 表项底层 host fd（dup 出独立 fd）加载 ELF，替换地址空间。
 * 不走路径重解析，也不依赖 /proc/self/fd，更不会返回 ENOSYS。
 *
 * 两个用例：
 *   -  成功路径：fexecve 一个指向自身 ELF 的 fd（经 /proc/self/exe 取真实 ELF 路径）。
 *      re-exec 后的新映像由哨兵 env（FEXECVE_REEXEC=1）识别，打印 ok 并 exit 0。
 *      覆盖 AT_EMPTY_PATH 实现 + /proc/self/exe open + 映像替换 + argv/envp 传递。
 *   -  优雅降级：fexecve 一个目录 fd（open(".")），目录非 ELF，execveat 返 -ENOEXEC，
 *      fexecve 不替换映像、返 -1 且 errno 被设置。验证关键点：fexecve
 *      【不崩溃、不把 fd 当 path 读导致段错误】。旧行为（execveat 错配到 EXECVE handler）
 *      会把 fd 当 path 读，导致段错误或乱 exec。
 */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#if defined(__ANDROID__)
#include <sys/syscall.h>
/* bionic 不暴露 fexecve() wrapper。Android 上用 execveat(AT_EMPTY_PATH) 实现 fexecve
 *（与 musl 的 fexecve 实现同理）。 */
static int fexecve(int fd, char *const argv[], char *const envp[]) {
    return (int)syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
}
#endif

#define SENTINEL "FEXECVE_REEXEC=1"

int main(void) {
    /* re-exec 后的新映像：哨兵 env 已设，说明用例 1 的 fexecve 成功替换了映像。
     * 校验 argv[0] 与新 env 都已正确传递，打印 ok 退出。 */
    if (getenv("FEXECVE_REEXEC")) {
        printf("ok\n");
        return 0;
    }

    /* —— 用例 1：成功路径 —— */
    /* /proc/self/exe 是 magic symlink -> 真实 ELF。open 经 ExeLinkGen 直连底层 exe fd
     * 重开，得到的 HostFd 即 do_execveat 的 AT_EMPTY_PATH 分支直取的 fd 表项。 */
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("FAIL: open /proc/self/exe: %s\n", strerror(errno));
        return 1;
    }
    char *argv[] = {"test_fexecve", NULL};
    /* envp 必须包含哨兵 SENTINEL（re-exec 识别用）+ 父进程 LD_LIBRARY_PATH
     * （动态变体 re-exec 需要 ldso/libc.so）。execve 用 envp 整体替换环境，不继承
     * 父 environ，故 LD_LIBRARY_PATH 必须显式带上。用动态构造避免数组字面量里出现
     * "中间的 NULL"（envp 数组里的 NULL 会提前终止，吞掉后面的项）。*/
    char ldpath_var[280];
    const char *lp = getenv("LD_LIBRARY_PATH");
    char *envp[4];
    int en = 0;
    if (lp && *lp) {
        snprintf(ldpath_var, sizeof(ldpath_var), "LD_LIBRARY_PATH=%s", lp);
        envp[en++] = ldpath_var;
    }
    envp[en++] = SENTINEL;
    envp[en] = NULL;
    int r = fexecve(fd, argv, envp);
    /* 走到这里说明 fexecve 失败（成功则映像已被替换，不会返回）。 */
    printf("FAIL: fexecve(self exe) returned %d, expected not to return: %s\n",
           r, strerror(errno));
    close(fd);

    /* —— 用例 2：优雅降级（目录 fd -> ENOEXEC）—— */
    /* open 一个目录 fd，目录非 ELF，load_elf 失败 -> execveat 返 -ENOEXEC。
     * 验证关键点：不崩溃、不把 fd 当 path 读导致段错误。 */
    int dfd = open(".", O_RDONLY);
    if (dfd < 0) {
        printf("FAIL: open(.): %s\n", strerror(errno));
        return 1;
    }
    char *dargv[] = {"test_fexecve", NULL};
    char *denvp[] = {NULL};
    int dr = fexecve(dfd, dargv, denvp);
    if (dr != -1) {
        printf("FAIL: fexecve(dir) returned %d, expected -1\n", dr);
        close(dfd);
        return 1;
    }
    if (errno == 0) {
        printf("FAIL: fexecve(dir) returned -1 but errno is 0\n");
        close(dfd);
        return 1;
    }
    close(dfd);
    printf("fexecve(dir) gracefully degraded: ret=%d errno=%d\n", dr, errno);

    /* 用例 1 失败导致走到这里：整体失败。 */
    return 1;
}
