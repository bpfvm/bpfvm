// execve 的 shebang(#!) 解释支持验证：脚本文件 exec 时由 VM 解析脚本头并递归 exec
// 解释器。本测试兼任解释器：脚本头写自身路径（/proc/self/exe），被脚本调起时
// argc >= 2（驱动模式 CTest 不传参，argc == 1），分流进 argv 校验分支，校验
// binfmt_script 语义：解释器头只取首行（脚本体不得泄入参数）、至多一个解释器
// 参数、原 argv[1:] 原样透传。
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern char **environ;

#define SCRIPT_NAME "shebang_test.script"

/* 透传父环境（动态变体的解释器需要 LD_LIBRARY_PATH 定位 ldso/libc.so） */
static int exec_script(const char *path, char *const cargv[]) {
    return execve(path, cargv, environ);
}

/* 解释器模式：argv 为 [self, "-x", script, "sarg"]（带参）或 [self, script]（无参）。
 * script 允许两种形态：调用者路径（普通 exec），或 VM/内核合成的 /dev/fd/N
 * （fexecve）；后者按路径重开校验内容确是脚本头。语义不符打印 FAIL 返回 1，
 * 全对返回 0x22 供驱动方 waitpid 断言。 */
static int check_fd_script(const char *path) {
    if (strncmp(path, "/dev/fd/", 8) != 0) {
        return 1;   /* 普通路径形态，不在此校验 */
    }
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("FAIL: reopen %s (errno=%d)\n", path, errno);
        return 0;
    }
    char head[2];
    size_t n = fread(head, 1, 2, f);
    fclose(f);
    if (n != 2 || head[0] != '#' || head[1] != '!') {
        printf("FAIL: %s does not reopen as script (errno=%d)\n", path, errno);
        return 0;
    }
    return 1;
}

static int interp_main(int argc, char *argv[]) {
    if (strcmp(argv[1], "-x") == 0) {
        if (argc < 3 || (strstr(argv[2], SCRIPT_NAME) == NULL &&
                         strncmp(argv[2], "/dev/fd/", 8) != 0)) {
            printf("FAIL: expected script path after -x, got: %s\n", argc > 2 ? argv[2] : "(none)");
            return 1;
        }
        if (argc >= 4 && strcmp(argv[3], "sarg") != 0) {
            printf("FAIL: expected sarg passthrough, got: %s\n", argv[3]);
            return 1;
        }
        if (!check_fd_script(argv[2])) {
            return 1;
        }
    } else if (strstr(argv[1], SCRIPT_NAME) == NULL &&
               strncmp(argv[1], "/dev/fd/", 8) != 0) {
        printf("FAIL: unexpected argv[1]: %s\n", argv[1]);
        return 1;
    }
    return 0x22;
}

int main(int argc, char *argv[]) {
    if (argc >= 2) {
        return interp_main(argc, argv);
    }

    /* /proc/self/exe 即脚本头里要写的解释器路径 */
    char self[256];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n < 0) {
        printf("FAIL: readlink /proc/self/exe (errno=%d)\n", errno);
        return 1;
    }
    self[n] = '\0';

    /* 脚本：带参数的解释器头 + 脚本体（首行截断语义，脚本体不得泄入 argv[1]） */
    const char *script_path = SCRIPT_NAME;
    FILE *f = fopen(script_path, "w");
    if (!f) {
        printf("FAIL: fopen script (errno=%d)\n", errno);
        return 1;
    }
    fprintf(f, "#!%s -x\nthis line must not leak into argv\n", self);
    fclose(f);
    chmod(script_path, 0755);

    pid_t pid = fork();
    if (pid == 0) {
        char *const cargv[] = { (char *)script_path, "sarg", NULL };
        exec_script(script_path, cargv);
        printf("child: execve script failed (errno=%d)\n", errno);
        _exit(126);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
        printf("FAIL: waitpid status=0x%x\n", status);
        return 1;
    }
    if (WEXITSTATUS(status) != 0x22) {
        printf("FAIL: expected exit 0x22(34), got %d (argv semantic check failed?)\n",
               WEXITSTATUS(status));
        return 1;
    }

    /* 解释器头不带参数的形态：argv = [self, script] */
    f = fopen(script_path, "w");
    fprintf(f, "#!%s\n", self);
    fclose(f);
    chmod(script_path, 0755);
    pid = fork();
    if (pid == 0) {
        char *const cargv[] = { (char *)script_path, NULL };
        exec_script(script_path, cargv);
        _exit(126);
    }
    if (waitpid(pid, &status, 0) != pid) {
        printf("FAIL: waitpid (errno=%d)\n", errno);
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0x22) {
        printf("FAIL: bare shebang exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return 1;
    }

    /* 解释器行无换行结尾（EOF 即行尾）：同样可执行，argv 语义与带换行一致 */
    f = fopen(script_path, "w");
    fprintf(f, "#!%s -x", self);
    fclose(f);
    chmod(script_path, 0755);
    pid = fork();
    if (pid == 0) {
        char *const cargv[] = { (char *)script_path, "sarg", NULL };
        exec_script(script_path, cargv);
        printf("child: execve script failed (errno=%d)\n", errno);
        _exit(126);
    }
    if (waitpid(pid, &status, 0) != pid) {
        printf("FAIL: waitpid (errno=%d)\n", errno);
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0x22) {
        printf("FAIL: no-newline shebang exit=%d\n",
               WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return 1;
    }

    /* fexecve（execveat + AT_EMPTY_PATH）脚本：脚本参数被合成为 /dev/fd/N，
     * 解释器按该路径重开脚本校验内容；非 cloexec fd 跨 exec 存活 -> 0x22 */
    f = fopen(script_path, "w");
    fprintf(f, "#!%s -x\nfexecve form\n", self);
    fclose(f);
    chmod(script_path, 0755);
    int sfd = open(script_path, O_RDONLY);
    if (sfd < 0) {
        printf("FAIL: open script for fexecve (errno=%d)\n", errno);
        return 1;
    }
    pid = fork();
    if (pid == 0) {
        char *const cargv[] = { (char *)script_path, "sarg", NULL };
        fexecve(sfd, cargv, environ);
        fprintf(stderr, "child: fexecve script failed (errno=%d)\n", errno);
        _exit(126);
    }
    close(sfd);
    if (waitpid(pid, &status, 0) != pid) {
        printf("FAIL: waitpid (errno=%d)\n", errno);
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0x22) {
        printf("FAIL: fexecve script exit=%d\n",
               WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return 1;
    }

    /* 同上但 fd 带 O_CLOEXEC：路径 /dev/fd/N 在 exec 后即失效，exec 调用处
     * 直接拒绝 ENOENT（内核 BINPRM_FLAGS_PATH_INACCESSIBLE，两侧一致） */
    sfd = open(script_path, O_RDONLY | O_CLOEXEC);
    if (sfd < 0) {
        printf("FAIL: open script cloexec (errno=%d)\n", errno);
        return 1;
    }
    pid = fork();
    if (pid == 0) {
        char *const cargv[] = { (char *)script_path, "sarg", NULL };
        fexecve(sfd, cargv, environ);
        fprintf(stderr, "child: cloexec fexecve (errno=%d)\n", errno);
        _exit(errno == ENOENT ? 99 : errno);
    }
    close(sfd);
    if (waitpid(pid, &status, 0) != pid) {
        printf("FAIL: waitpid (errno=%d)\n", errno);
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 99) {
        printf("FAIL: cloexec fexecve should ENOENT, got %d\n",
               WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return 1;
    }

    /* 非脚本、非 ELF 的文件必须保持 ENOEXEC */
    f = fopen(script_path, "w");
    fprintf(f, "not a script\n");
    fclose(f);
    pid = fork();
    if (pid == 0) {
        char *const cargv[] = { (char *)script_path, NULL };
        exec_script(script_path, cargv);
        _exit(errno == ENOEXEC ? 99 : errno);
    }
    if (waitpid(pid, &status, 0) != pid) {
        printf("FAIL: waitpid (errno=%d)\n", errno);
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 99) {
        printf("FAIL: plain text should ENOEXEC, got %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return 1;
    }

    unlink(script_path);
    printf("shebang exec ok (interp=%s)\n", self);
    return 0;
}
