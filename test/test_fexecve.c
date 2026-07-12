/* fexecve() 优雅降级回归测试。
 *
 * musl 的 fexecve 先试 SYS_execveat(fd,"",argv,envp,AT_EMPTY_PATH)。VM 未实现
 * execveat（占位返 ENOSYS），故 musl 回退到 /proc/self/fd/<fd> + execve。VM 也未
 * 实现 /proc，回退路径的 open 会失败，fexecve 最终返 -1（errno 非 0）。
 *
 * 本测试只验证关键点：fexecve 【不崩溃、不换 ABI 错位】，返 -1 且 errno 被设置。
 * 旧行为（execveat 错配到 EXECVE handler）会把 fd 当 path 读，导致段错误或乱 exec。
 */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int main(void) {
    /* 打开自身可执行文件，作为 fexecve 的 fd 参数。 */
    int fd = open("/bin/test_fexecve", O_RDONLY);
    if (fd < 0) {
        /* rootfs 下路径可能不同，尝试 argv 不依赖；这里只需一个有效 fd。
         * open 失败本身不构成 fexecve 的验证失败，跳过：用一个必然无效的 fd。 */
        fd = open(".", O_RDONLY);
        if (fd < 0) {
            printf("cannot open any file for fexecve test, skip\n");
            return 0;
        }
    }

    char *argv[] = {"test_fexecve", NULL};
    char *envp[] = {NULL};
    int r = fexecve(fd, argv, envp);
    /* 到这里说明 fexecve 返回了（没替换进程映像）。VM 未实现 execveat+proc，
     * 预期返 -1 且 errno 被设置（ENOSYS/ENOENT/EBADF 任一均可）。 */
    if (r != -1) {
        printf("fexecve returned %d, expected -1\n", r);
        return 1;
    }
    if (errno == 0) {
        printf("fexecve returned -1 but errno is 0\n");
        return 1;
    }
    printf("fexecve gracefully degraded: ret=%d errno=%d\n", r, errno);
    return 0;
}
