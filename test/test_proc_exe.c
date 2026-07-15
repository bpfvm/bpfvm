/* open(/proc/self/exe) 应穿透符号链接，读到真实 ELF 文件内容（防回归）。
 * ProcLink 节点曾只服务 readlink/statx，open 返回空 ProcFd，read 立即 EOF，
 * 导致依赖 open("/proc/self/exe") re-exec 的 multi-call 二进制（如 busybox）命令查找失败。 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

int main(void) {
    int fd = open("/proc/self/exe", O_RDONLY);
    if(fd < 0) {
        fprintf(stderr, "FAIL: open /proc/self/exe: errno=%d\n", fd < 0 ? -1 : 0);
        return 1;
    }

    /* 必须能读到真实 ELF header（非空、magic 正确）。 */
    Elf64_Ehdr eh;
    ssize_t n = read(fd, &eh, sizeof eh);
    close(fd);
    if(n < (ssize_t)SELFMAG || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "FAIL: read got %zd bytes, e_ident=%02x%02x%02x%02x (not ELF)\n",
                n, eh.e_ident[0], eh.e_ident[1], eh.e_ident[2], eh.e_ident[3]);
        return 1;
    }
    fprintf(stderr, "OK: /proc/self/exe open+read -> valid ELF\n");
    return 0;
}
