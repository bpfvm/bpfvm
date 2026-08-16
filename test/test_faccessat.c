/* faccessat 回归测试。
 *
 * 重点验证 musl faccessat() 的 3 参路径：syscall(SYS_faccessat, fd, filename, amode)
 * 只传 3 参，VM 的 do_faccessat 读 r4=flags 时拿到的是【未设置】的寄存器值。
 * 本测试通过 access()（musl 内部走 faccessat(AT_FDCWD, path, amode, 0)）和直接
 * faccessat(...,0) 两条路径，确认结果正确（不因 r4 垃圾值误判权限）。
 *
 * 样本路径用 guest 自身在 CWD 创建的可读文件（而非 /bin 等系统路径）：Android 等
 * 沙箱对系统路径访问受限，自建文件确保跨环境一致。
 */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int main(void) {
    /* 创建一个 guest 可读的样本文件 */
    int fd = open("faccessat_sample", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("create sample failed errno=%d\n", errno);
        return 1;
    }
    write(fd, "x", 1);
    close(fd);

    /* -  access() — musl 内部 faccessat(AT_FDCWD, path, amode, 0)，无 flag 走 3 参路径 */
    if (access("faccessat_sample", R_OK) != 0) {
        printf("access(sample, R) failed errno=%d\n", errno);
        return 1;
    }
    /* 不存在的路径应返 -1 + ENOENT */
    if (access("/no/such/path", R_OK) == 0) {
        printf("access(/no/such/path) unexpectedly succeeded\n");
        return 1;
    }
    if (errno != ENOENT) {
        printf("access(/no/such/path) errno=%d expected ENOENT(%d)\n", errno, ENOENT);
        return 1;
    }

    /* -  直接 faccessat(...,0) — 显式 4 参，r4=0 */
    if (faccessat(AT_FDCWD, "faccessat_sample", R_OK, 0) != 0) {
        printf("faccessat(sample, R, 0) failed errno=%d\n", errno);
        return 1;
    }
    if (faccessat(AT_FDCWD, "/no/such/path", R_OK, 0) == 0) {
        printf("faccessat(/no/such/path) unexpectedly succeeded\n");
        return 1;
    }

    unlink("faccessat_sample");
    printf("faccessat ok\n");
    return 0;
}
