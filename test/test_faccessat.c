/* faccessat 回归测试。
 *
 * 重点验证 musl faccessat() 的 3 参路径：syscall(SYS_faccessat, fd, filename, amode)
 * 只传 3 参，VM 的 do_faccessat 读 r4=flags 时拿到的是【未设置】的寄存器值。
 * 本测试通过 access()（musl 内部走 faccessat(AT_FDCWD, path, amode, 0)）和直接
 * faccessat(...,0) 两条路径，确认结果正确（不因 r4 垃圾值误判权限）。
 */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int main(void) {
    /* /bin 应可读可执行，普通文件测试用自身可执行文件 */
    /* 1) access() — musl 内部 faccessat(AT_FDCWD, path, amode, 0)，无 flag 走 3 参路径 */
    if (access("/bin", R_OK | X_OK) != 0) {
        printf("access(/bin, R|X) failed errno=%d\n", errno);
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

    /* 2) 直接 faccessat(...,0) — 显式 4 参，r4=0 */
    if (faccessat(AT_FDCWD, "/bin", R_OK | X_OK, 0) != 0) {
        printf("faccessat(/bin, R|X, 0) failed errno=%d\n", errno);
        return 1;
    }
    if (faccessat(AT_FDCWD, "/no/such/path", R_OK, 0) == 0) {
        printf("faccessat(/no/such/path) unexpectedly succeeded\n");
        return 1;
    }

    printf("faccessat ok\n");
    return 0;
}
