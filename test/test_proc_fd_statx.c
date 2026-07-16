/* open("/proc/version") 后用该 fd 经 statx(fd,"",AT_EMPTY_PATH,...) 做 fstat——
 * 验证 ProcFile（虚拟 /proc fd，无 host fd）的 statx 路径可达，且字段与 stat(path) 一致。 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define CHECK(expr, msg) do { if(!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while(0)

int main(void) {
    char buf[512];
    int fd = open("/proc/version", O_RDONLY);
    CHECK(fd >= 0, "open /proc/version");

    /* 读出内容，供后续比对 size */
    ssize_t n = read(fd, buf, sizeof(buf));
    CHECK(n > 0 && strstr(buf, "Linux"), "read version");

    /* 用 fd 直接 statx：AT_EMPTY_PATH + 空 pathname = fstat 语义。
     * ProcFile 无 host fd，故 do_statx 不能透传 host——必须走 ProcFile::fstatx。 */
    struct statx stx;
    int rc = statx(fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &stx);
    CHECK(rc == 0, "statx via fd");
    CHECK(S_ISREG(stx.stx_mode), "stx is reg");
    CHECK((stx.stx_mode & 0777) == 0444, "stx mode 0444");
    /* stx_size=0：与真实 Linux /proc 一致（procfs 文件无固定大小）。 */
    CHECK(stx.stx_size == 0, "stx size 0");

    /* 对照：按路径 statx，字段应与 fd 形式一致 */
    struct statx stx2;
    rc = statx(AT_FDCWD, "/proc/version", 0, STATX_BASIC_STATS, &stx2);
    CHECK(rc == 0, "statx via path");
    CHECK(stx2.stx_mode == stx.stx_mode, "mode match");
    CHECK(stx2.stx_size == stx.stx_size, "size match");

    /* lseek 回 0 后再 read，验证 fd 仍可用且内容一致（statx 不应破坏游标） */
    CHECK(lseek(fd, 0, SEEK_SET) == 0, "lseek set");
    char b2[64] = {0};
    ssize_t m = read(fd, b2, sizeof(b2) - 1);
    CHECK(m > 0 && strncmp(b2, buf, m) == 0, "read after statx");

    close(fd);
    fprintf(stderr, "ALL PASS\n");
    return 0;
}
