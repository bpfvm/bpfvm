// --root chroot 隔离测试。全部断言在 guest 内自证（无需宿主侧校验）：
//   1. getcwd() == "/"（进入 chroot 后从根开始）。
//   2. /marker.txt 可写可读，内容一致（guest 视角绝对路径正常工作）。
//   3. argv[0] 反映 guest 命名空间（以 '/' 开头）。
//   4. 目录 "/" 可列出 marker.txt。
//   5. "/../../../etc/passwd" 无法逃逸：chroot 生效时它规范化为 guest /etc/passwd
//      （rootfs 内不存在）→ open 失败；若 chroot 失效则逃逸到宿主 /etc/passwd → open
//      成功，本项失败。这是隔离的充分自证：guest 自己就能发现逃逸。
//
// 全部通过 → exit 0；任一失败 → exit 非 0（打印 FAIL 行）。

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

static int check(int cond, const char *what) {
    if (!cond) {
        printf("FAIL: %s\n", what);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    int failures = 0;

    // (1) getcwd 应为 "/"
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        printf("FAIL: getcwd returned NULL\n");
        return 1;
    }
    failures += check(strcmp(cwd, "/") == 0, "getcwd should be '/' in chroot");

    // (2) 写 /marker.txt 并读回校验
    int fd = open("/marker.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    failures += check(fd >= 0, "open /marker.txt for write");
    if (fd >= 0) {
        const char *msg = "chroot-ok";
        ssize_t n = write(fd, msg, strlen(msg));
        failures += check(n == (ssize_t)strlen(msg), "write marker");
        close(fd);
    }
    fd = open("/marker.txt", O_RDONLY);
    failures += check(fd >= 0, "open /marker.txt for read");
    if (fd >= 0) {
        char buf[64] = {0};
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        failures += check(n == 9 && strcmp(buf, "chroot-ok") == 0,
                          "marker content mismatch on readback");
    }

    // (3) argv[0] 应是 guest 视角路径（/test_root.out），不是宿主路径
    if (argc > 0) {
        failures += check(strncmp(argv[0], "/", 1) == 0,
                          "argv[0] should start with '/' (guest path)");
    }

    // (4) 列出 / —— marker.txt 应可见
    DIR *d = opendir("/");
    int saw_marker = 0;
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, "marker.txt") == 0) saw_marker = 1;
        }
        closedir(d);
    }
    failures += check(saw_marker, "marker.txt should be visible in /");

    // (5) 逃逸检测：/../../../etc/passwd 在真 chroot 下应 open 失败。
    fd = open("/../../../etc/passwd", O_RDONLY);
    if (fd >= 0) {
        printf("FAIL: escaped chroot via /../../../etc/passwd\n");
        close(fd);
        ++failures;
    }

    if (failures == 0) {
        printf("ALL_PASS\n");
        return 0;
    }
    printf("TOTAL_FAILURES=%d\n", failures);
    return 1;
}
