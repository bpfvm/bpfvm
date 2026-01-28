#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int check(int rc, const char *msg) {
    if(rc == 0) {
        return 0;
    }
    printf("%s: %s\n", msg, strerror(errno));
    return rc;
}

int main(void) {
    char cwd_buf[1024];
    if(getcwd(cwd_buf, sizeof(cwd_buf)) == NULL) {
        printf("getcwd initial failed: %s\n", strerror(errno));
        return 1;
    }
    printf("cwd0=%s\n", cwd_buf);

    int fd = open("vm_path_tmp", O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if(fd < 0) {
        printf("open vm_path_tmp failed: %s\n", strerror(errno));
        return 2;
    }
    const char *msg = "ok\n";
    if(write(fd, msg, 3) != 3) {
        printf("write vm_path_tmp failed: %s\n", strerror(errno));
        close(fd);
        return 3;
    }
    close(fd);

    if(chdir("test") != 0) {
        printf("chdir test failed: %s\n", strerror(errno));
        return 4;
    }

    if(getcwd(cwd_buf, sizeof(cwd_buf)) == NULL) {
        printf("getcwd after chdir failed: %s\n", strerror(errno));
        return 5;
    }
    printf("cwd1=%s\n", cwd_buf);

    fd = open("../vm_path_tmp", O_RDONLY);
    if(fd < 0) {
        printf("open ../vm_path_tmp failed: %s\n", strerror(errno));
        return 6;
    }
    close(fd);

    if(check(rename("../vm_path_tmp", "../vm_path_tmp_renamed"), "rename ../vm_path_tmp") != 0) {
        return 7;
    }

    if(check(unlink("../vm_path_tmp_renamed"), "unlink ../vm_path_tmp_renamed") != 0) {
        return 8;
    }

    fd = open("test_arg.out", O_RDONLY);
    if(fd < 0) {
        printf("open test_arg.out failed: %s\n", strerror(errno));
        return 9;
    }
    close(fd);

    printf("ok\n");
    return 0;
}
