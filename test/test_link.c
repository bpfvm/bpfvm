#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

int main() {
    // Cleanup previous runs
    unlink("test_link_file");
    unlink("test_link_new");

    int fd = open("test_link_file", O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    write(fd, "hello", 5);
    close(fd);

    if (link("test_link_file", "test_link_new") < 0) {
        perror("link");
        return 1;
    }

    int fd2 = open("test_link_new", O_RDONLY);
    if (fd2 < 0) {
        perror("open linked file");
        return 1;
    }
    char buf[10];
    int n = read(fd2, buf, 10);
    if (n != 5 || strncmp(buf, "hello", 5) != 0) {
        fprintf(stderr, "read failed or mismatch\n");
        return 1;
    }
    close(fd2);

    if (unlink("test_link_file") < 0) {
        perror("unlink 1");
        return 1;
    }

    // File should still exist via new link
    fd2 = open("test_link_new", O_RDONLY);
    if (fd2 < 0) {
        perror("open linked file after unlink");
        return 1;
    }
    close(fd2);

    if (unlink("test_link_new") < 0) {
        perror("unlink 2");
        return 1;
    }

    printf("Test passed\n");
    return 0;
}
