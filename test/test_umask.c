#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    mode_t old = umask(0022);
    if(old != 0022) {
        printf("umask old=%o\n", (unsigned)old);
        return 1;
    }

    int fd = open("umask_tmp", O_CREAT | O_TRUNC | O_WRONLY, 0666);
    if(fd < 0) {
        printf("open umask_tmp failed: %s\n", strerror(errno));
        return 2;
    }

    struct stat st;
    if(fstat(fd, &st) != 0) {
        printf("fstat umask_tmp failed: %s\n", strerror(errno));
        close(fd);
        return 3;
    }

    mode_t mode = st.st_mode & 0777;
    if(mode != 0644) {
        printf("mode=%o\n", (unsigned)mode);
        close(fd);
        unlink("umask_tmp");
        return 4;
    }

    close(fd);
    unlink("umask_tmp");
    printf("ok\n");
    return 0;
}
