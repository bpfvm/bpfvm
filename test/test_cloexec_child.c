#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Child: Invalid argument count: %d\n", argc);
        return 1;
    }

    int fd_cloexec = atoi(argv[1]);
    int fd_keep = atoi(argv[2]);

    printf("Child: Checking fd_cloexec=%d (should be closed)...\n", fd_cloexec);
    if (write(fd_cloexec, "fail", 4) != -1) {
        printf("FAILURE: fd_cloexec is still open!\n");
        return 1;
    } else {
        if (errno == EBADF) {
             printf("SUCCESS: fd_cloexec is closed (EBADF).\n");
        } else {
             printf("WARNING: fd_cloexec write failed with unexpected error: %s\n", strerror(errno));
        }
    }

    printf("Child: Checking fd_keep=%d (should be open)...\n", fd_keep);
    if (write(fd_keep, "ok", 2) == -1) {
        printf("FAILURE: fd_keep is closed! Error: %s\n", strerror(errno));
        return 1;
    }
    printf("SUCCESS: fd_keep is open.\n");

    unlink("cloexec_check.tmp");
    unlink("keep_check.tmp");
    return 0;
}
