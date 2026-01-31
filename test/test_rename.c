#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

int main() {
    // Cleanup previous runs
    unlink("test_rename_old");
    unlink("test_rename_new");
    rmdir("test_rename_dir");

    // Case 1: Simple rename with AT_FDCWD
    int fd = open("test_rename_old", O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    close(fd);

    if (rename("test_rename_old", "test_rename_new") < 0) {
        perror("rename");
        return 1;
    }

    struct stat st;
    if (stat("test_rename_old", &st) == 0) {
        fprintf(stderr, "Old file still exists\n");
        return 1;
    }
    if (stat("test_rename_new", &st) != 0) {
        fprintf(stderr, "New file does not exist\n");
        return 1;
    }

    // Case 2: Rename using directory FDs
    if (mkdir("test_rename_dir", 0755) < 0) {
        perror("mkdir");
        return 1;
    }
    int dirfd = open("test_rename_dir", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        perror("open dir");
        return 1;
    }

    // Create a file inside the directory
    fd = openat(dirfd, "file_old", O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        perror("openat create");
        return 1;
    }
    close(fd);

    // Rename using renameat and the directory FD
    if (renameat(dirfd, "file_old", dirfd, "file_new") < 0) {
        perror("renameat");
        return 1;
    }

    if (fstatat(dirfd, "file_old", &st, 0) == 0) {
        fprintf(stderr, "Old file inside dir still exists\n");
        return 1;
    }
    if (fstatat(dirfd, "file_new", &st, 0) != 0) {
        fprintf(stderr, "New file inside dir does not exist\n");
        return 1;
    }

    close(dirfd);
    unlink("test_rename_new");
    unlink("test_rename_dir/file_new"); // cleanup inside dir? or just rm -rf equivalent
    // Since we don't have rm -rf easily, just unlink specific file
    int dirfd2 = open("test_rename_dir", O_RDONLY | O_DIRECTORY);
    unlinkat(dirfd2, "file_new", 0);
    close(dirfd2);
    rmdir("test_rename_dir");


    printf("Test passed\n");
    return 0;
}
