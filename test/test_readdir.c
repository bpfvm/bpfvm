#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int make_file(const char *path) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if(fd < 0) {
        return -1;
    }
    if(write(fd, "x", 1) != 1) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int main(void) {
    const char *dir = "readdir_tmp";
    char path[256];

    if(mkdir(dir, 0755) != 0 && errno != EEXIST) {
        printf("mkdir %s failed: %s\n", dir, strerror(errno));
        return 1;
    }

    snprintf(path, sizeof(path), "%s/a", dir);
    if(make_file(path) != 0) {
        printf("create %s failed: %s\n", path, strerror(errno));
        return 2;
    }

    snprintf(path, sizeof(path), "%s/b", dir);
    if(make_file(path) != 0) {
        printf("create %s failed: %s\n", path, strerror(errno));
        return 3;
    }

    snprintf(path, sizeof(path), "%s/sub", dir);
    if(mkdir(path, 0755) != 0 && errno != EEXIST) {
        printf("mkdir %s failed: %s\n", path, strerror(errno));
        return 4;
    }

    DIR *d = opendir(dir);
    if(d == NULL) {
        printf("opendir %s failed: %s\n", dir, strerror(errno));
        return 5;
    }

    int found_a = 0;
    int found_b = 0;
    int found_sub = 0;

    errno = 0;
    for(struct dirent *ent = readdir(d); ent != NULL; ent = readdir(d)) {
        if(strcmp(ent->d_name, "a") == 0) {
            found_a = 1;
        } else if(strcmp(ent->d_name, "b") == 0) {
            found_b = 1;
        } else if(strcmp(ent->d_name, "sub") == 0) {
            found_sub = 1;
        }
    }

    if(errno != 0) {
        printf("readdir %s failed: %s\n", dir, strerror(errno));
        closedir(d);
        return 6;
    }

    closedir(d);

    if(!found_a || !found_b || !found_sub) {
        printf("missing entries: a=%d b=%d sub=%d\n", found_a, found_b, found_sub);
        return 7;
    }

    snprintf(path, sizeof(path), "%s/a", dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/b", dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/sub", dir);
    rmdir(path);
    rmdir(dir);

    printf("ok\n");
    return 0;
}
