#ifndef DIRENT_H
#define DIRENT_H

#include <sys/types.h>
#include <stdint.h>

struct dirent {
    char d_name[256];
    unsigned char d_type;
};

struct linux_dirent64 {
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

typedef struct {
    uint64_t handle;
    int fd;
    struct dirent entry;
} DIR;

enum{
    DT_UNKNOWN = 0,
    DT_DIR = 4,
    DT_LNK = 10,
};

#ifndef BPF_NO_SYSCALL
DIR *opendir(const char *pathname);
DIR *fdopendir(int fd);
struct dirent *readdir(DIR *dirp);
int closedir(DIR *dirp);
ssize_t getdents64(int fd, void *dirp, size_t count);
#endif

#endif
