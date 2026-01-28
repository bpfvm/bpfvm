#ifndef DIRENT_H
#define DIRENT_H

#include <sys/types.h>
#include <stdint.h>

struct dirent {
    char d_name[256];
    unsigned char d_type;
};

typedef struct {
    uint64_t handle;
    struct dirent entry;
} DIR;

enum{
    DT_UNKNOWN = 0,
    DT_DIR = 4,
    DT_LNK = 10,
};

#ifndef BPF_NO_SYSCALL
DIR *opendir(const char *pathname);
struct dirent *readdir(DIR *dirp);
int closedir(DIR *dirp);
#endif

#endif
