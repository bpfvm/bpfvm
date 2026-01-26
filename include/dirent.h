#ifndef DIRENT_H
#define DIRENT_H

#include <sys/types.h>

typedef struct {
    int dummy;
} DIR;

struct dirent64 {
    char d_name[256];
    unsigned char d_type;
};

#define DT_UNKNOWN 0
#define DT_DIR 4
#define DT_LNK 10

#ifndef BPF_NO_SYSCALL
DIR *opendir(const char *pathname);
struct dirent64 *readdir(DIR *dirp);
int closedir(DIR *dirp);
#endif

#endif
