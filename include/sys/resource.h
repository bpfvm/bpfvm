#ifndef SYS_RESOURCE_H
#define SYS_RESOURCE_H

#include <sys/types.h>

typedef unsigned long rlim_t;

struct rlimit {
    rlim_t rlim_cur;
    rlim_t rlim_max;
};

#define RLIM_INFINITY ((rlim_t)-1)

#ifndef BPF_NO_SYSCALL
int getrlimit(int resource, struct rlimit *rlim);
int setrlimit(int resource, const struct rlimit *rlim);
#endif

#endif
