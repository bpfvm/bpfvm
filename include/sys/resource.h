#ifndef SYS_RESOURCE_H
#define SYS_RESOURCE_H

#include <sys/types.h>

typedef unsigned long rlim_t;

struct rlimit {
    rlim_t rlim_cur;
    rlim_t rlim_max;
};

#define RLIM_INFINITY ((rlim_t)-1)

#define NZERO 20

#define PRIO_PROCESS 0
#define PRIO_PGRP    1
#define PRIO_USER    2

#ifndef PRIO_MIN
#define PRIO_MIN (-NZERO)
#endif

#ifndef PRIO_MAX
#define PRIO_MAX (NZERO - 1)
#endif

#ifndef BPF_NO_SYSCALL
int getrlimit(int resource, struct rlimit *rlim);
int setrlimit(int resource, const struct rlimit *rlim);
int getpriority(int which, int who);
int setpriority(int which, int who, int prio);
#endif

#endif
