#ifndef SYS_TIME_H
#define SYS_TIME_H

#include <time.h>

#define suseconds_t unsigned long long

struct timeval {
    time_t      tv_sec;
    suseconds_t tv_usec;
};

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

#ifndef BPF_NO_SYSCALL
int gettimeofday(struct timeval* tv, struct timezone* tz);
#endif

#endif
