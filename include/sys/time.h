#ifndef SYS_TIME_H
#define SYS_TIME_H

#include <sys/types.h>

struct timeval {
    time_t tv_sec;
    long   tv_usec;
};

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

#ifndef BPF_NO_SYSCALL
int gettimeofday(struct timeval* tv, struct timezone* tz);
int utimes(const char *filename, const struct timeval times[2]);
int lutimes(const char *filename, const struct timeval times[2]);
int futimes(int fd, const struct timeval times[2]);
#endif

#endif
