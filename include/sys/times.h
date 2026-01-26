#ifndef SYS_TIMES_H
#define SYS_TIMES_H

#include <sys/types.h>
#include <time.h>

struct tms {
    clock_t tms_utime;
    clock_t tms_stime;
    clock_t tms_cutime;
    clock_t tms_cstime;
};

#ifndef _SC_CLK_TCK
#define _SC_CLK_TCK 2
#endif

#ifndef BPF_NO_SYSCALL
clock_t times(struct tms *buf);
#endif

#endif
