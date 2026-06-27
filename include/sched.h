#ifndef SCHED_H
#define SCHED_H

#include <sys/types.h>

#ifndef BPF_NO_SYSCALL
int sched_yield(void);
#endif

#endif
