#ifndef _BPFVM_SYS_WAIT_H
#define _BPFVM_SYS_WAIT_H

#include <sys/types.h>

/* Minimal wait status macros for BPF builds. */
#define WNOHANG    1
#define WUNTRACED  2

#define WIFEXITED(status)   (((status) & 0x7f) == 0)
#define WEXITSTATUS(status) (((status) >> 8) & 0xff)
#define WIFSIGNALED(status) (((status) & 0x7f) != 0 && ((status) & 0x7f) != 0x7f)
#define WTERMSIG(status)    ((status) & 0x7f)
#define WIFSTOPPED(status)  (((status) & 0xff) == 0x7f)
#define WSTOPSIG(status)    (((status) >> 8) & 0xff)

#endif
