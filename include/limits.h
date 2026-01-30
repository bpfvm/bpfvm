#ifndef BPF_LIMITS_H
#define BPF_LIMITS_H

#include <sys/types.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#ifndef NAME_MAX
#define NAME_MAX 128
#endif

#ifndef SSIZE_MAX
#define SSIZE_MAX LONG_MAX
#endif

#define _POSIX_PATH_MAX 256
#define _POSIX_NAME_MAX 14
#define _POSIX_HOST_NAME_MAX 255
#define _POSIX_ARG_MAX 4096

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

#ifndef LOGIN_NAME_MAX
#define LOGIN_NAME_MAX 256
#endif

#endif
