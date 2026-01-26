#ifndef SYS_PARAM_H
#define SYS_PARAM_H

#include <limits.h>

#ifndef MAXPATHLEN
#ifdef PATH_MAX
#define MAXPATHLEN PATH_MAX
#else
#define MAXPATHLEN 1024
#endif
#endif

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#endif
