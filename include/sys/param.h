#ifndef SYS_PARAM_H
#define SYS_PARAM_H

#include <limits.h>

#ifndef MAXPATHLEN
#ifdef PATH_MAX
#define MAXPATHLEN PATH_MAX
#else
#define MAXPATHLEN 4096
#endif
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#endif
