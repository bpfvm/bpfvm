#ifndef FCNTL_H
#define FCNTL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define AT_FDCWD          -100

#ifndef PATH_MAX
#define PATH_MAX          4096
#endif

#define O_RDONLY         00
#define O_WRONLY         01
#define O_RDWR           02
#define O_CREAT        0100
#define O_TRUNC       01000
#define O_APPEND      02000
#define O_EXCL     00000200
#define O_NONBLOCK 00004000

#define F_DUPFD 0
#define F_GETFL 3
#define F_SETFL 4
#define F_DUPFD_CLOEXEC 1030
#define F_SETFD 2
#define FD_CLOEXEC 1


#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IXUSR 0100
#define S_IRGRP (S_IRUSR >> 3)
#define S_IWGRP (S_IWUSR >> 3)
#define S_IXGRP (S_IXUSR >> 3)
#define S_IROTH (S_IRGRP >> 3)
#define S_IWOTH (S_IWGRP >> 3)
#define S_IXOTH (S_IXGRP >> 3)

#ifndef BPF_NO_SYSCALL
int open3(const char *pathname, int flags, mode_t mode);
off64_t lseek(int fd, off64_t offset, int whence);
int fcntl(int fd, int cmd, long arg);

static inline int open2(const char *pathname, int flags)
{
    return open3(pathname, flags, 0);
}

#define __bpf_pick_open(_1, _2, _3, name, ...) name
#define open(...) __bpf_pick_open(__VA_ARGS__, open3, open2)(__VA_ARGS__)

#endif

#endif
