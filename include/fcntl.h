#ifndef FCNTL_H
#define FCNTL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

#define AT_FDCWD          -100
#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_REMOVEDIR        0x200
#define AT_SYMLINK_FOLLOW   0x400
#define AT_EACCESS          0x200
#define AT_EMPTY_PATH       0x1000

#define O_RDONLY         00
#define O_WRONLY         01
#define O_RDWR           02
#define O_CREAT        0100
#define O_TRUNC       01000
#define O_APPEND      02000
#define O_EXCL     00000200
#define O_NONBLOCK 00004000
#define O_DIRECTORY 00200000
#define O_CLOEXEC   02000000

#define F_DUPFD 0
#define F_GETFL 3
#define F_SETFL 4
#define F_DUPFD_CLOEXEC 1030
#define F_SETFD 2
#define FD_CLOEXEC 1

#ifndef BPF_NO_SYSCALL
int open3(const char *pathname, int flags, mode_t mode);
int openat4(int dirfd, const char *pathname, int flags, mode_t mode);
int creat(const char *pathname, mode_t mode);
off64_t lseek(int fd, off64_t offset, int whence);
int fcntl3(int fd, int cmd, long arg);

static inline int fcntl2(int fd, int cmd)
{
    return fcntl3(fd, cmd, 0);
}

#define __bpf_pick_fcntl(_1, _2, _3, name, ...) name
#define fcntl(...) __bpf_pick_fcntl(__VA_ARGS__, fcntl3, fcntl2)(__VA_ARGS__)

static inline int open2(const char *pathname, int flags)
{
    return open3(pathname, flags, 0);
}

#define __bpf_pick_open(_1, _2, _3, name, ...) name
#define open(...) __bpf_pick_open(__VA_ARGS__, open3, open2)(__VA_ARGS__)

static inline int openat3(int dirfd, const char *pathname, int flags)
{
    return openat4(dirfd, pathname, flags, 0);
}

#define __bpf_pick_openat(_1, _2, _3, _4, name, ...) name
#define openat(...) __bpf_pick_openat(__VA_ARGS__, openat4, openat3)(__VA_ARGS__)

#endif

#endif
