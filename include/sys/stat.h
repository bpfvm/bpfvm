#ifndef SYS_STAT_H
#define SYS_STAT_H

#include <sys/types.h>
#include <time.h>

/*
 * struct stat 布局：对齐 musl 的 bits/stat.h（x86_64 kernel 风格）。
 * 字段顺序、padding、末尾 __unused 都与 musl 一致——PDCLib 的 fstatat 封装
 *（statx→stat 转换）写入此布局，guest 程序读取，偏移必须严丝合缝。
 * 关键差异点（相对早期布局）：st_nlink 在 st_mode 之前；st_gid 后有 __pad0；
 * 末尾有 __unused[3]。注释里的偏移供核对。
 */
struct stat {
    dev_t       st_dev;         /* 0x00 */
    ino_t       st_ino;         /* 0x08 */
    nlink_t     st_nlink;       /* 0x10 */
    mode_t      st_mode;        /* 0x18 */
    uid_t       st_uid;         /* 0x1c */
    gid_t       st_gid;         /* 0x20 */
    unsigned int __pad0;        /* 0x24 */
    dev_t       st_rdev;        /* 0x28 */
    off_t       st_size;        /* 0x30 */
    blksize_t   st_blksize;     /* 0x38 */
    blkcnt_t    st_blocks;      /* 0x40 */
    struct timespec st_atim;    /* 0x48 */
    struct timespec st_mtim;    /* 0x58 */
    struct timespec st_ctim;    /* 0x68 */
    long        __unused[3];    /* 0x78 */
};

#define st_atime st_atim.tv_sec
#define st_mtime st_mtim.tv_sec
#define st_ctime st_ctim.tv_sec

#define S_IFMT  0170000
#define S_IFSOCK 0140000
#define S_IFLNK  0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000

#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000

#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

#define AT_FDCWD		-100
#define AT_SYMLINK_NOFOLLOW	0x100
#define AT_REMOVEDIR		0x200
#define AT_SYMLINK_FOLLOW	0x400
#define AT_EACCESS		0x200
#define UTIME_NOW		((1L << 30) - 1L)
#define UTIME_OMIT		((1L << 30) - 2L)

/* struct statx 布局对齐 musl include/sys/stat.h（源自 Linux UAPI stat.h）。
 * VM do_statx（posix_syscall.cpp）与 guest 程序读写同一份布局，偏移须严丝合缝。
 * host glibc 的 struct statx 同源 UAPI，二进制兼容（均 256 字节）。 */
struct statx_timestamp {
    int64_t tv_sec;
    uint32_t tv_nsec;
    uint32_t __pad;
};

struct statx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t __pad0[1];
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct statx_timestamp stx_atime;
    struct statx_timestamp stx_btime;
    struct statx_timestamp stx_ctime;
    struct statx_timestamp stx_mtime;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t stx_mnt_id;
    uint32_t stx_dio_mem_align;
    uint32_t stx_dio_offset_align;
    uint64_t stx_subvol;
    uint32_t stx_atomic_write_unit_min;
    uint32_t stx_atomic_write_unit_max;
    uint32_t stx_atomic_write_segments_max;
    uint32_t __pad1[1];
    uint64_t __pad2[9];
};

#define STATX_TYPE 1U
#define STATX_MODE 2U
#define STATX_NLINK 4U
#define STATX_UID 8U
#define STATX_GID 0x10U
#define STATX_ATIME 0x20U
#define STATX_MTIME 0x40U
#define STATX_CTIME 0x80U
#define STATX_INO 0x100U
#define STATX_SIZE 0x200U
#define STATX_BLOCKS 0x400U
#define STATX_BASIC_STATS 0x7ffU
#define STATX_BTIME 0x800U
#define STATX_ALL 0xfffU

#ifndef BPF_NO_SYSCALL
int stat(const char *path, struct stat *buf);
int lstat(const char *path, struct stat *buf);
int fstat(int fd, struct stat *buf);
int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
mode_t umask(mode_t mask);
int mkdir(const char *path, mode_t mode);
int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
int mknod(const char *pathname, mode_t mode, dev_t dev);
int mkfifoat(int dirfd, const char *pathname, mode_t mode);
int mkfifo(const char *pathname, mode_t mode);
int chmod(const char *path, mode_t mode);
int fchmod(int fd, mode_t mode);
int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
int chown(const char *path, uid_t owner, gid_t group);
int fchown(int fd, uid_t owner, gid_t group);
int lchown(const char *pathname, uid_t owner, gid_t group);
int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);
int futimens(int fd, const struct timespec times[2]);
#endif

#endif
