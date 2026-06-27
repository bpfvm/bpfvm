#ifndef SYS_MMAN_H
#define SYS_MMAN_H

#include <stdint.h>
#include <sys/types.h>

#define PROT_READ       0x1
#define PROT_WRITE      0x2
#define PROT_EXEC       0x4

#define MAP_SHARED      0x01
#define MAP_PRIVATE     0x02
#define MAP_ANONYMOUS	0x20
#define MAP_ANON	MAP_ANONYMOUS
#define MAP_FAILED	((void *)-1)

#define MADV_NORMAL     0
#define MADV_RANDOM     1
#define MADV_SEQUENTIAL 2
#define MADV_WILLNEED   3
#define MADV_DONTNEED   4
#define MADV_FREE       8

#ifndef BPF_NO_SYSCALL
void* mmap(size_t length, int prot, int flags, int fd, uint64_t offset);
int munmap(void* addr, size_t length);
int mprotect(void *addr, size_t len, int prot);
int madvise(void *addr, size_t length, int advice);
#endif

#endif
