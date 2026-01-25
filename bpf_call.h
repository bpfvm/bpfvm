//
// Created by chouryzhou on 24-11-1.
//

#ifndef BPF_CALL_H
#define BPF_CALL_H

#define BPF_CALL_MMAP      0x10001
#define BPF_CALL_MUNMAP    0x10002
#define BPF_CALL_EXIT      0x10003
#define BPF_CALL_GETTIMEOFDAY      0x10004
#define BPF_CALL_TIMES     0x10005
#define BPF_CALL_OPEN      0x10006
#define BPF_CALL_READ      0x10007
#define BPF_CALL_WRITE     0x10008
#define BPF_CALL_LSEEK     0x10009
#define BPF_CALL_CLOSE     0x1000A
#define BPF_CALL_UNLINK    0x1000B
#define BPF_CALL_RENAMEAT  0x1000C
#define BPF_CALL_READLINK  0x1000D
#define BPF_CALL_EXECVE    0x1000E
#define BPF_CALL_FORK      0x1000F
#define BPF_CALL_GETPID    0x10010
#define BPF_CALL_WAITPID   0x10011

#ifndef WNOHANG
#define WNOHANG 1
#endif

#endif //BPF_CALL_H
