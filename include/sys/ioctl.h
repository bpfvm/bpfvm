#ifndef SYS_IOCTL_H
#define SYS_IOCTL_H

#ifndef BPF_NO_SYSCALL
int ioctl(int fd, unsigned long request, void *arg);
#endif

#endif
