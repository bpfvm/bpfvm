#ifndef SYS_IOCTL_H
#define SYS_IOCTL_H

struct winsize {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
};

#ifndef TIOCGWINSZ
#define TIOCGWINSZ 0x5413
#endif

#ifndef BPF_NO_SYSCALL
int ioctl(int fd, unsigned long request, void *arg);
#endif

#endif
