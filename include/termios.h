#ifndef _BPF_TERMIOS_H
#define _BPF_TERMIOS_H

#include <sys/types.h>

typedef unsigned int tcflag_t;

struct termios {
    tcflag_t c_lflag;
};

#define ICANON 0x0002
#define TCGETS 0x5401

#endif
