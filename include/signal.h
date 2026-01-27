#ifndef SIGNAL_H
#define SIGNAL_H

#include <stdint.h>
#include <sys/types.h>

#ifndef SIGHUP
#define SIGHUP 1
#endif
#ifndef SIGINT
#define SIGINT 2
#endif
#ifndef SIGQUIT
#define SIGQUIT 3
#endif
#ifndef SIGILL
#define SIGILL 4
#endif
#ifndef SIGABRT
#define SIGABRT 6
#endif
#ifndef SIGFPE
#define SIGFPE 8
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef SIGSEGV
#define SIGSEGV 11
#endif
#ifndef SIGPIPE
#define SIGPIPE 13
#endif
#ifndef SIGTERM
#define SIGTERM 15
#endif
#ifndef SIGCHLD
#define SIGCHLD 17
#endif
#ifndef SIGCONT
#define SIGCONT 18
#endif
#ifndef SIGTSTP
#define SIGTSTP 20
#endif
#ifndef SIGTTIN
#define SIGTTIN 21
#endif
#ifndef SIGTTOU
#define SIGTTOU 22
#endif
#ifndef NSIG
#define NSIG 32
#endif

#ifndef SIG_DFL
#define SIG_DFL (void (*)(int))0
#endif
#ifndef SIG_ERR
#define SIG_ERR (void (*)(int))-1
#endif
#ifndef SIG_IGN
#define SIG_IGN (void (*)(int))1
#endif

typedef int sig_atomic_t;
typedef uint64_t sigset_t;
struct sigaction {
    void (*sa_handler)(int);
    sigset_t sa_mask;
    int sa_flags;
};

#ifndef SIG_SETMASK
#define SIG_SETMASK 2
#endif

#ifndef BPF_NO_SYSCALL
int sigaction(int signo, const struct sigaction *act, struct sigaction *oldact);
int kill(pid_t pid, int sig);

typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler);
int raise(int sig);
int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int sigsetmask(int mask);
int sigsuspend(const sigset_t *set);
extern const char *const sys_siglist[NSIG];
#endif

#endif
