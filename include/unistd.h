#ifndef UNISTD_H
#define UNISTD_H

#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <stdarg.h>

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2


#ifndef BPF_NO_SYSCALL
__attribute__((noreturn)) void _exit(int status);
int execve(const char* pathname, char* const argv[], char* const envp[]);
int execvp(const char *file, char *const argv[]);
int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);

int _execl(const char *path, _PDCLIB_va_list ap);
int _execle(const char *path, _PDCLIB_va_list ap);
int _execlp(const char *file, _PDCLIB_va_list ap);

#define execl(path, ...) ({ \
    PDCLIB_MAKE_VA_LIST(ap, ##__VA_ARGS__); \
    _execl(path, ap); \
})

#define execle(path, ...) ({ \
    PDCLIB_MAKE_VA_LIST(ap, ##__VA_ARGS__); \
    _execle(path, ap); \
})

#define execlp(file, ...) ({ \
    PDCLIB_MAKE_VA_LIST(ap, ##__VA_ARGS__); \
    _execlp(file, ap); \
})

int dup(int fd);
int dup2(int oldfd, int newfd);
int pipe(int pipefd[2]);
int pipe2(int pipefd[2], int flags);
int close(int fd);
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
int unlink(const char *pathname);
int unlinkat(int dirfd, const char *pathname, int flags);
int rmdir(const char *pathname);
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
int readlink(const char *pathname, char *buf, size_t bufsiz);
int symlink(const char *target, const char *linkpath);
int symlinkat(const char *target, int newdirfd, const char *linkpath);
int link(const char *oldpath, const char *newpath);
int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);

pid_t getpid(void);
pid_t getppid(void);
int fork(void);
int vfork(void);
int waitpid(int pid, int *status, int options);
pid_t wait(int *status);
int chdir(const char *path);
char *getcwd(char *buf, size_t size);
int isatty(int fd);
uid_t getuid(void);
uid_t geteuid(void);
gid_t getgid(void);
gid_t getegid(void);
int getgroups(int size, gid_t list[]);

int access(const char *pathname, int mode);
int faccessat(int dirfd, const char *pathname, int mode, int flags);

#endif

#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4

#define _SC_LOGIN_NAME_MAX 256

#endif
