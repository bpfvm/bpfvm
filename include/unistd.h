#ifndef UNISTD_H
#define UNISTD_H

#include <stdint.h>
#include <time.h>
#include <sys/types.h>

#ifndef BPF_NO_SYSCALL
__attribute__((noreturn)) void _exit(int status);
int execve(const char* pathname, char* const argv[], char* const envp[]);
int dup(int fd);
int dup2(int oldfd, int newfd);
int pipe(int pipefd[2]);
int pipe2(int pipefd[2], int flags);
int close(int fd);
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
int unlink(const char *pathname);
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
int readlink(const char *pathname, char *buf, size_t bufsiz);

pid_t getpid(void);
pid_t getppid(void);
int fork(void);
int vfork(void);
int waitpid(int pid, int *status, int options);
int chdir(const char *path);
char *getcwd(char *buf, size_t size);
int isatty(int fd);
uid_t getuid(void);
uid_t geteuid(void);
gid_t getgid(void);
gid_t getegid(void);
int getgroups(int size, gid_t list[]);

#endif

#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4


#endif
