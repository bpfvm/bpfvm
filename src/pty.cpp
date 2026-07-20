#define _GNU_SOURCE 1
#include "pty.h"
#include "insn.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <termios.h>
#include <pthread.h>
#include <poll.h>

// pump 线程职责（PTY/非 PTY 两种模式）：
//   宿主信号路由（两种模式都做）：signalfd(5 信号) 可读 -> sys->host_signal(pid1_vm, sig)。
//   PTY 字节转发（仅 has_real_pty）：
//     host stdin <-> pty master 双向转发 + SIGWINCH -> TIOCSWINSZ
struct PumpArg {
    Pty* self;
    SyscallHandler* sys;    // 信号路由桥：调 sys->host_signal
    vm* pid1_vm;            // host_signal 的目标 vm（pid 1）
};

// pump 线程处理的 5 个宿主信号（main 已进程级 block）。
static const int k_host_signals[] = {SIGINT, SIGQUIT, SIGTSTP, SIGHUP, SIGTERM};

static void* pump_thread_fn(void* raw) {
    auto* a = static_cast<PumpArg*>(raw);
    int& master_fd = a->self->master_fd();
    SyscallHandler* sys = a->sys;
    vm* pid1_vm = a->pid1_vm;
    delete a;

    // 宿主信号 signalfd：5 个信号 main 已进程级 block，这里只读。signalfd 要求对应信号
    // 在调用线程的 mask 里 block（与进程级 block 一致即可）。
    sigset_t smask;
    sigemptyset(&smask);
    for(int s : k_host_signals) sigaddset(&smask, s);

    int efd = epoll_create1(EPOLL_CLOEXEC);
    if(efd < 0) {
        return nullptr;
    }
    epoll_event ev{};
    ev.events = EPOLLIN | EPOLLRDHUP;

    if(master_fd >= 0) {
        ev.data.fd = STDIN_FILENO;
        epoll_ctl(efd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);

        ev.data.fd = master_fd;
        epoll_ctl(efd, EPOLL_CTL_ADD, master_fd, &ev);

        // SIGWINCH 经 signalfd 同步处理：block 后开 sfd 并注册。
        sigaddset(&smask, SIGWINCH);
    }

    int sig_sfd = signalfd(-1, &smask, SFD_CLOEXEC | SFD_NONBLOCK);
    ev.data.fd = sig_sfd;
    epoll_ctl(efd, EPOLL_CTL_ADD, sig_sfd, &ev);

    char buf[4096];
    while(true) {
        epoll_event events[4];
        int n = TEMP_FAILURE_RETRY(epoll_wait(efd, events, 4, -1));
        if(n < 0) break;
        bool has_error = false;
        for(int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if(events[i].events & (EPOLLHUP | EPOLLERR)){
                has_error = true;
                continue;
            }
            if(fd == sig_sfd && (events[i].events & EPOLLIN)) {
                signalfd_siginfo ssi;
                while(read(sig_sfd, &ssi, sizeof(ssi)) == sizeof(ssi)) {
                    if(ssi.ssi_signo == SIGWINCH) {
                        struct winsize ws;
                        if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
                            ioctl(master_fd, TIOCSWINSZ, &ws);
                        }
                    } else {
                        if(sys) sys->host_signal(pid1_vm, (int)ssi.ssi_signo);
                    }
                }
            } else if(fd == STDIN_FILENO && (events[i].events & (EPOLLIN | EPOLLRDHUP))) {
                // 仅 PTY 模式注册了 STDIN_FILENO（见上 epoll_ctl），非 PTY 不会进此分支。
                // 含 RDHUP：stdin 端断开（/dev/null、管道耗尽、真 tty 的 Ctrl+D…），
                // 此时 read 通常返回 0（EOF），走下面的 master 关闭路径把 EOF 透传给 guest。
                ssize_t r = TEMP_FAILURE_RETRY(read(STDIN_FILENO, buf, sizeof(buf)));
                if(r < 0) goto done;
                if(r == 0) {
                    close(master_fd);
                    master_fd = -1;
                    goto done;
                }
                ssize_t off = 0;
                while(off < r) {
                    ssize_t w = TEMP_FAILURE_RETRY(write(master_fd, buf + off, (size_t)(r - off)));
                    if(w < 0) break;
                    off += w;
                }
            } else if(fd == master_fd && (events[i].events & (EPOLLIN | EPOLLRDHUP))) {
                // 仅 PTY 模式注册了 master_fd。
                ssize_t r = TEMP_FAILURE_RETRY(read(master_fd, buf, sizeof(buf)));
                if(r <= 0) { goto done; }
                ssize_t off = 0;
                while(off < r) {
                    ssize_t w = TEMP_FAILURE_RETRY(write(STDOUT_FILENO, buf + off, (size_t)(r - off)));
                    if(w < 0) break;
                    off += w;
                }
            }
        }
        if(has_error) break;
    }

done:
    close(efd);
    if(sig_sfd >= 0) close(sig_sfd);
    return nullptr;
}

bool Pty::setup(bool enable_pty) {
    if(!enable_pty) {
        // 非 PTY 模式：不开真 pty，仅承载信号路由。master_fd_/slave_fd_ 保持 -1。
        return true;
    }
    // PTY 模式：开一对 host pty。master 给 pump，slave 给 guest fd 0/1/2。
    // canonical/echo 全在 host 内核的 n_tty（slave 侧），bpfvm 不写 ldisc。
    int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if(master < 0) {
        return false;
    }
    if(grantpt(master) < 0 || unlockpt(master) < 0) {
        close(master);
        return false;
    }
    char* slave_name = ptsname(master);
    if(!slave_name) {
        close(master);
        return false;
    }
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if(slave < 0) {
        close(master);
        return false;
    }
    struct winsize ws;
    if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        ioctl(master, TIOCSWINSZ, &ws);
    }
    // 必须关掉宿主 STDIN 自身的本地回显，否则同一行被宿主终端与 pty slave 各回显一次
    // 同时关 ICANON——slave 已是 canonical，宿主侧再分行会吞掉原始按键（如方向键）使 slave 收不到。
    // 刻意保留 ISIG：Ctrl-C/C-Z 等仍由宿主内核生成信号；host pty slave 的 fg_pgrp 恒为 0
    if(tcgetattr(STDIN_FILENO, &saved_tio_) == 0) {
        tio_saved_ = true;
        struct termios raw = saved_tio_;
        raw.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL | ICANON);
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    }
    master_fd_ = master;
    slave_fd_ = slave;
    return true;
}

int Pty::take_slave_fd() {
    int s = slave_fd_;
    slave_fd_ = -1;  // 所有权移交给调用方
    return s;
}

void Pty::start_pump(SyscallHandler* sys, vm* pid1_vm) {
    if(pump_thread_) return;
    auto* arg = new PumpArg{this, sys, pid1_vm};
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&pump_thread_, &attr, pump_thread_fn, arg);
    pthread_attr_destroy(&attr);
    if(rc != 0) {
        delete arg;
        return;
    }
}

Pty::~Pty() {
    // pump 线程 detached：~Pty 在 vm 析构（main 返回时）触发，进程即将退出，无需 join。
    // pty 不会在 run() 期间提前释放（它由 vm->options 持有，与 vm 同生命周期）。
    if(master_fd_ >= 0) {
        close(master_fd_);
        master_fd_ = -1;
    }
    if(slave_fd_ >= 0) {
        close(slave_fd_);
        slave_fd_ = -1;
    }  // 未 take 的兜底
    // 恢复宿主 STDIN 的 termios（setup 时 PTY 模式 raw 化过）。
    if(tio_saved_) {
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_tio_);
        tio_saved_ = false;
    }
}
