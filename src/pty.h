#ifndef PTY_H__
#define PTY_H__

#include <atomic>
#include <pthread.h>
#include <termios.h>
#include <errno.h>      // EINTR（TEMP_FAILURE_RETRY 用）

class vm;
class SyscallHandler;

// TEMP_FAILURE_RETRY：glibc 的 <unistd.h> 扩展（非 POSIX，非 UAPI），musl 不提供。
// 仅 bpfvm 自身 pty 模块用（pump 线程的 EINTR 自动重试），不对外暴露给 guest，
// 故放本模块头而非 include/。host glibc 已定义时 #ifndef 守护跳过。
#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression) \
    (__extension__({ long int __result; \
       do __result = (long int)(expression); \
       while(__result == -1L && errno == EINTR); \
       __result; }))
#endif

// host 接入器 + 信号路由器。两类职责，统一由 pump 线程承载：
//
// 1) PTY 字节转发（enable_pty=true）：开一对 host pty（posix_openpt），host stdin/stdout
//    经 pump 纯转发到 pty master；guest fd 0/1/2 用 pty slave 包裹。canonical/echo/termios
//    全交 host 内核的 n_tty，bpfvm 不实现 ldisc。
// 2) 宿主信号路由（两种模式都做）：SIGINT/SIGQUIT/SIGTSTP/SIGHUP/SIGTERM 经 main 进程级
//    block 后只排队到 signalfd，pump 线程读出后调 sys->host_signal()，在普通线程上下文
//    完成 guest 侧路由（摆脱 async-signal-safe 约束）。
//
// 非 PTY 模式（enable_pty=false）：不开真 pty，pump 退化为仅 epoll signalfd 做信号路由。
// 无论哪种模式都必须起 pump 线程——否则被 block 的宿主信号无消费者会永久 pending。
//
// 本类不感知 guest 进程语义（session/ctty/前台组）；路由决策交给 SyscallHandler。
class Pty {
    pthread_t pump_thread_ = 0;
    int master_fd_ = -1;             // pump 用的 host pty master（<0 = 非 PTY 模式）
    int slave_fd_ = -1;              // 给 guest fd 0/1/2 的 host pty slave
    bool tio_saved_ = false;         // 宿主 STDIN 原 termios 是否已保存（setup 时 raw 化）
    struct termios saved_tio_{};     // 宿主 STDIN 原 termios，~Pty 恢复

public:
    Pty() = default;
    ~Pty();

    Pty(const Pty&) = delete;
    Pty& operator=(const Pty&) = delete;

    // 开一对 host pty（enable_pty=true）或仅初始化信号路由形态（false，不开真 pty）。
    // enable_pty=false 时恒成功；true 时 posix_openpt 失败返回 false。
    bool setup(bool enable_pty);

    // 用于判断是否开了真 pty（master >= 0）。init(pid==1) 据此决定 fd 0/1/2 播种方式。
    int& master_fd() { return master_fd_; }

    // init(pid==1) 调用：取走 slave fd（只允许一次）。master 留给 pump。
    // 仅 master_fd >= 0 时有意义。返回 host slave fd。
    int take_slave_fd();

    // 起 pump 线程（joinable）。须在 take_slave_fd 之后调用。
    // sys/vm 为信号路由的桥：pump 线程读出 signalfd 后调 sys->host_signal(vm, sig)。
    void start_pump(SyscallHandler* sys, vm* pid1_vm);
};

#endif
