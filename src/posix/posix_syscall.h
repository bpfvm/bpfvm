#ifndef POSIX_SYSCALL_H__
#define POSIX_SYSCALL_H__
#include "insn.h"

#include <unordered_map>
#include <array>
#include <memory>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <unistd.h>

#define BPF_SIGNAL_QUE_SIZE 1024

// pty master 端的共享 token。fd_handle 持有它的 shared_ptr，use_count 即 master fd 引用数
// （对应内核 master tty_struct::count）。归零（drop_fd_handle 里 use_count()==1 判断，
// erase 析构后）触发 SIGHUP。slave fd 不持有 PtySide——slave 关闭不发 SIGHUP，故无需计数。
struct PtySide {};

struct GuestTty;
struct fd_handle {
    const int fd = -1;
    bool cloexec = false;
    std::string path;
    // 非空表示本 fd 是某 pty 设备的一端（master/slave）；空表示普通文件/pipe/socket。
    // dup/fork 后多份 fd 共享同一 GuestTty
    std::shared_ptr<GuestTty> tty;
    // 仅 master fd 设此字段（多个 master fd 副本共享同一 PtySide，use_count = master fd 数）；
    std::shared_ptr<PtySide> master_token;
    explicit fd_handle(int fd_, std::string path_ = {}, std::shared_ptr<GuestTty> t = {},
                       std::shared_ptr<PtySide> m = {})
        : fd(fd_), path(std::move(path_)), tty(std::move(t)), master_token(std::move(m)) {}
    ~fd_handle(){ if(fd >= 0) close(fd); }
    // 复制本 fd 句柄（dup/dup2/fork 用）：host dup 得独立 host fd
    // 不复制 cloexec（由调用方按需设置）。失败返回 nullptr。
    std::shared_ptr<fd_handle> clone() const {
        int new_fd = ::dup(fd);
        if(new_fd < 0) return nullptr;
        return std::make_shared<fd_handle>(new_fd, path, tty, master_token);
    }
    bool is_tty() const { return tty != nullptr || ::isatty(fd) == 1; }
};

// guest tty 设备的 bpfvm 侧状态。
// 本对象只持有 bpfvm 必须管的进程语义：
//   fg_pgrp  —— 本设备当前前台进程组。tty 信号（SIGINT/SIGTSTP/...）发给 fg_pgrp 的所有成员。
//   owner_   —— 当前归属 session（裸指针，不参与生命周期：TIOCSCTTY 抢夺判定用）。
struct Session;
struct GuestTty {
    std::atomic<uint64_t> fg_pgrp{0};
    Session* owner_ = nullptr;
    GuestTty() = default;
};

// 会话（session）：setsid 创建，sid == leader->pid。
// 持有控制终端 ctty（shared_ptr<GuestTty>，nullptr = 无 ctty）。前台组挂在 GuestTty 上。
struct Session {
    uint64_t sid;
    std::shared_ptr<GuestTty> ctty;   // 控制终端；setsid 后置 nullptr（脱离），TIOCSCTTY 绑定
    explicit Session(uint64_t sid) : sid(sid) {}
};

// 进程组（process group）：setpgid/setsid 创建/修改，pgid == leader->pid。
// 同 pgid 必同 session。多个 task 通过 shared_ptr 共享同一 ProcessGroup 对象；
// setpgid 替换 shared_ptr 即"离组加组"，无需通知旧组。
struct ProcessGroup {
    uint64_t pgid;
    std::shared_ptr<Session> session;
    ProcessGroup(uint64_t pgid, std::shared_ptr<Session> session)
        : pgid(pgid), session(std::move(session)) {}
};

// 线程组生命周期状态（CLONE_THREAD 共享；fork 新建）。
// tgid = leader 的 tid。live_threads 归 0 时进程可被 waitpid 回收。
struct ThreadGroup {
    uint64_t tgid;
    std::atomic<size_t> live_threads{1};
    std::atomic<bool> exited{false};
    // 整组对外报告的退出码（waitpid 读此值）。初值 -1 = 未设。
    // exit/exit_group/被信号杀（走 do_exit）均用 CAS(-1->code) 写入：首个正常退出者
    // 赢，后续不覆盖。被 exit_group 置 VM_KILLED 的线程不走 do_exit，fini 里不碰此值，
    // 故不会覆盖 winner 设的码。last 线程 fini 时若仍为 -1（整组无人正常退出，理论上
    // 不会发生——置 VM_KILLED 的调用方必先走过 do_exit_group），兜底置 137。
    std::atomic<int> exit_code{-1};
    // —— job-control 停止状态（thread-group 级，整组一致）——
    // stop 是进程级语义：SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU 停止整个线程组，故状态放tg而非vm
    // stopped       —— 整组处于停止态（waitpid WUNTRACED 查此位）
    // stop_sig      —— 停止信号号（WSTOPSIG 用；musl WIFSTOPPED 要求 status 低字节 0x7f、
    //                  高字节为信号号）
    // stop_reported —— SIGCHLD 去重：停止后给父进程投一次 SIGCHLD 后置 true，waitpid
    //                  消费（报告 WIFSTOPPED）后清零，使下次停止能再投。避免重复通知。
    std::atomic<bool> stopped{false};
    std::atomic<int>  stop_sig{-1};
    std::atomic<bool> stop_reported{false};
    std::mutex mtx;
    std::condition_variable cv;
    std::vector<std::weak_ptr<vm>> threads;
    explicit ThreadGroup(uint64_t t) : tgid(t) {}
};

class MpscQueue {
    struct slot {
        std::atomic<uint64_t> seq;
        int value = 0;
    };
    static constexpr size_t k_capacity = BPF_SIGNAL_QUE_SIZE;
    static constexpr size_t k_mask = k_capacity - 1;
    static_assert((k_capacity & (k_capacity - 1)) == 0, "k_capacity must be power of two");
    std::array<slot, k_capacity> slots{};
    std::atomic<uint64_t> head{0};
    std::atomic<uint64_t> tail{0};
public:
    MpscQueue();
    bool try_push(int value);
    bool try_pop(int& value);
    bool empty() const {
        return head.load(std::memory_order_relaxed) == tail.load(std::memory_order_relaxed);
    }
};

#ifndef NSIG
#define NSIG 32
#endif

class PosixSyscall: public SyscallHandler{
    struct signal_action {
        uint64_t handler = 0;
        uint64_t mask = 0;
        int flags = 0;
    };

    // CLONE_THREAD / CLONE_FILES / CLONE_SIGHAND / CLONE_FS 共享的进程级状态。
    // CLONE_THREAD: 整体共享。fork: 整体拷贝（make_shared + 复制内容）。
    struct SharedState {
        std::string cwd;
        std::unordered_map<int, std::shared_ptr<fd_handle>> fds;
        std::array<signal_action, NSIG> signal_actions{};
        // chroot 根目录（宿主绝对路径，无尾斜杠）。空 = 不 chroot。
        // 随 fork/clone 自动传播（与 cwd 同级）。ps->cwd 存 guest 视角路径，
        // resolve_path 负责 cwd → 宿主路径时拼上此 root。
        std::string root;
    };

    uint32_t umask_val = 0022;
    std::shared_ptr<SharedState> ps = std::make_shared<SharedState>();

    static std::atomic<uint64_t> next_pid;
    static std::unordered_map<uint64_t, std::shared_ptr<vm>> pid_map;
    static std::mutex pid_map_mutex;
    // ptmx 注册表：guest open("/dev/ptmx") 合成的 host pty，按 pts 编号(=TIOCGPTN 返回值)
    // 索引到 GuestTty。后续 open("/dev/pts/N") 用 N 查此表，复用同一 GuestTty。
    static std::unordered_map<int, std::shared_ptr<GuestTty>> ptmx_registry;
    static std::mutex ptmx_registry_mutex;
    uint64_t pid = 0;          // task id（== tid）。gettid 返回此值。
    std::shared_ptr<ThreadGroup> tg;  // 线程组生命周期（CLONE_THREAD 共享；fork 新建）。
    std::atomic<uint64_t> ppid{0};
    pthread_t tid = 0;
    // 信号掩码（POSIX sigprocmask）：bit (sig-1) 表示信号 sig 被阻塞（与 Linux 内核/
    // musl sigset_t ABI 一致）。SIGKILL/SIGSTOP 不可阻塞（do_sigprocmask 强制清对应位）。
    // 仅在 handle_signals 投递端过滤；queue_signal 无条件入队，被阻塞的信号留在
    // pending_signals 里，解锁后 safepoint 重扫时自然投出（实时信号统一模型）。
    std::atomic<uint64_t> sigmask{0};
    MpscQueue pending_signals;
    // set_tid_address / CLONE_CHILD_CLEARTID 设置；线程退出时清零并 futex_wake。
    uint64_t tid_address_ = 0;
    // 进程组/会话。fork 继承父的 shared_ptr（共享同一对象）；setpgid/setsid 替换为新对象。
    std::shared_ptr<ProcessGroup> pgrp;
    std::shared_ptr<Session> session;

    // 信号默认动作判定：是否为"可忽略"信号——即 SIG_IGN，或 SIG_DFL 且默认动作为
    // Ign(SIGCHLD/SIGURG/SIGWINCH)/Cont(SIGCONT)。这类信号投递给进程不会改变其状态，
    // 也不会打断阻塞中的系统调用（对齐 Linux：get_signal 不让 Ign/Cont 信号产生 EINTR）。
    // SIGKILL/SIGSTOP 调用方已特判，不会进入此函数。
    bool signal_ignorable(int sig);
    // 把信号投给指定 vm 的内部接口
    void queue_signal(vm* v, int sig);
    // 停止整个线程组（SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU）：设 tg 级停止状态 + 组内每线程
    // VM_STOPPED + 给父进程投一次 SIGCHLD（去重）。stop 是进程级，整组一致
    void stop_process(int sig);
    // 给父进程（ppid 指向的 vm）投 SIGCHLD。find_task(ppid) 取父 vm → sys()->queue_signal。
    // 父进程可能是 EmptySyscall（测试）或已退出，此时降级为 no-op。
    void notify_parent_sigchld();
    // 向控制终端的前台进程组（tty->fg_pgrp）投递 tty 信号。tty==nullptr 时退化为按
    // 调用者 session 选目标组。host_signal（宿主→guest 路由）与 do_close 的 pty master
    // 关闭发 SIGHUP（对齐 Linux tty_vhangup 语义）共用此路径。
    void deliver_to_ctty_fg(vm* v, GuestTty* tty, int sig);
    // 销毁一个 fd_handle 前的 master SIGHUP 处理：若是 master 端且是最后一个引用
    // （side.use_count()==1），向 ctty 前台组投 SIGHUP。所有 fd 销毁路径（do_close、
    // dup3 覆盖、execve cloexec 丢弃、fini 退出）统一调此函数，避免重复实现。返回后
    // 调用方再 erase 析构（side shared_ptr 自动 -1）。
    void drop_fd_handle(vm* v, const std::shared_ptr<fd_handle>& h);

    virtual void init(const std::shared_ptr<vm>& v) override;
    virtual void fini(const std::shared_ptr<vm>& v) override;
    virtual bool handle_signals(vm* v) override;
    virtual int64_t syscall(vm* v, uint32_t call) override;
    virtual int id() override {
        return (int)pid;
    }
    static std::shared_ptr<PosixSyscall> sys(vm* v_);
    static std::shared_ptr<vm> find_task(uint64_t target_pid);
    // futex 实现：等待者阻塞在 vm 自身 wait_cv 上，由 VM_BLOCKED 标志协调唤醒。
    // 见 posix/futex.cpp 中 futex_wait/futex_wake。
    static int futex_wait(vm* v, ThreadGroup* tg, uint64_t addr, uint32_t val,
                          const struct timespec* timeout);
    static int futex_wake(ThreadGroup* tg, uint64_t addr, int val);
public:
    PosixSyscall();
    PosixSyscall(uint64_t ppid, std::shared_ptr<ProcessGroup> pgrp, std::shared_ptr<Session> session);

    int allocate_fd(int min_fd = 0);
    bool read_c_string(vm* v, uint64_t addr, std::string& out, size_t max_len);
    bool read_c_string_array(vm* v, uint64_t addr, std::vector<std::string>& out, size_t max_count, size_t max_str_len);
    std::string resolve_path(const std::string& path);
    // 把任意 guest 路径（相对则用 cwd）规范化为 guest 视角的绝对路径（不拼 root 前缀）。
    // 用于 fd_handle::path 存储与特殊设备（/dev/ptmx 等）匹配 —— 这些都应基于 guest 命名空间。
    std::string guest_abs_path(const std::string& path);

    // 宿主侧信号（物理终端 ^C/^Z/^\ / 终端挂断 / 外部 kill 给 bpfvm）转交 handler 路由。
    // 凭本 handler 掌握的 session/ctty/前台组决定目标：有控制终端->发到 ctty 的前台
    // 进程组所有成员（tty 信号语义）；无 ctty->退化为投给该 vm 自身。
    virtual void host_signal(vm* v, int sig) override;

    // job-control 门控：检查对 fd 的后台 tty 访问是否需要投 SIGTTIN(read)/SIGTTOU(write)。
    // 返回 nullopt 表示放行真正 I/O；返回非空表示已拦截（已投信号），其值即 syscall 返回值。
    // 仅当 fd 是本 session ctty 且调用者非前台组时触发。
    std::optional<int64_t> tty_bg_check(vm* v, const std::shared_ptr<fd_handle>& fd, bool is_read);

    int64_t do_clock_gettime(vm* v);
    int64_t do_mmap(vm* v);
    int64_t do_munmap(vm* v);
    int64_t do_exit(vm* v);
    int64_t do_nanosleep(vm* v);
    int64_t do_openat(vm* v);
    int64_t do_read(vm* v);
    int64_t do_write(vm* v);
    int64_t do_lseek(vm* v);
    int64_t do_truncate(vm* v);
    int64_t do_ftruncate(vm* v);
    int64_t do_close(vm* v);
    int64_t do_unlinkat(vm* v);
    int64_t do_mkdirat(vm* v);
    int64_t do_symlinkat(vm* v);
    int64_t do_linkat(vm* v);
    int64_t do_renameat2(vm* v);
    int64_t do_readlinkat(vm* v);
    int64_t do_execve(vm* v);
    int64_t do_clone(vm* v);
    int64_t do_getpid(vm*);
    int64_t do_getppid(vm*);
    int64_t do_waitpid(vm* v);
    int64_t do_dup(vm* v);
    int64_t do_dup3(vm* v);
    int64_t do_pipe2(vm* v);
    int64_t do_fchdir(vm* v);
    int64_t do_getcwd(vm* v);
    int64_t do_statx(vm* v);
    int64_t do_fchmodat(vm* v);
    int64_t do_utimensat(vm* v);
    int64_t do_faccessat(vm* v);
    int64_t do_kill(vm* v);
    int64_t do_tkill(vm* v);
    int64_t do_tgkill(vm* v);
    int64_t do_sigaction(vm* v);
    int64_t do_sigprocmask(vm* v);
    int64_t do_setpgid(vm* v);
    int64_t do_getpgid(vm* v);
    int64_t do_getpgrp(vm*);
    int64_t do_setsid(vm*);
    int64_t do_getsid(vm* v);
    int64_t do_fcntl(vm* v);
    int64_t do_ioctl(vm* v);
    int64_t do_umask(vm* v);
    int64_t do_sigsetjmp(vm* v);
    int64_t do_siglongjmp(vm* v);
    int64_t do_mprotect(vm* v);
    int64_t do_readv(vm* v);
    int64_t do_writev(vm* v);
    int64_t do_pread(vm* v);
    int64_t do_pwrite(vm* v);
    int64_t do_getrandom(vm* v);
    int64_t do_getdents64(vm* v);
    int64_t do_set_tid_address(vm* v);
    int64_t do_exit_group(vm* v);
    int64_t do_madvise(vm*);
    int64_t do_sched_yield(vm*);
    int64_t do_gettid(vm*);
    int64_t do_set_tls(vm* v);
    int64_t do_get_tls(vm* v);
    int64_t do_futex(vm* v);
    int64_t do_alloca(vm* v);
    int64_t do_poll(vm* v);
};

#endif
