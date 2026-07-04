#ifndef POSIX_SYSCALL_H__
#define POSIX_SYSCALL_H__
#include "insn.h"

#include <unordered_map>
#include <array>
#include <memory>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <unistd.h>

#define BPF_SIGNAL_QUE_SIZE 1024

struct GuestTty;
struct fd_handle {
    const int fd = -1;
    bool cloexec = false;
    std::string path;
    // 非空表示本 fd 是某 pty 设备的一端（master/slave）；空表示普通文件/pipe/socket。
    // dup/fork 后多份 fd 共享同一 GuestTty
    std::shared_ptr<GuestTty> tty;
    explicit fd_handle(int fd_, std::string path_ = {}, std::shared_ptr<GuestTty> t = {})
        : fd(fd_), path(std::move(path_)), tty(std::move(t)) {}
    ~fd_handle(){ if(fd >= 0) close(fd); }
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

    // 把信号投给指定 vm 的内部接口
    void queue_signal(vm* v, int sig);
    // 停止整个线程组（SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU）：设 tg 级停止状态 + 组内每线程
    // VM_STOPPED + 给父进程投一次 SIGCHLD（去重）。stop 是进程级，整组一致
    void stop_process(int sig);
    // 给父进程（ppid 指向的 vm）投 SIGCHLD。find_task(ppid) 取父 vm → sys()->queue_signal。
    // 父进程可能是 EmptySyscall（测试）或已退出，此时降级为 no-op。
    void notify_parent_sigchld();

    virtual void init(const std::shared_ptr<vm>& v) override;
    virtual void fini(const std::shared_ptr<vm>& v) override;
    virtual bool handle_signals(vm* v) override;
    virtual bool syscall(vm* v, uint32_t call) override;
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
    PosixSyscall(uint64_t ppid, const std::unordered_map<int, std::shared_ptr<fd_handle>>& opened, std::string cwd,
                 std::shared_ptr<ProcessGroup> pgrp, std::shared_ptr<Session> session);

    int allocate_fd(int min_fd = 0);
    bool read_c_string(vm* v, uint64_t addr, std::string& out, size_t max_len);
    bool read_c_string_array(vm* v, uint64_t addr, std::vector<std::string>& out, size_t max_count, size_t max_str_len);
    std::string resolve_path(const std::string& path);

    // 宿主侧信号（物理终端 ^C/^Z/^\ / 终端挂断 / 外部 kill 给 bpfvm）转交 handler 路由。
    // 凭本 handler 掌握的 session/ctty/前台组决定目标：有控制终端->发到 ctty 的前台
    // 进程组所有成员（tty 信号语义）；无 ctty->退化为投给该 vm 自身。
    virtual void host_signal(vm* v, int sig) override;

    bool do_clock_gettime(vm* v);
    bool do_mmap(vm* v);
    bool do_munmap(vm* v);
    bool do_exit(vm* v);
    bool do_nanosleep(vm* v);
    bool do_openat(vm* v);
    // job-control 门控：检查对 fd 的后台 tty 访问是否需要投 SIGTTIN(read)/SIGTTOU(write)。
    // 返回 true 表示已处理（已投信号并按 POSIX 设好 r(0)，调用方直接 return true）；
    // false 表示放行。仅当 fd 是本 session ctty 且调用者非前台组时触发。
    bool tty_bg_check(vm* v, const std::shared_ptr<fd_handle>& fd, bool is_read);
    bool do_read(vm* v);
    bool do_write(vm* v);
    bool do_lseek(vm* v);
    bool do_truncate(vm* v);
    bool do_ftruncate(vm* v);
    bool do_close(vm* v);
    bool do_unlinkat(vm* v);
    bool do_mkdirat(vm* v);
    bool do_symlinkat(vm* v);
    bool do_linkat(vm* v);
    bool do_renameat2(vm* v);
    bool do_readlinkat(vm* v);
    bool do_execve(vm* v);
    bool do_clone(vm* v);
    bool do_getpid(vm* v);
    bool do_getppid(vm* v);
    bool do_waitpid(vm* v);
    bool do_dup(vm* v);
    bool do_dup3(vm* v);
    bool do_pipe2(vm* v);
    bool do_fchdir(vm* v);
    bool do_getcwd(vm* v);
    bool do_statx(vm* v);
    bool do_fchmodat(vm* v);
    bool do_utimensat(vm* v);
    bool do_faccessat(vm* v);
    bool do_kill(vm* v);
    bool do_tkill(vm* v);
    bool do_tgkill(vm* v);
    bool do_sigaction(vm* v);
    bool do_sigprocmask(vm* v);
    bool do_setpgid(vm* v);
    bool do_getpgid(vm* v);
    bool do_getpgrp(vm* v);
    bool do_setsid(vm* v);
    bool do_getsid(vm* v);
    bool do_fcntl(vm* v);
    bool do_ioctl(vm* v);
    bool do_umask(vm* v);
    bool do_setjmp(vm* v);
    bool do_longjmp(vm* v);
    bool do_mprotect(vm* v);
    bool do_readv(vm* v);
    bool do_writev(vm* v);
    bool do_pread(vm* v);
    bool do_pwrite(vm* v);
    bool do_getrandom(vm* v);
    bool do_getdents64(vm* v);
    bool do_set_tid_address(vm* v);
    bool do_exit_group(vm* v);
    bool do_madvise(vm* v);
    bool do_sched_yield(vm* v);
    bool do_gettid(vm* v);
    bool do_set_tls(vm* v);
    bool do_get_tls(vm* v);
    bool do_futex(vm* v);
};

#endif
