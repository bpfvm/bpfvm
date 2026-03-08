#ifndef POSIX_SYSCALL_H__
#define POSIX_SYSCALL_H__
#include "insn.h"

#include <unordered_map>
#include <array>

struct fd_handle {
    const int fd = -1;
    bool cloexec = false;
    std::string path;
    explicit fd_handle(int fd, std::string path = {}) : fd(fd), path(std::move(path)) {}
    ~fd_handle();
};

class MpscQueue {
    struct slot {
        std::atomic<uint64_t> seq;
        int value = 0;
    };
    static constexpr size_t k_capacity = 1024;
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
    std::string cwd;
    uint32_t umask_val = 0022;
    std::unordered_map<int, std::shared_ptr<fd_handle>> fds;

    static std::atomic<uint64_t> next_pid;
    static std::unordered_map<uint64_t, std::shared_ptr<vm>> pid_map;
    static std::mutex pid_map_mutex;
    uint64_t pid = 0;
    std::atomic<uint64_t> ppid{0};
    pthread_t tid = 0;
    std::array<signal_action, NSIG> signal_actions{};
    MpscQueue pending_signals;

    virtual void init(const std::shared_ptr<vm>& v) override;
    virtual void queue_signal(vm* v, int sig) override;
    virtual bool handle_signals(vm* v) override;
    virtual bool syscall(vm* v, uint32_t call) override;
    virtual int id() override {
        return (int)pid;
    }
    static std::shared_ptr<PosixSyscall> sys(vm* v_);
public:
    PosixSyscall();
    PosixSyscall(uint64_t ppid, const std::unordered_map<int, std::shared_ptr<fd_handle>>& opened, std::string cwd);

    int allocate_fd(int min_fd = 0);
    bool read_c_string(vm* v, uint64_t addr, std::string& out, size_t max_len);
    bool read_c_string_array(vm* v, uint64_t addr, std::vector<std::string>& out, size_t max_count, size_t max_str_len);
    std::string resolve_path(const std::string& path);

    bool do_clock_gettime(vm* v);
    bool do_mmap(vm* v);
    bool do_munmap(vm* v);
    bool do_exit(vm* v);
    bool do_nanosleep(vm* v);
    bool do_openat(vm* v);
    bool do_read(vm* v);
    bool do_write(vm* v);
    bool do_lseek(vm* v);
    bool do_truncate(vm* v);
    bool do_ftruncate(vm* v);
    bool do_close(vm* v);
    bool do_unlinkat(vm* v);
    bool do_mkdir(vm* v);
    bool do_rmdir(vm* v);
    bool do_symlinkat(vm* v);
    bool do_linkat(vm* v);
    bool do_renameat(vm* v);
    bool do_readlink(vm* v);
    bool do_execve(vm* v);
    bool do_fork(vm* v);
    bool do_getpid(vm* v);
    bool do_getppid(vm* v);
    bool do_waitpid(vm* v);
    bool do_dup(vm* v);
    bool do_dup2(vm* v);
    bool do_pipe2(vm* v);
    bool do_fchdir(vm* v);
    bool do_getcwd(vm* v);
    bool do_fdopendir(vm* v);
    bool do_readdir(vm* v);
    bool do_closedir(vm* v);
    bool do_fstatat(vm* v);
    bool do_fchmodat(vm* v);
    bool do_utimensat(vm* v);
    bool do_faccessat(vm* v);
    bool do_kill(vm* v);
    bool do_sigaction(vm* v);
    bool do_fcntl(vm* v);
    bool do_ioctl(vm* v);
    bool do_umask(vm* v);
    bool do_setjmp(vm* v);
    bool do_longjmp(vm* v);
};

#endif
