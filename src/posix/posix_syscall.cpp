#include "posix_internal.h"
#include "pty.h"

std::atomic<uint64_t> PosixSyscall::next_pid{1};
std::unordered_map<uint64_t, std::shared_ptr<vm>> PosixSyscall::pid_map{};
std::mutex PosixSyscall::pid_map_mutex;
std::unordered_map<int, std::shared_ptr<GuestTty>> PosixSyscall::ptmx_registry{};
std::mutex PosixSyscall::ptmx_registry_mutex{};

PosixSyscall::PosixSyscall() {
    pid = next_pid.fetch_add(1);
    tg = std::make_shared<ThreadGroup>(pid);
    // guest fd 0/1/2 在 init(pid==1) 内播种（构造函数拿不到 vm/options）；fork/clone 子进程
    // 经带参构造函数注入 fds，不走此路径。

    char buf[PATH_MAX];
    if(::getcwd(buf, sizeof(buf)) != nullptr) {
        ps->cwd = buf;
    } else {
        ps->cwd = "/";
    }
    // pid 1 自成会话 leader + 进程组 leader。
    session = std::make_shared<Session>(pid);
    pgrp = std::make_shared<ProcessGroup>(pid, session);
}

PosixSyscall::PosixSyscall(uint64_t ppid, const std::unordered_map<int, std::shared_ptr<fd_handle>>& opened, std::string cwd_,
                           std::shared_ptr<ProcessGroup> pgrp_, std::shared_ptr<Session> session_)
    : pgrp(std::move(pgrp_)), session(std::move(session_)) {
    pid = next_pid.fetch_add(1);
    tg = std::make_shared<ThreadGroup>(pid);
    this->ppid = ppid;
    ps->fds = opened;
    ps->cwd = cwd_;
    // 子进程经 fork 继承父的 pgrp/session（shared_ptr 共享同一对象），其控制终端由
    // session->ctty 表达（同样共享）。GuestTty随 fd 句柄的 tty 字段
    // 共享——fork 后子进程的 pty slave fd（fd_handle::clone）携带同一 GuestTty 引用。
}

void PosixSyscall::init(const std::shared_ptr<vm>& v){
    tid = pthread_self();
    // 只有 pid 1（主进程）在此注册自身：它没有父 task 替它 push 到 threads。
    // 其余 task（fork / clone 产生的子）由创建方在 do_fork / do_clone 持 tg->mtx 注册，
    // 避免子线程 host 尚未跑到 init() 时 leader 就 exit_group 漏杀它。
    if(pid == 1) {
        std::lock_guard<std::mutex> lock(tg->mtx);
        tg->threads.push_back(v);
    }
    std::lock_guard<std::mutex> lock(pid_map_mutex);
    //这里只对1号进程添加，其他进程由fork添加，因为推迟到这里就太晚了
    if(pid == 1) {
        pid_map[pid] = v;
        // guest fd 0/1/2 播种：PTY 模式取 Pty 的 slave fd 包成 fd_handle 并绑 ctty；否则 dup 宿主 stdio。
        // 注意：pump 线程由 main 在 vm->run() 前启动（host 接入职责），此处只消费 Pty 的 slave 产物
        // 做 guest 侧播种。测试（insn_test）不设 pty，nullptr 退化走 dup stdio。
        auto& pty = options(v.get()).pty;
        if(pty && pty->master_fd() >= 0) {
            int slave_fd = pty->take_slave_fd();
            auto tty = std::make_shared<GuestTty>();
            tty->owner_ = session.get();
            tty->fg_pgrp.store(pgrp->pgid);
            session->ctty = tty;
            auto mk = [&](int host_fd){ return std::make_shared<fd_handle>(host_fd, "", tty); };
            ps->fds.emplace(0, mk(dup(slave_fd)));
            ps->fds.emplace(1, mk(dup(slave_fd)));
            ps->fds.emplace(2, mk(dup(slave_fd)));
            close(slave_fd);
        } else {
            ps->fds.emplace(0, std::make_shared<fd_handle>(dup(STDIN_FILENO)));
            ps->fds.emplace(1, std::make_shared<fd_handle>(dup(STDOUT_FILENO)));
            ps->fds.emplace(2, std::make_shared<fd_handle>(dup(STDERR_FILENO)));
        }
    }
}

void PosixSyscall::fini(const std::shared_ptr<vm>& v) {
    // clear-child-tid：清零 *tid_address_ 并 futex_wake（musl pthread 退出依赖此机制）。
    // tid_address_ 是 CLONE_CHILD_CLEARTID 设的，指向 musl 的 __thread_list_lock（int），
    // musl __pthread_exit 不调 __tl_unlock，依赖此机制释放锁。
    auto clear_child_tid = [&]() {
        if(tid_address_ == 0) return;
        auto* ctid = static_cast<int*>(v->mmu_w(tid_address_, sizeof(int)));
        if(!ctid) return;
        // 持 futex 锁清零 *ctid + wake（实现见 futex.cpp）：避免与 futex_wait 的 *p
        // 检查产生 lost wakeup——futex_wait 在持锁时检查 *p==val 并注册进 waiters；
        // 这里持锁清零后摘一个等待者并 wakeup(true)，确保等待者要么看到 *p 已变（EAGAIN
        // 返回），要么被 wake 唤醒。
        futex_child_tid_clear(tg.get(), ctid, tid_address_);
    };
    clear_child_tid();

    // 线程组生命周期：减 live_threads，判定是否本组最后一个退出的线程。
    bool last = (tg->live_threads.fetch_sub(1, std::memory_order_acq_rel) == 1);

    // 本线程的信号上下文复位（与 last / pid_map 无关）。
    signal_depth(v.get()) = 0;

    // pid 1（init）不参与线程组清理，提前返回。
    if(pid == 1) {
        return;
    }

    // 释放本线程的地址空间引用：僵尸不再持地址空间。
    // 必须在 clear-child-tid（用 mmu_w 访问 maps）之后；本 vm 此后不再访存。
    maps_ptr(v.get()) = std::make_shared<std::list<memmap>>();

    // 非 leader 线程：从 pid_map 移除（不可 waitpid）。leader 留给 waitpid 回收。
    if(pid != tg->tgid) {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        pid_map.erase(pid);
    }

    if(!last) {
        return;
    }

    // 标记整组 exited 并唤醒 waitpid。tg->exit_code 由 do_exit/do_exit_group 用 CAS
    // 首次写入，被 VM_KILLED 的线程不走 do_exit 故不碰；此处仅在仍为 -1（整组无人正常
    // 退出，且不是经 do_kill→do_exit(128+sig) 被信号杀）时兜底置 137，正常路径不命中。
    int expected = -1;
    tg->exit_code.compare_exchange_strong(expected, 128 + 9, std::memory_order_acq_rel);
    tg->exited.store(true, std::memory_order_release);
    tg->cv.notify_all();
    // 子进程退出时给父进程投 SIGCHLD：让阻塞在 read/sigsuspend 的父（如 dash）被唤醒，
    // 进而 waitpid 回收。当前 dash 靠同步 waitpid 也能回收，但 SIGCHLD 使交互式 job-control
    // 行为正确（父不必轮询）。
    notify_parent_sigchld();

    // 把本组派生的孤儿重定向到 pid 1。children 的 ppid 记的是本组 tg->tgid（leader pid），
    // 故用 tg->tgid 匹配；由最后一个退出的线程执行即可——不必是 leader，规避 leader 先于
    // last 退出时漏 reparent 的窗口。
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        for(auto& entry : pid_map) {
            auto child_sys = sys(entry.second.get());
            if(child_sys && child_sys->ppid.load() == tg->tgid) {
                child_sys->ppid.store(1);
            }
        }
    }

    // 清理进程级资源。maps 已在上方 per-thread 释放（exit_mm 语义），此处清 fd 表，对齐do_close
    for(auto& kv : ps->fds) {
        drop_fd_handle(v.get(), kv.second);
    }
    ps->fds.clear();
}

std::shared_ptr<PosixSyscall> PosixSyscall::sys(vm* v) {
    if (v == nullptr) {
        return nullptr;
    }
    return std::dynamic_pointer_cast<PosixSyscall>(options(v).sys);
}

void PosixSyscall::host_signal(vm* v, int sig) {
    // 宿主侧信号转 guest 路由。判据是 guest 是否有控制终端——这是 PosixSyscall 内部
    // session->ctty，与 host 侧 PTY/非 PTY 接入方式无关。
    //
    // 有 ctty：tty 信号发给"控制终端的前台进程组所有成员"。
    // 无 ctty（非 PTY 模式 / setsid 前）：前台组即本进程所在 pgrp。
    deliver_to_ctty_fg(v, session ? session->ctty.get() : nullptr, sig);
}


void PosixSyscall::deliver_to_ctty_fg(vm* v, GuestTty* tty, int sig) {
    // 向控制终端的前台进程组（或无 ctty 时的本 session）投递 tty 信号。
    // tty != nullptr：向绑该 tty 为 ctty 的 session 的前台组（tty->fg_pgrp）投递。若该 tty
    //   未被任何 session 绑为 ctty（owner_ == nullptr），或前台组无活进程，则不投递（不
    //   fallback）——Linux tty_vhangup 只影响把该 tty 作为控制终端的 session。
    // tty == nullptr（host_signal 无 ctty 路径）：退化为按调用者 session 选目标组，目标
    //   为空时给当前 v 投信号（保留原 fallback 语义，让 pid 1 收到宿主信号）。
    if(sig <= 0) return;

    uint64_t target_pgid;
    if(tty) {
        target_pgid = tty->fg_pgrp.load(std::memory_order_acquire);
    } else {
        target_pgid = pgrp->pgid;
    }

    std::vector<std::shared_ptr<vm>> targets;
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        if(tty && tty->owner_ == nullptr) return;  // tty 路径不 fallback
        for(const auto& entry : pid_map) {
            auto s = sys(entry.second.get());
            if(!s || s->pgrp->pgid != target_pgid) continue;
            // 同 pgid 必同 session，但不同 session 可能复用同一 pgid 数值——有 ctty
            // 时按 ctty 收窄到同一控制终端的前台组，无 ctty 时退化为按 session 比对。
            if(tty) {
                if(!s->session || s->session->ctty.get() != tty) continue;
            } else {
                if(s->session.get() != session.get()) continue;
            }
            targets.push_back(entry.second);
        }
    }

    if(targets.empty()) {
        if(tty) return;  // tty 路径不 fallback
        queue_signal(v, sig);  // 无 ctty fallback：投给当前 v（pid 1）
        return;
    }
    for(auto& t : targets) {
        // 目标是另一个 PosixSyscall：经 sys() downcast 后调内部 queue_signal。
        if(auto s = sys(t.get())) s->queue_signal(t.get(), sig);
    }
}

void PosixSyscall::drop_fd_handle(vm* v, const std::shared_ptr<fd_handle>& h) {
    // 所有 fd 销毁路径（do_close、dup3 覆盖、execve cloexec 丢弃、fini 退出）统一调此函数。
    // master fd（master_token 非空）且是最后一个引用（use_count()==1）时，向 ctty 前台组投
    // SIGHUP（对齐 Linux pty_close → tty_vhangup）。
    if(h->master_token && h->master_token.use_count() == 1) {
        deliver_to_ctty_fg(v, h->tty.get(), SIGHUP);
    }
}


// —— 进程级杂项属性 / 系统信息类 syscall ——
// clock_gettime/nanosleep（时间）、getrandom（随机源）既不属 fd 操作也不属文件

bool PosixSyscall::do_clock_gettime(vm* v) {
    clockid_t clock_id = (clockid_t)arg_s32(v->r(1));
    struct timespec* tp = (struct timespec*)v->mmu_w(v->r(2), sizeof(*tp));
    if(tp == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    if(clock_gettime(clock_id, tp) == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_nanosleep(vm* v) {
    const struct timespec* req = static_cast<const struct timespec*>(v->mmu(v->r(1)));
    if(req == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }

    struct timespec* rem = nullptr;
    if(v->r(2) != 0) {
        rem = static_cast<struct timespec*>(v->mmu_w(v->r(2), sizeof(*rem)));
        if(rem == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
    }

    struct timespec host_req = {};
    if(req != nullptr) {
        host_req = *req;
    }

    struct timespec host_rem = {};
    int rc = nanosleep(&host_req, rem != nullptr ? &host_rem : nullptr);
    if(rc == -1) {
        if(rem != nullptr) {
            *rem = host_rem;
        }
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_getrandom(vm* v) {
    size_t buflen = arg_size(v->r(2));
    if(buflen == 0) {
        v->r(0) = 0;
        return true;
    }
    void* buf = v->mmu_w(v->r(1), buflen);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    unsigned int flags = (unsigned int)arg_u32(v->r(3));
    // 用 syscall(SYS_getrandom) 而非 libc wrapper：bionic 的 getrandom() 是
    // __INTRODUCED_IN(28)，在 target API < 28（如 Termux 默认）时声明被隐藏。
    ssize_t rc = ::syscall(SYS_getrandom, buf, buflen, flags);
    if(rc < 0) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = (uint64_t)rc;
    return true;
}

// alloca(inc) 的 syscall 入口
bool PosixSyscall::do_alloca(vm* v) {
    int64_t inc = (int64_t)v->r(1);
    v->r(0) = (uint64_t)v->alloca(inc);
    return true;
}

bool PosixSyscall::syscall(vm* v, uint32_t call) {
    uint32_t sys_id = call;
    if(call >= BPF_CALL_BASE) {
        sys_id = BPF_CALL_TO_ID(call);
    }
    switch (sys_id) {
    case BPF_SYS_MMAP:          return do_mmap(v);
    case BPF_SYS_MUNMAP:        return do_munmap(v);
    case BPF_SYS_EXIT:          return do_exit(v);
    case BPF_SYS_EXIT_GROUP:    return do_exit_group(v);
    case BPF_SYS_NANOSLEEP:     return do_nanosleep(v);
    case BPF_SYS_OPENAT:        return do_openat(v);
    case BPF_SYS_READ:          return do_read(v);
    case BPF_SYS_WRITE:         return do_write(v);
    case BPF_SYS_LSEEK:         return do_lseek(v);
    case BPF_SYS_TRUNCATE:      return do_truncate(v);
    case BPF_SYS_FTRUNCATE:     return do_ftruncate(v);
    case BPF_SYS_CLOSE:         return do_close(v);
    case BPF_SYS_UNLINKAT:      return do_unlinkat(v);
    case BPF_SYS_MKDIRAT:       return do_mkdirat(v);
    case BPF_SYS_SYMLINKAT:     return do_symlinkat(v);
    case BPF_SYS_LINKAT:        return do_linkat(v);
    case BPF_SYS_RENAMEAT2:     return do_renameat2(v);
    case BPF_SYS_READLINKAT:    return do_readlinkat(v);
    case BPF_SYS_EXECVE:        return do_execve(v);
    case BPF_SYS_CLONE:         return do_clone(v);
    case BPF_SYS_GETPID:        return do_getpid(v);
    case BPF_SYS_GETPPID:       return do_getppid(v);
    case BPF_SYS_WAITPID:       return do_waitpid(v);
    case BPF_SYS_DUP:           return do_dup(v);
    case BPF_SYS_DUP3:          return do_dup3(v);
    case BPF_SYS_PIPE2:         return do_pipe2(v);
    case BPF_SYS_FCHDIR:        return do_fchdir(v);
    case BPF_SYS_GETCWD:        return do_getcwd(v);
    case BPF_SYS_STATX:         return do_statx(v);
    case BPF_SYS_FCHMODAT:      return do_fchmodat(v);
    case BPF_SYS_UTIMENSAT:     return do_utimensat(v);
    case BPF_SYS_FACCESSAT:     return do_faccessat(v);
    case BPF_SYS_KILL:          return do_kill(v);
    case BPF_SYS_TKILL:         return do_tkill(v);
    case BPF_SYS_TGKILL:        return do_tgkill(v);
    case BPF_SYS_SIGACTION:     return do_sigaction(v);
    case BPF_SYS_SIGPROCMASK:   return do_sigprocmask(v);
    case BPF_SYS_SETPGID:       return do_setpgid(v);
    case BPF_SYS_GETPGID:       return do_getpgid(v);
    case BPF_SYS_GETPGRP:       return do_getpgrp(v);
    case BPF_SYS_SETSID:        return do_setsid(v);
    case BPF_SYS_GETSID:        return do_getsid(v);
    case BPF_SYS_FCNTL:         return do_fcntl(v);
    case BPF_SYS_IOCTL:         return do_ioctl(v);
    case BPF_SYS_UMASK:         return do_umask(v);
    case BPF_SYS_SIGSETJMP:     return do_sigsetjmp(v);
    case BPF_SYS_SIGLONGJMP:    return do_siglongjmp(v);
    case BPF_SYS_CLOCK_GETTIME: return do_clock_gettime(v);
    // —— musl/libc 兼容性补充 ——
    case BPF_SYS_MPROTECT:       return do_mprotect(v);
    case BPF_SYS_READV:          return do_readv(v);
    case BPF_SYS_WRITEV:         return do_writev(v);
    case BPF_SYS_PREAD:          return do_pread(v);
    case BPF_SYS_PWRITE:         return do_pwrite(v);
    case BPF_SYS_GETRANDOM:      return do_getrandom(v);
    case BPF_SYS_GETDENTS64:     return do_getdents64(v);
    case BPF_SYS_SET_TID_ADDRESS:return do_set_tid_address(v);
    case BPF_SYS_MADVISE:        return do_madvise(v);
    case BPF_SYS_SCHED_YIELD:    return do_sched_yield(v);
    case BPF_SYS_GETTID:         return do_gettid(v);
    case BPF_SYS_SET_TLS:        return do_set_tls(v);
    case BPF_SYS_GET_TLS:        return do_get_tls(v);
    case BPF_SYS_FUTEX:          return do_futex(v);
    case BPF_SYS_ALLOCA:         return do_alloca(v);
    case BPF_SYS_POLL:           return do_poll(v);
    default:
        /* 未实现的 syscall（包括 musl 移植用 BPF_CALL_BASE 占位的 brk/mremap/futex
         * 等探测型调用）。统一返回 -ENOSYS，让 musl 走兜底/降级路径。仅在 BPF_DEBUG
         * 时打印，避免每次启动刷屏（这些调用大多 musl 会主动忽略返回值）。 */
        if (getenv("BPF_DEBUG"))
            fprintf(stderr, "unsupported func: 0x%x\n", call);
        v->r(0) = -ENOSYS;
        return true;
    }
}
