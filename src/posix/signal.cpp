#include "posix_internal.h"

#include <sys/signalfd.h>   // host 侧 signalfd_siginfo 布局（与 guest 一致：128 字节）

void PosixSyscall::notify_parent_sigchld() {
    // 给父进程投 SIGCHLD。find_task(ppid) 取父 vm → sys()->queue_signal。
    // 父进程可能：已退出（find_task 返 nullptr）、是 EmptySyscall
    // （测试，sys() 返 nullptr）、或正常 PosixSyscall。前两者降级 no-op。
    // ppid 进程级（在 tg）：从 tg->ppid 取本进程的父 pid。
    uint64_t parent_pid = tg->ppid.load();
    if(parent_pid == 0) return;  // pid 1 无父（init）
    auto parent_vm = find_task(parent_pid);
    if(!parent_vm) return;

    // SIGCHLD 的 si_code/si_status 取决于子进程状态（对齐 Linux）：
    //   stopped —— CLD_STOPPED，status = stop_sig
    //   否则按 exit_code：<128 = CLD_EXITED + 退出码；>=128 = CLD_KILLED + 信号号
    // （bpfvm 不区分 core dump，故无 CLD_DUMPED。）exit_code 的 -1 兜底（last 线程
    // 在 posix_syscall.cpp fini 里 CAS 成 128+9）保证退出路径总有合法值。
    int32_t code;
    int32_t status;
    if(tg->stopped.load(std::memory_order_acquire)) {
        code = CLD_STOPPED;
        status = tg->stop_sig.load(std::memory_order_acquire);
    } else {
        int ec = tg->exit_code.load(std::memory_order_acquire);
        if(ec >= 128) {
            code = CLD_KILLED;
            status = ec - 128;   // 原始信号号
        } else {
            code = CLD_EXITED;
            status = ec;         // 原始退出码
        }
    }
    // sender = 本子进程的 pid（wait4 的 siginfo.si_pid 据此报告是谁退出/停止）。
    if(auto ps = sys(parent_vm.get())) {
        ps->queue_signal(parent_vm.get(), {SIGCHLD, pid, code, status});
    }
}

void PosixSyscall::stop_process(int sig) {
    // 停止整个线程组（进程级 stop 语义）。三件事：
    //   1) 设 tg 级停止状态（stopped/stop_sig），waitpid(WUNTRACED) 据此报告 WIFSTOPPED
    //   2) 组内每个线程设 VM_STOPPED + wakeup(false)：safepoint 见 VM_STOPPED 即 cond_wait
    //   3) 给父进程投一次 SIGCHLD（去重 stop_reported），让 dash 的 wait/sigsuspend 唤醒
    tg->stopped.store(true, std::memory_order_release);
    tg->stop_sig.store(sig, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(tg->mtx);
        for(auto& weak_vm : tg->threads) {
            auto tvm = weak_vm.lock();
            if(!tvm) {
                continue;
            }
            flags(tvm.get()).fetch_or(vm::VM_STOPPED, std::memory_order_release);
            tvm->wakeup(false);
        }
    }
    bool expected = false;
    if(tg->stop_reported.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        // 首次停止（未被 waitpid 消费过）才投 SIGCHLD，避免重复通知。
        notify_parent_sigchld();
    }
}

static bool is_default_term(int sig) {
    // SIG_DFL 默认动作为"终止"的信号（signal(7) Term/Core 列表）。bpfvm 不区分 core dump，
    // 统一走 do_exit_group 终止整个线程组（handle_signals 的 SIG_DFL 分支）。
    switch(sig) {
    case SIGHUP: case SIGINT: case SIGQUIT: case SIGILL: case SIGTRAP:
    case SIGABRT: case SIGBUS: case SIGFPE: case SIGUSR1: case SIGSEGV:
    case SIGUSR2: case SIGPIPE: case SIGALRM: case SIGTERM: case SIGSTKFLT:
    case SIGVTALRM: case SIGPROF: case SIGXCPU: case SIGXFSZ:
        return true;
    default:
        return false;
    }
}

static bool is_default_stop(int sig) {
    // SIG_DFL 默认动作为"停止作业"的信号（signal(7) Stop 列表）。SIGSTOP 不可捕获/忽略，
    // 恒为停止，但调用方（queue_signal）已特判，不进此函数。
    return sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU;
}

bool PosixSyscall::signal_ignorable(int sig) {
    // SIG_IGN 显式忽略，或 SIG_DFL 且默认动作 = Ign(SIGCHLD/SIGURG/SIGWINCH)/Cont(SIGCONT)。
    // 这些信号投递不会改变进程状态，Linux 也不让它们打断阻塞系统调用：get_signal 不让
    // Ign/Cont 信号产生 EINTR。判定复用 is_default_term/is_default_stop 单一来源。
    // SIGKILL/SIGSTOP 调用方已特判，不会进入此函数。
    if(sig <= 0 || sig >= NSIG) {
        return false;
    }
    const auto& act = ps->signal_actions[static_cast<size_t>(sig)];
    if(handler_is_ignored(act.handler)) {
        return true;
    }
    if(!handler_is_default(act.handler)) {
        return false;  // 已 catch：投递需中断系统调用
    }
    // SIG_DFL：默认动作非 Term/Stop 的即 Ign/Cont（可忽略）。
    return !is_default_term(sig) && !is_default_stop(sig);
}

void PosixSyscall::queue_signal(vm* v, const SigEvent& ev) {
    // 分类处理：不同信号走不同路径。SIGSTOP/SIGCONT/未阻塞 ignorable 自己 return
    // （不打断 host syscall）；SIGKILL/普通信号/被阻塞 ignorable 走到末尾的
    // pthread_kill(SIGUSR1) 把目标线程正阻塞的 host syscall 踢成 EINTR。
    int sig = ev.sig;
    bool stop_dfl = is_default_stop(sig) &&
                    handler_is_default(ps->signal_actions[static_cast<size_t>(sig)].handler);
    // 是否需要入队 pending_signals。SIGKILL 直接置 VM_KILLED 不入队；SIGSTOP/SIGCONT/
    // 未阻塞 ignorable 自己 return；普通信号 + 被阻塞 ignorable 需要入队。
    bool enqueue = true;

    if(sig == SIGKILL) {
        // SIGKILL 不入队：直接置 VM_KILLED，VM 在下个 safepoint 退出。落到末尾的
        // pthread_kill 把目标线程正阻塞的 host syscall（nanosleep/read/...）踢成
        // EINTR，让它回 safepoint 看到 VM_KILLED 退出（exit_group_race #7 检测此机制）。
        flags(v).fetch_or(vm::VM_KILLED, std::memory_order_release);
        v->wakeup(false);
        enqueue = false;
    } else if(sig == SIGSTOP || stop_dfl) {
        stop_process(sig);
        return;              // STOP 不踢 host syscall（stop_process 自己 wakeup）
    } else if(sig == SIGCONT) {
        // 恢复整个线程组：清 tg 停止状态 + 组内每线程清 VM_STOPPED + wakeup(false) 让
        // safepoint 的 cond_wait 返回。stop_sig 不清（waitpid 已消费或不再查询；下次
        // 停止会覆盖）。不投 SIGCHLD(CLD_CONTINUED) / 不报告 WIFCONTINUED（范围控制）。
        tg->stopped.store(false, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(tg->mtx);
            for(auto& weak_vm : tg->threads) {
                auto tvm = weak_vm.lock();
                if(!tvm) {
                    continue;
                }
                flags(tvm.get()).fetch_and(~vm::VM_STOPPED, std::memory_order_release);
                tvm->wakeup(false);  // 唤醒 safepoint 的停止 cond_wait；
            }
        }
        return;
    } else if(signal_ignorable(sig)) {
        uint64_t bit = (sig >= 1 && sig < NSIG) ? (1ULL << (sig - 1)) : 0;
        bool blocked = bit && (sigmask.load(std::memory_order_relaxed) & bit);
        if(!blocked) {
            return;   // 未阻塞：ignorable 直接丢弃，不打断 syscall
        }
        // 被阻塞：保留 enqueue=true，落入下面的入队路径（供 signalfd 消费）
    }

    if(enqueue) {
        // push + 置 flag 在同一把锁内，与 handle_signals 的 clear 形成原子对应：
        // 要么本线程的 fetch_or 在 handle_signals 的 fetch_and 之前（handle_signals
        // 看到 non-empty 不清 flag），要么在之后（fetch_and 已完成，本线程置位）。
        //
        // 直接操作 raw() 而非调 push()：本块已持 mtx()，再调 push() 会重复加锁死锁
        // （std::mutex 不可重入）。容量检查在此处内联，与 push() 的实现保持一致。
        // push 满则丢弃（容量 BPF_SIGNAL_QUE_SIZE）：丢弃的信号不置 flag、不 wakeup，
        // best-effort（对齐 Linux 信号队列满语义）。
        bool pushed;
        {
            std::lock_guard<std::mutex> lk(pending_signals.mtx());
            if(pending_signals.raw().size() >= BPF_SIGNAL_QUE_SIZE) {
                pushed = false;
            } else {
                pending_signals.raw().push_back(ev);
                pushed = true;
                flags(v).fetch_or(vm::VM_SIGNAL_PENDING, std::memory_order_relaxed);
            }
        }
        if(!pushed) {
            return;   // 队列满：丢弃信号，不处理
        }
        // wakeup 在队列锁外：锁序约定 pending_signals.mtx() → vm::wait_mutex，
        // wakeup 内部拿 wait_mutex，持锁调用会反序。
        // wakeup(false)：vm 可能正阻塞在 futex 上，而 SIGUSR1 无法可靠打断
        // pthread_cond_wait（glibc 内部重试 EINTR），靠 broadcast 唤醒。
        v->wakeup(false);
    }
    // 收尾：踢 SIGUSR1 把目标线程正阻塞的 host syscall 踢成 EINTR，让它回 safepoint
    // 处理（SIGKILL 看 VM_KILLED；普通/pending 信号 handle_signals 投递）。
    if(tid != 0) {
        pthread_kill(tid, SIGUSR1);
    }
}

bool PosixSyscall::handle_signals(vm* v, sig_info* info) {
    // 实时信号统一模型：队列 + 掩码过滤。从 pending_signals 逐个 pop，被 sigmask 阻塞
    // 的信号暂存到 deferred（函数末尾回挂队列，保持 FIFO），找到第一个未阻塞的即投递。
    // 队列空 / 全部被阻塞 → 收尾：阻塞信号留在队里，VM_SIGNAL_PENDING 保留，待
    // sigprocmask 解锁后 safepoint 重扫时投出。
    //
    // signalfd 分流：被阻塞的信号若被某 signalfd 监听，则送进 pipe、不入 deferred
    // （视为已消费）。对齐 Linux：signalfd 只消费"本来要走默认/handler 路径"的信号——
    // 用户用 signalfd 时必须先 sigprocmask 阻塞目标信号，故分流点必在被阻塞分支。
    // 未阻塞信号不送 signalfd（直接 handler/默认动作），与 Linux 一致。
    const uint64_t blocked = sigmask.load(std::memory_order_relaxed);

    SigEvent chosen{};          // 选中的待投递事件（sig==0 表示无）
    uint64_t handler = 0;
    int sig_action_flags = 0;
    std::vector<SignalFd*> signalfds;
    bool has_filled_signalfd = false;
    std::vector<SigEvent> deferred;   // 锁内收集的阻塞信号，锁内原样回挂

    {
        std::lock_guard<std::mutex> lk(pending_signals.mtx());
        // 扫描上限 = 队列容量，避免极端情况下死循环（理论上每轮最多处理这么多）。
        for(size_t i = 0; i < BPF_SIGNAL_QUE_SIZE; i++) {
            if(pending_signals.raw().empty()) {
                break;  // 队列空
            }
            SigEvent e = pending_signals.raw().front();
            pending_signals.raw().pop_front();
            uint64_t bit = (e.sig >= 1 && e.sig < NSIG) ? (1ULL << (e.sig - 1)) : 0;
            if(bit && (blocked & bit)) {
                // 被阻塞：先试 signalfd（仅当存在），命中即消费；否则暂存 deferred 回挂队列。
                if(!has_filled_signalfd) {
                    for(const auto& kv : *ps->fds_snap()) {
                        if(auto* sfd = dynamic_cast<SignalFd*>(kv.second.get())) {
                            signalfds.push_back(sfd);
                        }
                    }
                    has_filled_signalfd = true;
                }
                bool consumed = false;
                for(SignalFd* sfd : signalfds) {
                    // 第一个 mask 匹配的 signalfd 就投它一个（与 Linux 一致——信号在 task 队列里只一份，
                    // 多个 signalfd 读同一队列，先到先得）。code/status/sender 透传给 signalfd_siginfo。
                    if(sfd->deliver(e)) {
                        consumed = true;
                        break;
                    }
                }
                if(consumed) {
                    continue;
                }
                deferred.push_back(e);
                continue;
            }
            chosen = e;
            break;
        }
        // 重新入队被阻塞的信号（保持入队先后顺序）。
        for(const auto& d : deferred) {
            pending_signals.raw().push_back(d);
        }
        // flag 维护（锁内）：只有当队列空 且 本轮未投递信号时，才清 VM_SIGNAL_PENDING。
        if(chosen.sig == 0 && deferred.empty() && pending_signals.raw().empty()) {
            flags(v).fetch_and(~vm::VM_SIGNAL_PENDING, std::memory_order_relaxed);
        }
        // 预读 handler（锁内读 signal_actions，与 fork/clone 的 make_shared 拷贝路径隔离）
        if(chosen.sig > 0 && chosen.sig < NSIG) {
            const auto& act = ps->signal_actions[static_cast<size_t>(chosen.sig)];
            handler = act.handler;
            sig_action_flags = act.flags;
        }
    }
    // 当前 handler 只传 sig（r1），未走 SA_SIGINFO，故 chosen.code/status/sender 未使用；
    // 保留在 chosen 里供未来 SA_SIGINFO 投递填 siginfo.si_code/si_status/si_pid 用。
    int sig = chosen.sig;
    (void)chosen.sender; (void)chosen.code; (void)chosen.status;
    if(sig <= 0 || sig >= NSIG) {
        return true;
    }
    if(options(v).verbose) {
        std::lock_guard<std::mutex> lock(log_mutex);
        printf("[#%d] signal %d handler=0x%lx return=0x%lx\n",
               id(), sig, static_cast<unsigned long>(handler), pc(v));
    }
    if(handler_is_ignored(handler)) {
        return true;
    }
    if(handler_is_default(handler)) {
        // 默认动作分类（单一来源 = is_default_term/is_default_stop）。
        if(is_default_term(sig)) {
            // 默认动作为"终止"（Term）的信号（见 signal(7)）。bpfvm 不区分 core dump，
            // 统一走 do_exit_group 终止整个线程组（POSIX：default action of fatal signals
            // is process termination，等价 exit_group），不只杀当前线程。退出码 128+sig。
            v->r(1) = 128 + static_cast<uint64_t>(sig);
            v->r(0) = (uint64_t)do_exit_group(v);  // 置 VM_EXITED + 写退出码到 r(0)
            return false;
        }
        if(is_default_stop(sig)) {
            // 默认动作 = 停止作业（进程级）。stop_process 设 tg 状态 + 整组 VM_STOPPED +
            // 给父进程投 SIGCHLD，让父（如 dash）经 waitpid(WUNTRACED) 报告 WIFSTOPPED。
            stop_process(sig);
            return true;
        }
        // SIGCHLD（忽略）、SIGURG（忽略）、SIGWINCH（忽略）等默认动作为忽略的信号，
        // 以及任何未列出的信号：默认动作 = 丢弃，进程继续。
        return true;
    }

    // 已 catch：带回 sig 与 handler 地址，由 vm::deliver_signal 压栈跳转。
    // 同时带回 sa_flags：投递信号的 SA_RESTART 位用于 ERESTARTSYS 重启判定。
    info->sig = sig;
    info->handler = handler;
    info->sa_flags = static_cast<uint64_t>(sig_action_flags);
    return true;
}

int64_t PosixSyscall::do_kill(vm* v) {
    int target_pid = arg_s32(v->r(1));
    int sig = arg_s32(v->r(2));
    if(sig < 0 || sig >= NSIG) {
        return -EINVAL;
    }

    // 收集目标 task 列表。Linux 语义：
    //   pid > 0  → 指定 task
    //   pid == 0 → 调用者进程组所有 task（含自身）
    //   pid == -1→ 除 pid 1 外所有 task（含自身）
    //   pid < -1 → 进程组 -pid 所有 task
    std::vector<std::shared_ptr<vm>> targets;
    auto pick = [&](const std::shared_ptr<vm>& task_vm) {
        targets.push_back(task_vm);
    };

    if(target_pid > 0) {
        auto t = find_task(static_cast<uint64_t>(target_pid));
        if(t) pick(t);
    } else if(target_pid == 0) {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        for(const auto& entry : pid_map) {
            auto s = sys(entry.second.get());
            if(s && s->pgrp->pgid == pgrp->pgid) {
                pick(entry.second);
            }
        }
    } else if(target_pid == -1) {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        for(const auto& entry : pid_map) {
            auto s = sys(entry.second.get());
            // 跳过 pid 1（init）和调用者自身（Linux kill(-1) 不发给这二者）
            if(s && s->pid != 1 && s->pid != pid) {
                pick(entry.second);
            }
        }
    } else {
        // target_pid < -1：进程组 -pid
        uint64_t target_pgid = static_cast<uint64_t>(-target_pid);
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        for(const auto& entry : pid_map) {
            auto s = sys(entry.second.get());
            if(s && s->pgrp->pgid == target_pgid) {
                pick(entry.second);
            }
        }
    }

    if(targets.empty()) {
        return -ESRCH;
    }

    // sig == 0：仅存在性检查，不发信号。
    if(sig == 0) {
        return 0;
    }

    for(auto& t : targets) {
        // kill/tgkill 来源：SI_USER（用户态发起），si_status=0。
        if(auto s = sys(t.get())) s->queue_signal(t.get(), {sig, pid, SI_USER, 0});
    }
    return 0;
}

int64_t PosixSyscall::do_tkill(vm* v) {
    int tid = arg_s32(v->r(1));
    int sig = arg_s32(v->r(2));
    if(sig < 0 || sig >= NSIG || tid <= 0) {
        return -EINVAL;
    }
    auto target_vm = find_task(static_cast<uint64_t>(tid));
    if(!target_vm) {
        return -ESRCH;
    }
    if(sig == 0) {
        return 0;
    }
    if(auto s = sys(target_vm.get())) s->queue_signal(target_vm.get(), {sig, pid, SI_USER, 0});
    return 0;
}

int64_t PosixSyscall::do_tgkill(vm* v) {
    int tgid_arg = arg_s32(v->r(1));
    int tid = arg_s32(v->r(2));
    int sig = arg_s32(v->r(3));
    if(sig < 0 || sig >= NSIG || tid <= 0 || tgid_arg <= 0) {
        return -EINVAL;
    }
    auto target_vm = find_task(static_cast<uint64_t>(tid));
    if(!target_vm) {
        return -ESRCH;
    }
    auto target = sys(target_vm.get());
    if(!target || target->tg->tgid != static_cast<uint64_t>(tgid_arg)) {
        return -ESRCH;
    }
    if(sig == 0) {
        return 0;
    }
    target->queue_signal(target_vm.get(), {sig, pid, SI_USER, 0});
    return 0;
}

int64_t PosixSyscall::do_sigaction(vm* v) {
    int signo = arg_s32(v->r(1));
    uint64_t act_addr = v->r(2);
    uint64_t oldact_addr = v->r(3);

    if(signo <= 0 || signo >= NSIG || signo == SIGKILL || signo == SIGSTOP) {
        return -EINVAL;
    }

    // guest（musl）经 __libc_sigaction 把用户态 struct sigaction 转成内核 sigaction
    // 布局（arch/bpf/ksigaction.h，复制自 x86_64）再调本 syscall，故此处按内核
    // sigaction 布局解析，而非 guest 用户态 struct sigaction。布局定义见
    // include/signal.h（bpf::sigaction）。
    if(oldact_addr != 0) {
        auto* oldact = static_cast<bpf::sigaction*>(v->mmu_w(oldact_addr, sizeof(bpf::sigaction)));
        if(oldact == nullptr) {
            return -EFAULT;
        }
        const auto& current = ps->signal_actions[static_cast<size_t>(signo)];
        oldact->handler = current.handler;
        oldact->flags = static_cast<uint64_t>(current.flags);
        oldact->restorer = 0;  // VM 用信号帧机制，无 restorer；musl 读 old 时忽略
        oldact->mask = current.mask;
    }

    if(act_addr != 0) {
        const auto* action = static_cast<const bpf::sigaction*>(v->mmu(act_addr, sizeof(bpf::sigaction)));
        if(action == nullptr) {
            return -EFAULT;
        }
        if(action->handler == reinterpret_cast<uint64_t>(SIG_ERR)) {
            return -EINVAL;
        }
        auto& current = ps->signal_actions[static_cast<size_t>(signo)];
        current.handler = action->handler;
        current.mask = action->mask;
        current.flags = static_cast<int>(action->flags);
    }

    return 0;
}

int64_t PosixSyscall::do_sigprocmask(vm* v) {
    // rt_sigprocmask(how, set, old, sigsetsize)。how ∈ {SIG_BLOCK=0, SIG_UNBLOCK=1, SIG_SETMASK=2}。
    // sigset_t 在 bpf/musl 是 128 位（16 字节，2 个 unsigned long）；guest 指针指向 16 字节
    // 区域，本 host 仅用低 8 字节（信号 1..63），高 8 字节恒 0（NSIG=32）。
    // 信号 sig 占 bit (sig-1)（Linux 内核/musl sigset_t ABI；bit 0 不用）。
    int how = arg_s32(v->r(1));
    uint64_t set_addr = v->r(2);
    uint64_t old_addr = v->r(3);
    // r(4) = sigsetsize（musl 传 _NSIG/8=8）。本 host 固定按 16 字节 解释，故忽略 size 校验。

    if(how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK) {
        return -EINVAL;
    }

    // oldset 总是反映当前 mask，写回 16 字节 sigset_t（低 long = mask，高 long = 0）。
    if(old_addr != 0) {
        auto* old_ptr = static_cast<uint64_t*>(v->mmu_w(old_addr, 2 * sizeof(uint64_t)));
        if(old_ptr == nullptr) {
            return -EFAULT;
        }
        old_ptr[0] = sigmask.load(std::memory_order_relaxed);
        old_ptr[1] = 0;
    }

    if(set_addr != 0) {
        // 读 guest sigset_t 低 8 字节（信号 1..63 足够覆盖 NSIG=32）。
        auto* set_ptr = static_cast<const uint64_t*>(v->mmu(set_addr, sizeof(uint64_t)));
        if(set_ptr == nullptr) {
            return -EFAULT;
        }
        uint64_t bits = *set_ptr;
        // 仅保留有效位（bit (sig-1), sig ∈ [1, NSIG-1]）；SIGKILL/SIGSTOP 不可阻塞。
        constexpr uint64_t valid = (NSIG < 64) ? ((1ULL << (NSIG - 1)) - 1) : ~0ULL;
        bits &= valid;
        bits &= ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));

        uint64_t old_mask = sigmask.load(std::memory_order_relaxed);
        uint64_t new_mask;
        switch(how) {
        case SIG_BLOCK:    new_mask = old_mask | bits;  break;
        case SIG_UNBLOCK:  new_mask = old_mask & ~bits; break;
        case SIG_SETMASK:  new_mask = bits;             break;
        }
        sigmask.store(new_mask, std::memory_order_release);

        // 解锁可能让队列里先前被阻塞的 pending 信号变得可投递：VM_SIGNAL_PENDING 在
        // handle_signals 走空队列时已被清，这里补设 + 唤醒，让本 syscall 返回后 safepoint
        // 重扫投出。queue_signal 入队时已无条件置 flag，故这里只在 mask 变化时兜底。
        if(!pending_signals.empty()) {
            flags(v).fetch_or(vm::VM_SIGNAL_PENDING, std::memory_order_release);
            v->wakeup(false);
        }
    }

    return 0;
}

int64_t PosixSyscall::do_sigsetjmp(vm* v) {
    uint64_t env_addr = v->r(1);
    int savemask = arg_s32(v->r(2));
    uint64_t* env = (uint64_t*)v->mmu_w(env_addr, 10 * sizeof(uint64_t));
    if (!env) {
        return -EFAULT;
    }
    env[0] = v->r(6);
    env[1] = v->r(7);
    env[2] = v->r(8);
    env[3] = v->r(9);
    env[4] = v->r(10);
    env[5] = pc(v);
    env[6] = signal_depth(v);
    env[7] = 0;
    env[8] = savemask ? 1 : 0;    // __fl
    if (savemask)
        env[9] = sigmask.load(std::memory_order_relaxed);   // __ss[0]
    return 0;
}

int64_t PosixSyscall::do_siglongjmp(vm* v) {
    uint64_t env_addr = v->r(1);
    int32_t val = arg_s32(v->r(2));
    uint64_t* env = (uint64_t*)v->mmu(env_addr, 10 * sizeof(uint64_t));
    if (!env) {
        return -EFAULT;
    }
    v->r(6) = env[0];
    v->r(7) = env[1];
    v->r(8) = env[2];
    v->r(9) = env[3];
    v->r(10) = env[4];
    // CRTJMP（ldso 移交控制权到主程序入口）把 argc 地址（argv-1）放进 env[7]，让主程序
    // _start(long *p) 的 p=r1 指向 argc。普通 sigsetjmp 把 env[7] 置 0，此处不改 r1——
    // r1 是 caller-saved，标准 longjmp 不恢复它。仅 CRTJMP 路径 env[7]!=0 才设。
    if (env[7]) v->r(1) = env[7];
    uint64_t saved_pc = env[5];
    signal_depth(v) = static_cast<size_t>(env[6]);
    pc(v) = saved_pc;
    // pc points to syscall instruction.
    // loop increments pc.
    // next instruction is executed.

    // 若 setjmp 时保存过掩码（__fl!=0），恢复之。与 do_sigprocmask 一致：
    // 解锁后 pending 队列里先前被阻塞的信号可能变可投递，需补设 pending 标志 + 唤醒，
    // 让本 syscall 返回后 safepoint 重扫投出。
    if (env[8]) {
        sigmask.store(env[9], std::memory_order_release);
        if (!pending_signals.empty()) {
            flags(v).fetch_or(vm::VM_SIGNAL_PENDING, std::memory_order_release);
            v->wakeup(false);
        }
    }

    return (val == 0) ? 1 : val;
}

// 把 guest sigset_t 指针解析成 host uint64_t mask（仅低 8 字节有效），按 NSIG 截断。
// 返回 false 表示指针翻译失败（调用方返回 -EFAULT）。
static bool parse_guest_sigset(vm* v, uint64_t set_addr, uint64_t& out_mask) {
    if(set_addr == 0) {
        out_mask = 0;
        return true;
    }
    // 与 do_sigprocmask 一致：读低 8 字节，按 NSIG 截断。
    auto* set_ptr = static_cast<const uint64_t*>(v->mmu(set_addr, sizeof(uint64_t)));
    if(set_ptr == nullptr) {
        return false;
    }
    uint64_t bits = *set_ptr;
    constexpr uint64_t valid = (NSIG < 64) ? ((1ULL << (NSIG - 1)) - 1) : ~0ULL;
    out_mask = bits & valid;
    return true;
}

int64_t PosixSyscall::do_signalfd4(vm* v) {
    // ABI: r1=fd, r2=sigset*, r3=sigsetsize, r4=flags（musl signalfd() 透传）
    int fd = arg_s32(v->r(1));
    uint64_t set_addr = v->r(2);
    // r3 = sigsetsize（musl 传 _NSIG/8=8）。本 host 固定按 8 字节解析，忽略 size 校验。
    int flags = arg_s32(v->r(4));

    // 仅允许 SFD_CLOEXEC (=O_CLOEXEC) 与 SFD_NONBLOCK (=O_NONBLOCK)。
    if((flags & ~(SFD_CLOEXEC | SFD_NONBLOCK)) != 0) {
        return -EINVAL;
    }

    uint64_t mask;
    if(!parse_guest_sigset(v, set_addr, mask)) {
        return -EFAULT;
    }

    if(fd < 0) {
        // —— 创建新 signalfd ——
        // pipe2 用 O_CLOEXEC（若请求）让两端的 host fd 都带 CLOEXEC；写端额外设
        // O_NONBLOCK：信号风暴时 pipe 满 → EAGAIN → 静默丢，绝不阻塞 VM 线程。
        int p[2];
        int pipe_flags = (flags & SFD_CLOEXEC) ? O_CLOEXEC : 0;
        if(pipe2(p, pipe_flags) < 0) {
            return -errno;
        }
        // 写端设 O_NONBLOCK。读端保持阻塞（让 guest 的 read() 能阻塞，符合 signalfd 语义）；
        // SFD_NONBLOCK 仅作用在 guest 视角的读端行为上 → 通过 O_NONBLOCK 体现。
        int fcntl_flags = fcntl(p[1], F_GETFL);
        if(fcntl_flags >= 0) {
            fcntl(p[1], F_SETFL, fcntl_flags | O_NONBLOCK);
        }
        if(flags & SFD_NONBLOCK) {
            int rf = fcntl(p[0], F_GETFL);
            if(rf >= 0) {
                fcntl(p[0], F_SETFL, rf | O_NONBLOCK);
            }
        }

        auto handle = std::make_shared<SignalFd>(p[0], p[1], mask);
        if(flags & SFD_CLOEXEC) {
            handle->cloexec = true;
        }
        int guest_fd = -1;
        ps->fds_mutate([&](SharedState::FdMap& m){
            guest_fd = 0;
            while(m.count(guest_fd)) guest_fd++;
            m[guest_fd] = handle;
        });
        return guest_fd;
    }

    // —— 更新既有 signalfd 的 mask ——
    // dynamic_cast 判定：非 SignalFd（普通文件/pipe/socket/ProcFile/ProcDir）→ Linux 返回 EINVAL。
    auto h = ps->find_fd(fd);
    if(!h) {
        return -EBADF;
    }
    SignalFd* sfd = dynamic_cast<SignalFd*>(h.get());
    if(sfd == nullptr) {
        return -EINVAL;
    }
    sfd->mask.store(mask, std::memory_order_relaxed);
    return fd;
}

bool SignalFd::deliver(const SigEvent& ev) {
    // ev.sig 在 mask 内则构造 signalfd_siginfo 并写入 pipe。host 与 guest 的 signalfd_siginfo
    // 布局一致（128 字节，定义见 root/include/sys/signalfd.h）。
    int sig = ev.sig;
    if(sig <= 0 || sig >= NSIG) {
        return false;
    }
    uint64_t bit = 1ULL << (sig - 1);
    if(!(mask.load(std::memory_order_relaxed) & bit)) {
        return false;
    }
    signalfd_siginfo si{};
    si.ssi_signo  = static_cast<uint32_t>(sig);
    si.ssi_code   = ev.code;        // SI_USER/SI_KERNEL/CLD_*，对齐 Linux si_code
    si.ssi_status = ev.status;      // SIGCHLD 有效：CLD_EXITED=退出码、CLD_KILLED=信号号、CLD_STOPPED=停止信号号；其余 0
    si.ssi_pid    = static_cast<uint32_t>(ev.sender);   // 发送方 pid（0 = kernel/host，对齐 Linux si_pid 语义）
    si.ssi_uid    = 0;
    ssize_t n = ::write(write_fd, &si, sizeof(si));
    (void)n;  // EAGAIN（pipe 满）/ EBADF（已关闭，理论不会）均静默忽略，与 Linux 一致。
    return true;
}
