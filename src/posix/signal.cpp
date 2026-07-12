#include "posix_internal.h"

void PosixSyscall::notify_parent_sigchld() {
    // 给父进程投 SIGCHLD。find_task(ppid) 取父 vm（leader），sys() downcast 后调其
    // queue_signal(SIGCHLD)。父进程可能：已退出（find_task 返 nullptr）、是 EmptySyscall
    // （测试，sys() 返 nullptr）、或正常 PosixSyscall。前两者降级 no-op。
    // ppid 从 this 取（本进程的父 pid），不需传 v。
    uint64_t parent_pid = ppid.load();
    if(parent_pid == 0) return;  // pid 1 无父（init）
    auto parent_vm = find_task(parent_pid);
    if(!parent_vm) return;
    if(auto ps = sys(parent_vm.get())) ps->queue_signal(parent_vm.get(), SIGCHLD);
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

void PosixSyscall::queue_signal(vm* v, int sig) {
    bool stop_dfl = is_default_stop(sig) &&
                    handler_is_default(ps->signal_actions[static_cast<size_t>(sig)].handler);
    if(sig == SIGKILL) {
        flags(v).fetch_or(vm::VM_KILLED, std::memory_order_release);
        v->wakeup(false);
    } else if(sig == SIGSTOP || stop_dfl) {
        stop_process(sig);
        return;              // STOP 不踢 host syscall
    } else if(sig == SIGCONT) {
        // 恢复整个线程组：清 tg 停止状态 + 组内每线程清 VM_STOPPED + wakeup(true) 让 safepoint
        // 的 cond_wait 返回。stop_sig 不清（waitpid 已消费或不再查询；下次停止会覆盖）。
        // 本次不投 SIGCHLD(CLD_CONTINUED) / 不报告 WIFCONTINUED（范围控制）。
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
        return;
    } else if(pending_signals.try_push(sig)) {
        // Best-effort: drop if the queue is full to avoid blocking the VM thread.
        flags(v).fetch_or(vm::VM_SIGNAL_PENDING, std::memory_order_release);
        // 排队信号也要 wakeup(false)：vm 可能正阻塞在 futex 上，而 SIGUSR1
        // 无法可靠打断 pthread_cond_wait（glibc 内部重试 EINTR）
        v->wakeup(false);
    } else {
        return; // 队列满：丢弃信号，不处理
    }
    if (tid != 0) {
        pthread_kill(tid, SIGUSR1);
    }
}

bool PosixSyscall::handle_signals(vm* v, sig_info* info) {
    // 实时信号统一模型：队列 + 掩码过滤。从 pending_signals 逐个 pop，被 sigmask 阻塞
    // 的信号暂存到 deferred（函数末尾回挂队列，保持 FIFO），找到第一个未阻塞的即投递。
    // 队列空 / 全部被阻塞 → 收尾：阻塞信号留在队里，VM_SIGNAL_PENDING 保留，待
    // sigprocmask 解锁后 safepoint 重扫时投出。
    const uint64_t blocked = sigmask.load(std::memory_order_relaxed);
    int sig = 0;
    int deferred[BPF_SIGNAL_QUE_SIZE];
    size_t deferred_count = 0;
    // 扫描上限 = 队列容量，避免极端情况下死循环（理论上每轮最多 pop k_capacity 个）。
    for(size_t i = 0; i < BPF_SIGNAL_QUE_SIZE; i++) {
        int s;
        if(!pending_signals.try_pop(s)) {
            break;  // 队列空
        }
        uint64_t bit = (s >= 1 && s < NSIG) ? (1ULL << (s - 1)) : 0;
        if(bit && (blocked & bit)) {
            deferred[deferred_count++] = s;
            continue;
        }
        sig = s;
        break;
    }
    // 重新入队被阻塞的信号（保持入队先后顺序）。
    for(size_t i = 0; i < deferred_count; i++) {
        pending_signals.try_push(deferred[i]);
    }
    if(sig == 0) {
        // 没找到可投信号。若队列仍非空（全被阻塞）→ 保留 VM_SIGNAL_PENDING 等解锁；
        // 若队列空 → 清 VM_SIGNAL_PENDING，并 seq_cst fence 后复检关闭与并发
        // queue_signal 的丢失窗口（push 发生在 clear 前→复检抓到；后→queue_signal 已置位）。
        if(deferred_count > 0) {
            return true;  // 队列里只剩阻塞信号
        }
        flags(v).fetch_and(~vm::VM_SIGNAL_PENDING, std::memory_order_seq_cst);
        int recheck;
        if(pending_signals.try_pop(recheck)) {
            // 复检抓到一个 push：要么被阻塞（回挂、留 flag），要么可投（投它）。
            uint64_t bit = (recheck >= 1 && recheck < NSIG) ? (1ULL << (recheck - 1)) : 0;
            if(bit && (blocked & bit)) {
                pending_signals.try_push(recheck);
                return true;
            }
            sig = recheck;
        } else {
            return true;
        }
    }
    if(sig <= 0 || sig >= NSIG) {
        return true;
    }
    const auto& act = ps->signal_actions[static_cast<size_t>(sig)];
    uint64_t handler = act.handler;
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
    info->sa_flags = static_cast<uint64_t>(act.flags);
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
        if(auto s = sys(t.get())) s->queue_signal(t.get(), sig);
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
    if(auto s = sys(target_vm.get())) s->queue_signal(target_vm.get(), sig);
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
    target->queue_signal(target_vm.get(), sig);
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
