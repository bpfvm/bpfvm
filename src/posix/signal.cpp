#include "posix_internal.h"

void PosixSyscall::queue_signal(vm* v, int sig) {
    if(sig == SIGKILL) {
        flags(v).fetch_or(vm::VM_KILLED, std::memory_order_release);
        v->wakeup();
    } else if(sig == SIGSTOP) {
        flags(v).fetch_or(vm::VM_STOPPED, std::memory_order_release);
        v->wakeup();
    } else if(sig == SIGCONT) {
        flags(v).fetch_and(~vm::VM_STOPPED, std::memory_order_release);
        v->wakeup();
    } else {
        // Best-effort: drop if the queue is full to avoid blocking the VM thread.
        if(pending_signals.try_push(sig)) {
            flags(v).fetch_or(vm::VM_SIGNAL_PENDING, std::memory_order_release);
            // 排队信号也要 wakeup()：vm 可能正阻塞在 futex 的 exit_cv 上，而 SIGUSR1
            // 无法可靠打断 pthread_cond_wait（glibc 内部重试 EINTR），必须靠 broadcast
            // exit_cv 让等待者醒来查 VM_SIGNAL_PENDING 并返回 -EINTR 交回 safepoint。
            v->wakeup();
        }
    }
    if (tid != 0) {
        pthread_kill(tid, SIGUSR1);
    }
}

bool PosixSyscall::handle_signals(vm* v) {
    int sig = 0;
    if(!pending_signals.try_pop(sig)) {
        // Queue is empty. Clear VM_SIGNAL_PENDING with a seq_cst fence, then
        // re-check to close the race window with a concurrent queue_signal:
        // if another thread pushed between try_pop and the clear, the second
        // try_pop will catch it; if it pushed after the clear, it will have
        // set VM_SIGNAL_PENDING again, so the next safepoint() will retry.
        flags(v).fetch_and(~vm::VM_SIGNAL_PENDING, std::memory_order_seq_cst);
        if(!pending_signals.try_pop(sig)) {
            return true;
        }
        flags(v).fetch_or(vm::VM_SIGNAL_PENDING, std::memory_order_relaxed);
    }
    if(sig <= 0 || sig >= NSIG) {
        return true;
    }
    const uint64_t sig_dfl = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_DFL));
    const uint64_t sig_ign = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_IGN));
    uint64_t handler = ps->signal_actions[static_cast<size_t>(sig)].handler;
    if(options(v).verbose) {
        std::lock_guard<std::mutex> lock(log_mutex);
        printf("[#%d] signal %d handler=0x%lx return=0x%lx\n",
               id(), sig, static_cast<unsigned long>(handler), pc(v));
    }
    if(handler == sig_ign) {
        return true;
    }
    if(handler == sig_dfl) {
        switch(sig) {
        case SIGTERM:
        case SIGINT:
        case SIGABRT:
        case SIGSEGV:
        case SIGILL:
        case SIGFPE:
            // 致命信号默认动作 = 终止整个线程组（POSIX/Linux 语义：default action of
            // fatal signals is process termination，等价 exit_group），不只杀当前线程。
            v->r(1) = 128 + static_cast<uint64_t>(sig);
            return do_exit_group(v);
        case SIGTSTP:
        case SIGTTIN:
        case SIGTTOU:
            flags(v).fetch_or(vm::VM_STOPPED, std::memory_order_release);
            v->wakeup();
            return true;
        default:
            return true;
        }
    }

    if(!v->mmu(handler)) {
        v->r(1) = 128 + static_cast<uint64_t>(SIGSEGV);
        return do_exit_group(v);
    }
    if(!v->push_frame(pc(v), true)) {
        v->r(1) = 128 + static_cast<uint64_t>(SIGBUS);
        return do_exit_group(v);
    }
    v->r(1) = static_cast<uint64_t>(sig);
    pc(v) = handler;
    return true;
}

bool PosixSyscall::do_kill(vm* v) {
    int target_pid = arg_s32(v->r(1));
    int sig = arg_s32(v->r(2));
    if(sig < 0 || sig >= NSIG) {
        v->r(0) = -EINVAL;
        return true;
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
        v->r(0) = -ESRCH;
        return true;
    }

    // sig == 0：仅存在性检查，不发信号。
    if(sig == 0) {
        v->r(0) = 0;
        return true;
    }

    for(auto& t : targets) {
        options(t.get()).sys->queue_signal(t.get(), sig);
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_tkill(vm* v) {
    int tid = arg_s32(v->r(1));
    int sig = arg_s32(v->r(2));
    if(sig < 0 || sig >= NSIG || tid <= 0) {
        v->r(0) = -EINVAL;
        return true;
    }
    auto target_vm = find_task(static_cast<uint64_t>(tid));
    if(!target_vm) {
        v->r(0) = -ESRCH;
        return true;
    }
    if(sig == 0) {
        v->r(0) = 0;
        return true;
    }
    options(target_vm.get()).sys->queue_signal(target_vm.get(), sig);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_tgkill(vm* v) {
    int tgid_arg = arg_s32(v->r(1));
    int tid = arg_s32(v->r(2));
    int sig = arg_s32(v->r(3));
    if(sig < 0 || sig >= NSIG || tid <= 0 || tgid_arg <= 0) {
        v->r(0) = -EINVAL;
        return true;
    }
    auto target_vm = find_task(static_cast<uint64_t>(tid));
    if(!target_vm) {
        v->r(0) = -ESRCH;
        return true;
    }
    auto target = sys(target_vm.get());
    if(!target || target->tg->tgid != static_cast<uint64_t>(tgid_arg)) {
        v->r(0) = -ESRCH;
        return true;
    }
    if(sig == 0) {
        v->r(0) = 0;
        return true;
    }
    options(target_vm.get()).sys->queue_signal(target_vm.get(), sig);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_sigaction(vm* v) {
    int signo = arg_s32(v->r(1));
    uint64_t act_addr = v->r(2);
    uint64_t oldact_addr = v->r(3);

    if(signo <= 0 || signo >= NSIG || signo == SIGKILL || signo == SIGSTOP) {
        v->r(0) = -EINVAL;
        return true;
    }

    if(oldact_addr != 0) {
        auto oldact = static_cast<struct bpf::sigaction*>(v->mmu_w(oldact_addr, sizeof(struct bpf::sigaction)));
        if(oldact == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        const auto& current = ps->signal_actions[static_cast<size_t>(signo)];
        oldact->sa_handler = reinterpret_cast<void (*)(int)>(static_cast<uintptr_t>(current.handler));
        oldact->sa_mask = static_cast<bpf::sigset_t>(current.mask);
        oldact->sa_flags = current.flags;
    }

    if(act_addr != 0) {
        auto action = static_cast<const struct bpf::sigaction*>(v->mmu(act_addr));
        if(action == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        if(reinterpret_cast<uintptr_t>(action->sa_handler) == reinterpret_cast<uintptr_t>(SIG_ERR)) {
            v->r(0) = -EINVAL;
            return true;
        }
        auto& current = ps->signal_actions[static_cast<size_t>(signo)];
        current.handler = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(action->sa_handler));
        current.mask = static_cast<uint64_t>(action->sa_mask);
        current.flags = action->sa_flags;
    }

    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_setjmp(vm* v) {
    uint64_t env_addr = v->r(1);
    uint64_t* env = (uint64_t*)v->mmu_w(env_addr, 7 * sizeof(uint64_t));
    if (!env) {
        v->r(0) = -EFAULT;
        return true;
    }
    env[0] = v->r(6);
    env[1] = v->r(7);
    env[2] = v->r(8);
    env[3] = v->r(9);
    env[4] = v->r(10);
    env[5] = pc(v);
    env[6] = signal_depth(v);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_longjmp(vm* v) {
    uint64_t env_addr = v->r(1);
    int32_t val = arg_s32(v->r(2));
    uint64_t* env = (uint64_t*)v->mmu(env_addr);
    if (!env) {
        v->r(0) = -EFAULT;
        return true;
    }
    v->r(6) = env[0];
    v->r(7) = env[1];
    v->r(8) = env[2];
    v->r(9) = env[3];
    v->r(10) = env[4];
    uint64_t saved_pc = env[5];
    signal_depth(v) = static_cast<size_t>(env[6]);
    pc(v) = saved_pc;
    // pc points to syscall instruction.
    // loop increments pc.
    // next instruction is executed.

    v->r(0) = (val == 0) ? 1 : val;
    return true;
}
