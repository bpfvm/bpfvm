#include "posix_internal.h"

int64_t PosixSyscall::do_setpgid(vm* v) {
    pid_t pid_arg = arg_s32(v->r(1));
    pid_t pgrp_arg = arg_s32(v->r(2));
    if(pgrp_arg < 0) {
        return -EINVAL;
    }

    // 解析目标 task：pid_arg==0 → 自身；否则必须是自身或子进程。
    std::shared_ptr<vm> target_vm;
    PosixSyscall* target = nullptr;
    if(pid_arg == 0) {
        target = this;
    } else {
        target_vm = find_task(static_cast<uint64_t>(pid_arg));
        if(!target_vm) {
            return -ESRCH;
        }
        target = sys(target_vm.get()).get();
        if(!target) {
            return -ESRCH;
        }
        // 仅允许改自身或子进程（ppid 记的是父 tg->tgid，故用 tg->tgid 匹配）
        if(static_cast<uint64_t>(pid_arg) != tg->tgid && target->ppid.load() != tg->tgid) {
            return -ESRCH;
        }
    }

    // 跨 session 禁止
    if(target->session.get() != session.get()) {
        return -EPERM;
    }
    // session leader 不可改 pgrp
    if(target->session->sid == target->pid) {
        return -EPERM;
    }
    // 已是目标组成员且 pgid 一致：no-op
    if(target->pgrp->pgid == static_cast<uint64_t>(pgrp_arg) && pgrp_arg != 0) {
        return 0;
    }

    // 解析新 pgid：pgrp_arg==0 → 目标自身 pid（新建组）
    uint64_t new_pgid = (pgrp_arg == 0) ? target->pid : static_cast<uint64_t>(pgrp_arg);

    // 若 new_pgid != 目标 pid，必须存在同 session 的进程以该 pid 为 pgid leader
    //（即某进程 pid == new_pgid 且同 session）。
    if(new_pgid != target->pid) {
        std::shared_ptr<vm> leader_vm = find_task(new_pgid);
        if(!leader_vm) {
            return -EPERM;
        }
        auto leader = sys(leader_vm.get());
        if(!leader || leader->session.get() != session.get()) {
            return -EPERM;
        }
    }

    target->pgrp = std::make_shared<ProcessGroup>(new_pgid, target->session);
    return 0;
}

int64_t PosixSyscall::do_getpgid(vm* v) {
    pid_t pid_arg = arg_s32(v->r(1));
    if(pid_arg == 0) {
        return (int64_t)pgrp->pgid;
    }
    auto target_vm = find_task(static_cast<uint64_t>(pid_arg));
    if(!target_vm) {
        return -ESRCH;
    }
    auto target = sys(target_vm.get());
    if(!target) {
        return -ESRCH;
    }
    return (int64_t)target->pgrp->pgid;
}

int64_t PosixSyscall::do_getpgrp(vm*) {
    return (int64_t)pgrp->pgid;
}

int64_t PosixSyscall::do_setsid(vm*) {
    // 已是进程组 leader → EPERM
    if(pgrp->pgid == pid) {
        return -EPERM;
    }
    auto new_session = std::make_shared<Session>(pid);
    pgrp = std::make_shared<ProcessGroup>(pid, new_session);
    session = new_session;
    return (int64_t)pid;
}

int64_t PosixSyscall::do_getsid(vm* v) {
    pid_t pid_arg = arg_s32(v->r(1));
    if(pid_arg == 0) {
        return (int64_t)session->sid;
    }
    auto target_vm = find_task(static_cast<uint64_t>(pid_arg));
    if(!target_vm) {
        return -ESRCH;
    }
    auto target = sys(target_vm.get());
    if(!target) {
        return -ESRCH;
    }
    return (int64_t)target->session->sid;
}
