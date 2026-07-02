#include "posix_internal.h"

bool PosixSyscall::do_setpgid(vm* v) {
    pid_t pid_arg = arg_s32(v->r(1));
    pid_t pgrp_arg = arg_s32(v->r(2));
    if(pgrp_arg < 0) {
        v->r(0) = -EINVAL;
        return true;
    }

    // 解析目标 task：pid_arg==0 → 自身；否则必须是自身或子进程。
    std::shared_ptr<vm> target_vm;
    PosixSyscall* target = nullptr;
    if(pid_arg == 0) {
        target = this;
    } else {
        target_vm = find_task(static_cast<uint64_t>(pid_arg));
        if(!target_vm) {
            v->r(0) = -ESRCH;
            return true;
        }
        target = sys(target_vm.get()).get();
        if(!target) {
            v->r(0) = -ESRCH;
            return true;
        }
        // 仅允许改自身或子进程（ppid 记的是父 tg->tgid，故用 tg->tgid 匹配）
        if(static_cast<uint64_t>(pid_arg) != tg->tgid && target->ppid.load() != tg->tgid) {
            v->r(0) = -ESRCH;
            return true;
        }
    }

    // 跨 session 禁止
    if(target->session.get() != session.get()) {
        v->r(0) = -EPERM;
        return true;
    }
    // session leader 不可改 pgrp
    if(target->session->sid == target->pid) {
        v->r(0) = -EPERM;
        return true;
    }
    // 已是目标组成员且 pgid 一致：no-op
    if(target->pgrp->pgid == static_cast<uint64_t>(pgrp_arg) && pgrp_arg != 0) {
        v->r(0) = 0;
        return true;
    }

    // 解析新 pgid：pgrp_arg==0 → 目标自身 pid（新建组）
    uint64_t new_pgid = (pgrp_arg == 0) ? target->pid : static_cast<uint64_t>(pgrp_arg);

    // 若 new_pgid != 目标 pid，必须存在同 session 的进程以该 pid 为 pgid leader
    //（即某进程 pid == new_pgid 且同 session）。
    if(new_pgid != target->pid) {
        std::shared_ptr<vm> leader_vm = find_task(new_pgid);
        if(!leader_vm) {
            v->r(0) = -EPERM;
            return true;
        }
        auto leader = sys(leader_vm.get());
        if(!leader || leader->session.get() != session.get()) {
            v->r(0) = -EPERM;
            return true;
        }
    }

    target->pgrp = std::make_shared<ProcessGroup>(new_pgid, target->session);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_getpgid(vm* v) {
    pid_t pid_arg = arg_s32(v->r(1));
    if(pid_arg == 0) {
        v->r(0) = pgrp->pgid;
        return true;
    }
    auto target_vm = find_task(static_cast<uint64_t>(pid_arg));
    if(!target_vm) {
        v->r(0) = -ESRCH;
        return true;
    }
    auto target = sys(target_vm.get());
    if(!target) {
        v->r(0) = -ESRCH;
        return true;
    }
    v->r(0) = target->pgrp->pgid;
    return true;
}

bool PosixSyscall::do_getpgrp(vm* v) {
    v->r(0) = pgrp->pgid;
    return true;
}

bool PosixSyscall::do_setsid(vm* v) {
    // 已是进程组 leader → EPERM
    if(pgrp->pgid == pid) {
        v->r(0) = -EPERM;
        return true;
    }
    auto new_session = std::make_shared<Session>(pid);
    pgrp = std::make_shared<ProcessGroup>(pid, new_session);
    session = new_session;
    v->r(0) = pid;
    return true;
}

bool PosixSyscall::do_getsid(vm* v) {
    pid_t pid_arg = arg_s32(v->r(1));
    if(pid_arg == 0) {
        v->r(0) = session->sid;
        return true;
    }
    auto target_vm = find_task(static_cast<uint64_t>(pid_arg));
    if(!target_vm) {
        v->r(0) = -ESRCH;
        return true;
    }
    auto target = sys(target_vm.get());
    if(!target) {
        v->r(0) = -ESRCH;
        return true;
    }
    v->r(0) = target->session->sid;
    return true;
}
