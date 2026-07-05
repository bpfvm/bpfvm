#include "posix_internal.h"

int PosixSyscall::allocate_fd(int min_fd) {
    int fd = min_fd;
    while(ps->fds.count(fd)) {
        fd++;
    }
    return fd;
}

bool PosixSyscall::do_umask(vm* v) {
    uint32_t new_mask = arg_u32(v->r(1));
    v->r(0) = umask_val;
    umask_val = new_mask & 0777;
    return true;
}

bool PosixSyscall::do_dup(vm* v) {
    int old_fd = arg_s32(v->r(1));
    if(old_fd < 0) {
        v->r(0) = -EBADF;
        return true;
    }

    auto it = ps->fds.find(old_fd);
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }

    auto new_handle = it->second->clone();  // host dup host fd；GuestTty共享
    if(!new_handle) {
        v->r(0) = -errno;
        return true;
    }

    int new_fd = allocate_fd();
    ps->fds[new_fd] = new_handle;
    v->r(0) = new_fd;
    return true;
}

bool PosixSyscall::do_dup3(vm* v) {
    int old_fd = arg_s32(v->r(1));
    int new_fd = arg_s32(v->r(2));
    int flags = arg_s32(v->r(3));
    if(old_fd < 0 || new_fd < 0) {
        v->r(0) = -EBADF;
        return true;
    }
    if(old_fd == new_fd) {
        v->r(0) = -EINVAL;
        return true;
    }
    if(flags & ~O_CLOEXEC) {
        v->r(0) = -EINVAL;
        return true;
    }

    auto it = ps->fds.find(old_fd);
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }

    auto handle = it->second->clone();
    if(!handle) {
        v->r(0) = -errno;
        return true;
    }
    if(flags & O_CLOEXEC) {
        handle->cloexec = true;
    }
    // 若 new_fd 已被占用：dup2/dup3 静默关闭旧 fd（Linux 语义）。旧 fd 若是最后一个 master
    // 端，应触发 SIGHUP（drop_fd_handle 判断）。先 drop 再覆盖（覆盖的赋值会析构旧 shared_ptr）。
    auto existing = ps->fds.find(new_fd);
    if(existing != ps->fds.end()) {
        drop_fd_handle(v, existing->second);
    }
    ps->fds[new_fd] = handle;
    v->r(0) = new_fd;
    return true;
}

bool PosixSyscall::do_pipe2(vm* v) {
    int* pipefd = static_cast<int*>(v->mmu_w(v->r(1), 2 * sizeof(int)));
    if(pipefd == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }

    int flags = arg_s32(v->r(2));
    int host_fds[2] = {-1, -1};

    int rc = pipe2(host_fds, flags);
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }

    int guest_fd0 = allocate_fd();
    auto handle0 = std::make_shared<fd_handle>(host_fds[0]);
    if (flags & O_CLOEXEC) {
        handle0->cloexec = true;
    }
    ps->fds[guest_fd0] = handle0;

    int guest_fd1 = allocate_fd(guest_fd0 + 1);
    auto handle1 = std::make_shared<fd_handle>(host_fds[1]);
    if (flags & O_CLOEXEC) {
        handle1->cloexec = true;
    }
    ps->fds[guest_fd1] = handle1;

    pipefd[0] = guest_fd0;
    pipefd[1] = guest_fd1;
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_fcntl(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    int cmd = arg_s32(v->r(2));
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        int min_fd = arg_s32(v->r(3));
        if (min_fd < 0) {
            v->r(0) = -EINVAL;
            return true;
        }

        auto new_handle = it->second->clone();
        if(!new_handle) {
            v->r(0) = -errno;
            return true;
        }

        int new_fd = allocate_fd(min_fd);
        if (cmd == F_DUPFD_CLOEXEC) {
            new_handle->cloexec = true;
        }
        ps->fds[new_fd] = new_handle;
        v->r(0) = new_fd;
        return true;
    }
    if (cmd == F_GETFD) {
        v->r(0) = it->second->cloexec ? FD_CLOEXEC : 0;
        return true;
    }
    if (cmd == F_SETFD) {
        it->second->cloexec = (v->r(3) & FD_CLOEXEC) != 0;
        v->r(0) = 0;
        return true;
    }

    uint64_t arg = v->r(3);
    int rc = -1;
    if (cmd == F_GETLK) {
            void* guest_arg = v->mmu_w(arg, sizeof(struct flock));
            if(guest_arg == nullptr) {
                v->r(0) = -EFAULT;
                return true;
            }
            rc = fcntl(it->second->fd, cmd, guest_arg);
    } else if (cmd == F_SETLK || cmd == F_SETLKW) {
            void* guest_arg = v->mmu(arg, sizeof(struct flock));
            if(guest_arg == nullptr) {
                v->r(0) = -EFAULT;
                return true;
            }
            rc = fcntl(it->second->fd, cmd, guest_arg);
    } else {
            rc = fcntl(it->second->fd, cmd, arg);
    }

    if(rc == -1) {
        v->r(0) = -errno;
    } else {
        v->r(0) = rc;
    }
    return true;
}

bool PosixSyscall::do_ioctl(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    unsigned long request = v->r(2);

    // 终端属性 (TCGETS/TCSETS/...)、winsize (TIOCGWINSZ/TIOCSWINSZ)、ptmx 锁/编号
    // (TIOCSPTLCK/TIOCGPTN) 等透传 host 内核（host ioctl 直通，由 host n_tty 处理）。
    // 只有 job-control 类（TIOCSCTTY/TIOCSPGRP/TIOCGPGRP）是 guest 进程语义，bpfvm 自己管。
    if (request == TIOCSCTTY) {
        // 绑定控制终端。语义：arg==1 强制（即使已被别的 session 占也夺），arg==0 仅在无人
        // 占用时绑定。前提：调用者须是 session leader（setsid 后），fd 是 pty 设备，否则错。
        const auto& tty = it->second->tty;
        if(!tty) {
            v->r(0) = -ENOTTY;
            return true;
        }
        if(!session || session->sid != pid) {  // session leader 检查
            v->r(0) = -EPERM;
            return true;
        }
        int force = arg_s32(v->r(3));
        // 本会话已绑同一 tty：幂等成功。
        if(session->ctty.get() == tty.get()) {
            v->r(0) = 0;
            return true;
        }
        // tty 已被别的 session 占用？持 pid_map_mutex 保护 owner_ 读写（防抢夺竞态）。
        {
            std::lock_guard<std::mutex> lock(pid_map_mutex);
            if(tty->owner_ != nullptr && tty->owner_ != session.get()) {
                if(!force) {
                    v->r(0) = -EPERM;
                    return true;
                }
                // force 抢夺：解除原 session 的 ctty 引用。
                tty->owner_->ctty.reset();
            }
            // 绑定：session->ctty 指向 GuestTty，owner_ 反指 session，前台组初始化为自身。
            session->ctty = tty;
            tty->owner_ = session.get();
        }
        tty->fg_pgrp.store(pgrp->pgid, std::memory_order_release);
        v->r(0) = 0;
        return true;
    } else if (request == TIOCSPGRP) {
        // 设置前台进程组（tcsetpgrp）。musl 的 tcsetpgrp 传指向 int 的指针（&pgrp），
        // 故 r(3) 是 guest 指针，需 mmu 取值。仅更新本 ctty 的 fg_pgrp，供 deliver_tty_signal
        // 选目标组。POSIX：fd 必须是本会话 ctty，否则 ENOTTY。
        if(!session || !session->ctty || it->second->tty.get() != session->ctty.get()) {
            v->r(0) = -ENOTTY;
            return true;
        }
        const pid_t* in = (const pid_t*)v->mmu(v->r(3), sizeof(pid_t));
        if(in == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        pid_t g_pgid = *in;
        if(g_pgid <= 0) {
            v->r(0) = -EINVAL;
            return true;
        }
        // 校验目标 pgrp 存在且同 session（Linux：不存在/跨 session→EPERM）。
        bool found = false;
        {
            std::lock_guard<std::mutex> lock(pid_map_mutex);
            for(const auto& entry : pid_map) {
                auto s = sys(entry.second.get());
                if(s && s->session.get() == session.get() && s->pgrp->pgid == static_cast<uint64_t>(g_pgid)) {
                    found = true;
                    break;
                }
            }
        }
        if(!found) {
            v->r(0) = -EPERM;
            return true;
        }
        session->ctty->fg_pgrp.store(static_cast<uint64_t>(g_pgid), std::memory_order_release);
        v->r(0) = 0;
        return true;
    } else if (request == TIOCGPGRP) {
        // 读取前台进程组（tcgetpgrp）。fd 必须是本会话 ctty，否则 ENOTTY。
        if(!session || !session->ctty || it->second->tty.get() != session->ctty.get()) {
            v->r(0) = -ENOTTY;
            return true;
        }
        pid_t* out = (pid_t*)v->mmu_w(v->r(3), sizeof(pid_t));
        if(out == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        *out = (pid_t)session->ctty->fg_pgrp.load(std::memory_order_acquire);
        v->r(0) = 0;
        return true;
    } else {
        // 通用 ioctl（含 TCGETS/TCSETS/TIOCGWINSZ/TIOCSPTLCK/TIOCGPTN...）：把 guest 指针按
        // 方向翻译成 host 指针，再透传 host 内核。这些是 ldisc/设备属性，host n_tty 处理得
        // 比我们正确。旧式终端 ioctl（TCGETS/TIOCGWINSZ/...）用固定方向编码：明确方向以便
        // 正确翻译 guest 指针（旧值如 TIOCGWINSZ=0x5413 不含 _IOC_DIR 位，按已知方向显式判定）。
        bool write_back = false;   // TCGETS/TIOCGWINSZ：host 写回 guest 缓冲（需 mmu_w）
        size_t psize = 0;
        if(request == TCGETS || request == TCSETS || request == TCSETSW || request == TCSETSF) {
            write_back = (request == TCGETS);
            psize = sizeof(struct termios);
        } else if(request == TIOCGWINSZ || request == TIOCSWINSZ) {
            write_back = (request == TIOCGWINSZ);
            psize = sizeof(struct winsize);
        } else {
            // 其余（含 TIOCSPTLCK/TIOCGPTN 及任意 dir-encoded ioctl）：按 Linux 编码判方向。
            size_t ioctl_size = (request >> 16) & 0x3FFF;
            psize = ioctl_size;
            if(ioctl_size) {
                int dir = _IOC_DIR(request);
                write_back = (dir & _IOC_READ) != 0;
            }
            // 既非已知终端 ioctl 又无 size 编码：arg 当作无指针（r(3) 即值本身），透传。
        }
        void* arg = nullptr;
        if(psize) {
            arg = write_back ? v->mmu_w(v->r(3), psize) : v->mmu(v->r(3), psize);
            if(arg == nullptr) {
                v->r(0) = -EFAULT;
                return true;
            }
        } else {
            arg = (void*)v->r(3);
        }
        int rc = ioctl(it->second->fd, request, arg);
        if(rc == -1) {
            v->r(0) = -errno;
        } else {
            v->r(0) = rc;
        }
        return true;
    }
}
