#include "posix_internal.h"

int PosixSyscall::allocate_fd(int min_fd) {
    int fd = min_fd;
    while(ps->fds.count(fd)) {
        fd++;
    }
    return fd;
}

int64_t PosixSyscall::do_umask(vm* v) {
    uint32_t new_mask = arg_u32(v->r(1));
    int old = umask_val;
    umask_val = new_mask & 0777;
    return old;
}

int64_t PosixSyscall::do_dup(vm* v) {
    int old_fd = arg_s32(v->r(1));
    if(old_fd < 0) {
        return -EBADF;
    }

    auto it = ps->fds.find(old_fd);
    if(it == ps->fds.end()) {
        return -EBADF;
    }

    auto new_handle = it->second->clone();  // host dup host fd；GuestTty共享
    if(!new_handle) {
        return -errno;
    }

    int new_fd = allocate_fd();
    ps->fds[new_fd] = new_handle;
    return new_fd;
}

int64_t PosixSyscall::do_dup3(vm* v) {
    int old_fd = arg_s32(v->r(1));
    int new_fd = arg_s32(v->r(2));
    int flags = arg_s32(v->r(3));
    if(old_fd < 0 || new_fd < 0) {
        return -EBADF;
    }
    if(old_fd == new_fd) {
        return -EINVAL;
    }
    if(flags & ~O_CLOEXEC) {
        return -EINVAL;
    }

    auto it = ps->fds.find(old_fd);
    if(it == ps->fds.end()) {
        return -EBADF;
    }

    auto handle = it->second->clone();
    if(!handle) {
        return -errno;
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
    return new_fd;
}

int64_t PosixSyscall::do_pipe2(vm* v) {
    int* pipefd = static_cast<int*>(v->mmu_w(v->r(1), 2 * sizeof(int)));
    if(pipefd == nullptr) {
        return -EFAULT;
    }

    int flags = arg_s32(v->r(2));
    int host_fds[2] = {-1, -1};

    int rc = pipe2(host_fds, flags);
    if(rc == -1) {
        return -errno;
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
    return 0;
}

int64_t PosixSyscall::do_fcntl(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        return -EBADF;
    }
    int cmd = arg_s32(v->r(2));
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        int min_fd = arg_s32(v->r(3));
        if (min_fd < 0) {
            return -EINVAL;
        }

        auto new_handle = it->second->clone();
        if(!new_handle) {
            return -errno;
        }

        int new_fd = allocate_fd(min_fd);
        if (cmd == F_DUPFD_CLOEXEC) {
            new_handle->cloexec = true;
        }
        ps->fds[new_fd] = new_handle;
        return new_fd;
    }
    if (cmd == F_GETFD) {
        return it->second->cloexec ? FD_CLOEXEC : 0;
    }
    if (cmd == F_SETFD) {
        it->second->cloexec = (v->r(3) & FD_CLOEXEC) != 0;
        return 0;
    }

    uint64_t arg = v->r(3);
    int rc = -1;
    if (cmd == F_GETLK) {
            void* guest_arg = v->mmu_w(arg, sizeof(struct flock));
            if(guest_arg == nullptr) {
                return -EFAULT;
            }
            rc = fcntl(it->second->fd, cmd, guest_arg);
    } else if (cmd == F_SETLK || cmd == F_SETLKW) {
            void* guest_arg = v->mmu(arg, sizeof(struct flock));
            if(guest_arg == nullptr) {
                return -EFAULT;
            }
            rc = fcntl(it->second->fd, cmd, guest_arg);
    } else {
            rc = fcntl(it->second->fd, cmd, arg);
    }

    if(rc == -1) {
        return -errno;
    }
    return rc;
}

int64_t PosixSyscall::do_ioctl(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        return -EBADF;
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
            return -ENOTTY;
        }
        if(!session || session->sid != pid) {  // session leader 检查
            return -EPERM;
        }
        int force = arg_s32(v->r(3));
        // 本会话已绑同一 tty：幂等成功。
        if(session->ctty.get() == tty.get()) {
            return 0;
        }
        // tty 已被别的 session 占用？持 pid_map_mutex 保护 owner_ 读写（防抢夺竞态）。
        {
            std::lock_guard<std::mutex> lock(pid_map_mutex);
            if(tty->owner_ != nullptr && tty->owner_ != session.get()) {
                if(!force) {
                    return -EPERM;
                }
                // force 抢夺：解除原 session 的 ctty 引用。
                tty->owner_->ctty.reset();
            }
            // 绑定：session->ctty 指向 GuestTty，owner_ 反指 session，前台组初始化为自身。
            session->ctty = tty;
            tty->owner_ = session.get();
        }
        tty->fg_pgrp.store(pgrp->pgid, std::memory_order_release);
        return 0;
    } else if (request == TIOCSPGRP) {
        // 设置前台进程组（tcsetpgrp）。musl 的 tcsetpgrp 传指向 int 的指针（&pgrp），
        // 故 r(3) 是 guest 指针，需 mmu 取值。仅更新本 ctty 的 fg_pgrp，供 deliver_tty_signal
        // 选目标组。POSIX：fd 必须是本会话 ctty，否则 ENOTTY。
        if(!session || !session->ctty || it->second->tty.get() != session->ctty.get()) {
            return -ENOTTY;
        }
        const pid_t* in = (const pid_t*)v->mmu(v->r(3), sizeof(pid_t));
        if(in == nullptr) {
            return -EFAULT;
        }
        pid_t g_pgid = *in;
        if(g_pgid <= 0) {
            return -EINVAL;
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
            return -EPERM;
        }
        session->ctty->fg_pgrp.store(static_cast<uint64_t>(g_pgid), std::memory_order_release);
        return 0;
    } else if (request == TIOCGPGRP) {
        // 读取前台进程组（tcgetpgrp）。fd 必须是本会话 ctty，否则 ENOTTY。
        if(!session || !session->ctty || it->second->tty.get() != session->ctty.get()) {
            return -ENOTTY;
        }
        pid_t* out = (pid_t*)v->mmu_w(v->r(3), sizeof(pid_t));
        if(out == nullptr) {
            return -EFAULT;
        }
        *out = (pid_t)session->ctty->fg_pgrp.load(std::memory_order_acquire);
        return 0;
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
                return -EFAULT;
            }
        } else {
            arg = (void*)v->r(3);
        }
        int rc = ioctl(it->second->fd, request, arg);
        if(rc == -1) {
            return -errno;
        }
        return rc;
    }
}

int64_t PosixSyscall::do_poll(vm* v) {
    // guest/host 的 struct pollfd 布局一致（{int fd; short events; short revents;}），
    // 故把 guest 数组当作 host 数组就地读写；唯一要做的是 guest fd → host fd 翻译。
    nfds_t n = arg_size(v->r(2));
    int timeout = arg_s32(v->r(3));  // ms；负数=永久阻塞，0=非阻塞

    // n 上限：Linux 上 poll 会校验 nfds > RLIMIT_NOFILE → EINVAL。bpfvm 无 rlimit 概念，
    // 给一个固定上限，避免 guest 传极大 n 导致下面的 vector(n) 全量构造时 bad_alloc/OOM。
    if(n > 1024) {
        return -EINVAL;
    }

    struct pollfd* gfds = nullptr;
    if(n > 0) {
        // 翻译整段数组（mmu_w 校验 [addr, addr+size) 全在映射范围内）。
        gfds = static_cast<struct pollfd*>(v->mmu_w(v->r(1), sizeof(struct pollfd) * n));
        if(gfds == nullptr) {
            return -EFAULT;
        }
    }

    // 构造 host 侧数组：合法 guest fd 翻译成对应 host fd；非法 guest fd（不在 ps->fds 表内）
    // 用 fd=-1 让宿主 poll 忽略该条，并在 guest 上预填 POLLNVAL（POSIX：fd 不打开算"事件"）。
    // guest fd<0（POSIX：忽略此条）同样置 host fd=-1，但 revents 清零。
    std::vector<struct pollfd> hfds(n);
    std::vector<char> valid(n, 0);
    nfds_t invalid_count = 0;
    for(nfds_t i = 0; i < n; ++i) {
        hfds[i].events = gfds[i].events;
        hfds[i].revents = 0;

        int gfd = gfds[i].fd;
        gfds[i].revents = 0;
        if(gfd < 0) {
            hfds[i].fd = -1;          // 宿主 poll 跳过；guest revents 维持 0（POSIX：负 fd 条目）
            continue;
        }
        auto it = ps->fds.find(gfd);
        if(it == ps->fds.end()) {
            hfds[i].fd = -1;          // 让宿主 poll 忽略；POLLNVAL 由我们直接写回 guest
            gfds[i].revents = POLLNVAL;
            invalid_count++;
            continue;
        }
        hfds[i].fd = it->second->fd;
        valid[i] = 1;
    }

    // 直接阻塞在宿主 poll。timeout(ms) 直接透传；信号路径下 queue_signal 会
    // pthread_kill(SIGUSR1) 把宿主 poll 踢出 EINTR，符合 poll 不被 SA_RESTART 重启的语义，
    // POLLNVAL 是"就绪事件"，POSIX 要求 poll 见到就绪条目立即返回——而我们已把非法 fd 屏蔽
    // 成 fd=-1，宿主 poll 感知不到它们。若已手握 invalid_count 条 POLLNVAL，强制 timeout=0
    // 非阻塞，否则当所有合法 fd 未就绪时会等满 timeout（timeout<0 时甚至永久挂起）。
    int rc = ::poll(hfds.data(), n, invalid_count > 0 ? 0 : timeout);
    if(rc == -1) {
        return -errno;             // EINTR/EFAULT/ENOMEM 等
    }

    // 把 host revents 写回 guest（仅对翻译过的合法条目）。
    for(nfds_t i = 0; i < n; ++i) {
        if(!valid[i]) {
            continue;
        }
        gfds[i].revents = hfds[i].revents;
    }
    // POLLNVAL 条目按 POSIX 也算"有事件"，加入返回计数。
    return rc + invalid_count;
}
