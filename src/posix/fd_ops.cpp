#include "posix_internal.h"

#include <asm/ioctl.h>
#include <sys/ioctl.h>   // FIONBIO/FIONREAD（socket 非阻塞/可读字节查询，OpenSSL BIO 用）
#include <sys/select.h>  // fd_set / FD_ZERO / FD_SET（do_pselect6）

int64_t PosixSyscall::do_umask(vm* v) {
    uint32_t new_mask = arg_u32(v->r(1));
    int old = ps->umask;
    ps->umask = new_mask & 0777;
    return old;
}

int64_t PosixSyscall::do_dup(vm* v) {
    int old_fd = arg_s32(v->r(1));
    if(old_fd < 0) {
        return -EBADF;
    }

    auto h = ps->find_fd(old_fd);
    if(!h) {
        return -EBADF;
    }

    auto new_handle = h->clone();  // host dup host fd；GuestTty共享
    if(!new_handle) {
        return -errno;
    }

    return ps->fds_emplace(new_handle);
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

    auto old_h = ps->find_fd(old_fd);
    if(!old_h) {
        return -EBADF;
    }

    auto handle = old_h->clone();
    if(!handle) {
        return -errno;
    }
    if(flags & O_CLOEXEC) {
        handle->cloexec = true;
    }
    // 若 new_fd 已被占用：dup2/dup3 静默关闭旧 fd（Linux 语义）。旧 fd 若是最后一个
    // master 端，on_close 触发 SIGHUP。on_close 在锁外（投 SIGHUP 不能在 fds_mutate
    // 重试循环里）。
    auto existing = ps->find_fd(new_fd);
    if(existing) {
        existing->on_close(this, v);
    }
    ps->fds_mutate([&](SharedState::FdMap& m){
        m[new_fd] = handle;
    });
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

    auto handle0 = std::make_shared<HostFd>(host_fds[0]);
    if (flags & O_CLOEXEC) {
        handle0->cloexec = true;
    }
    auto handle1 = std::make_shared<HostFd>(host_fds[1]);
    if (flags & O_CLOEXEC) {
        handle1->cloexec = true;
    }
    // 两端在同一个 mutate 内分配，保证不抢同号。Linux 不要求两端连续，从 fd0+1 找
    // 第二个空号尽量相邻。
    int guest_fd0 = -1, guest_fd1 = -1;
    ps->fds_mutate([&](SharedState::FdMap& m){
        guest_fd0 = 0;
        while(m.count(guest_fd0)) guest_fd0++;
        guest_fd1 = guest_fd0 + 1;
        while(m.count(guest_fd1)) guest_fd1++;
        m[guest_fd0] = handle0;
        m[guest_fd1] = handle1;
    });

    pipefd[0] = guest_fd0;
    pipefd[1] = guest_fd1;
    return 0;
}

int64_t PosixSyscall::do_fcntl(vm* v) {
    auto h = ps->find_fd(arg_s32(v->r(1)));
    if(!h) {
        return -EBADF;
    }
    int cmd = arg_s32(v->r(2));
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        int min_fd = arg_s32(v->r(3));
        if (min_fd < 0) {
            return -EINVAL;
        }

        auto new_handle = h->clone();
        if(!new_handle) {
            return -errno;
        }
        if (cmd == F_DUPFD_CLOEXEC) {
            new_handle->cloexec = true;
        }
        return ps->fds_emplace(new_handle, min_fd);
    }
    if (cmd == F_GETFD) {
        return h->cloexec ? FD_CLOEXEC : 0;
    }
    if (cmd == F_SETFD) {
        // cloexec 是该 fd 号的属性，直接改 shared Fd 对象即可。并发 fcntl 与操作
        // 之间有固有竞态（与 Linux 一致），后续读快照立即看到新值。
        h->cloexec = (v->r(3) & FD_CLOEXEC) != 0;
        return 0;
    }
    // 虚拟 /proc fd（host_fd() < 0）：其余 fcntl cmd（F_GETFL/F_GETLK/...）无意义，返回 EINVAL。
    int hfd = h->host_fd();
    if(hfd < 0) {
        return -EINVAL;
    }

    uint64_t arg = v->r(3);
    int rc = -1;
    if (cmd == F_GETLK) {
        void* guest_arg = v->mmu_w(arg, sizeof(struct flock));
        if(guest_arg == nullptr) {
            return -EFAULT;
        }
        rc = fcntl(hfd, cmd, guest_arg);
    } else if (cmd == F_SETLK || cmd == F_SETLKW) {
        void* guest_arg = v->mmu(arg, sizeof(struct flock));
        if(guest_arg == nullptr) {
            return -EFAULT;
        }
        rc = fcntl(hfd, cmd, guest_arg);
    } else {
        rc = fcntl(hfd, cmd, arg);
    }

    if(rc == -1) {
        return -errno;
    }
    return rc;
}

int64_t PosixSyscall::do_ioctl(vm* v) {
    auto h = ps->find_fd(arg_s32(v->r(1)));
    if(!h) {
        return -EBADF;
    }
    unsigned long request = v->r(2);

    // tty 身份（pty 设备才有；普通 host fd / 虚拟 /proc fd 此处为 nullptr）。
    // TIOCSCTTY/TIOCSPGRP/TIOCGPGRP 三个分支据此判 ctty 身份，nullptr 即 ENOTTY 短路。
    auto dfd = std::dynamic_pointer_cast<DevFd>(h).get();
    GuestTty* tty = dfd ? dfd->guest_tty().get() : nullptr;

    // 终端属性 (TCGETS/TCSETS/...)、winsize (TIOCGWINSZ/TIOCSWINSZ)、ptmx 锁/编号
    // (TIOCSPTLCK/TIOCGPTN) 等透传 host 内核（host ioctl 直通，由 host n_tty 处理）。
    // 只有 job-control 类（TIOCSCTTY/TIOCSPGRP/TIOCGPGRP）是 guest 进程语义，bpfvm 自己管。
    if (request == TIOCSCTTY) {
        // 绑定控制终端。语义：arg==1 强制（即使已被别的 session 占也夺），arg==0 仅在无人
        // 占用时绑定。前提：调用者须是 session leader（setsid 后），fd 是 pty 设备，否则错。
        if(!tty) {
            return -ENOTTY;
        }
        if(!session || session->sid != pid) {  // session leader 检查
            return -EPERM;
        }
        int force = arg_s32(v->r(3));
        // 本会话已绑同一 tty：幂等成功。
        if(session->ctty.get() == tty) {
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
            session->ctty = dfd->guest_tty();
            tty->owner_ = session.get();
        }
        tty->fg_pgrp.store(pgrp->pgid, std::memory_order_release);
        return 0;
    } else if (request == TIOCSPGRP) {
        // 设置前台进程组（tcsetpgrp）。musl 的 tcsetpgrp 传指向 int 的指针（&pgrp），
        // 故 r(3) 是 guest 指针，需 mmu 取值。仅更新本 ctty 的 fg_pgrp，供 deliver_tty_signal
        // 选目标组。POSIX：fd 必须是本会话 ctty，否则 ENOTTY。
        if(!session || !session->ctty || tty != session->ctty.get()) {
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
        // 校验目标 pgrp 存在且同 session（Linux：不存在/跨 session->EPERM）。
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
        if(!session || !session->ctty || tty != session->ctty.get()) {
            return -ENOTTY;
        }
        pid_t* out = (pid_t*)v->mmu_w(v->r(3), sizeof(pid_t));
        if(out == nullptr) {
            return -EFAULT;
        }
        *out = (pid_t)session->ctty->fg_pgrp.load(std::memory_order_acquire);
        return 0;
    } else {
        // 虚拟 /proc fd（host_fd() < 0）：无 host fd，ioctl 无意义，返回 ENOTTY。
        int hfd = h->host_fd();
        if(hfd < 0) {
            return -ENOTTY;
        }
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
        } else if(request == FIONBIO || request == FIONREAD) {
            // FIONBIO/FIONREAD：旧式无 _IOC_DIR 编码的 ioctl，arg 指向 int。
            // FIONBIO 读取该 int（非阻塞标志），FIONREAD 写回该 int（可读字节数）。
            // 与 _IOC_DIR 探测分支（psize=0 -> arg 当裸值）不同，这两个必须翻译指针。
            write_back = (request == FIONREAD);
            psize = sizeof(int);
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
        int rc = ioctl(hfd, request, arg);
        if(rc == -1) {
            return -errno;
        }
        return rc;
    }
}

int64_t PosixSyscall::do_poll(vm* v) {
    // guest/host 的 struct pollfd 布局一致（{int fd; short events; short revents;}），
    // 故把 guest 数组当作 host 数组就地读写；唯一要做的是 guest fd -> host fd 翻译。
    nfds_t n = arg_size(v->r(2));
    int timeout = arg_s32(v->r(3));  // ms；负数=永久阻塞，0=非阻塞

    // n 上限：Linux 上 poll 会校验 nfds > RLIMIT_NOFILE -> EINVAL。bpfvm 无 rlimit 概念，
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
    nfds_t invalid_count = 0;  // POLLNVAL 条目数（非法 guest fd）
    nfds_t ready_count = 0;    // 已就地回填 revents 的条目数（虚拟 /proc fd 立即就绪）
    for(nfds_t i = 0; i < n; ++i) {
        hfds[i].events = gfds[i].events;
        hfds[i].revents = 0;

        int gfd = gfds[i].fd;
        gfds[i].revents = 0;
        if(gfd < 0) {
            hfds[i].fd = -1;          // 宿主 poll 跳过；guest revents 维持 0（POSIX：负 fd 条目）
            continue;
        }
        auto fd_h = ps->find_fd(gfd);
        if(!fd_h) {
            hfds[i].fd = -1;          // 让宿主 poll 忽略；POLLNVAL 由我们直接写回 guest
            gfds[i].revents = POLLNVAL;
            invalid_count++;
            continue;
        }
        int hfd = fd_h->host_fd();
        if(hfd < 0) {
            hfds[i].fd = -1;
            gfds[i].revents = gfds[i].events & (POLLIN | POLLOUT);
            valid[i] = 0;  // 不走 host revents 回写，直接用上面设的值
            ready_count++;  // 计入"已就绪"使 poll 立即返回（与 POLLNVAL 同效果，分离计数以求清晰）
            continue;
        }
        hfds[i].fd = hfd;
        valid[i] = 1;
    }

    // 直接阻塞在宿主 poll。timeout(ms) 直接透传；信号路径下 queue_signal 会
    // pthread_kill(SIGUSR1) 把宿主 poll 踢出 EINTR，符合 poll 不被 SA_RESTART 重启的语义。
    // POLLNVAL 与虚拟 fd 的就地就绪都是"已发生事件"立即返回
    nfds_t preset = invalid_count + ready_count;
    int rc = ::poll(hfds.data(), n, preset > 0 ? 0 : timeout);
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
    // POLLNVAL 与就地就绪条目按 POSIX 都算"有事件"，加入返回计数。
    return rc + preset;
}

int64_t PosixSyscall::do_pselect6(vm* v) {
    // pselect6(n, fd_set* rfds, fd_set* wfds, fd_set* efds, timespec* ts, sigmask_data*)
    // select() 在 musl 里经 BpfWideArgs 转成本调用（6 参）。把 fd_set 位图转成 pollfd
    // 数组复用 host poll，再把 revents 写回位图。ts==NULL 表示永久阻塞。
    int n = arg_s32(v->r(1));
    if(n < 0) return -EINVAL;
    if(n > FD_SETSIZE) n = FD_SETSIZE;  // OpenSSL 传 fd<FD_SETSIZE；超过无意义

    fd_set *grfds = (fd_set*)v->r(2) ? (fd_set*)v->mmu_w(v->r(2), sizeof(fd_set)) : nullptr;
    fd_set *gwfds = (fd_set*)v->r(3) ? (fd_set*)v->mmu_w(v->r(3), sizeof(fd_set)) : nullptr;
    fd_set *gefds = (fd_set*)v->r(4) ? (fd_set*)v->mmu_w(v->r(4), sizeof(fd_set)) : nullptr;
    if((v->r(2) && !grfds) || (v->r(3) && !gwfds) || (v->r(4) && !gefds)) {
        return -EFAULT;
    }
    // 超时：pselect6 第 5 参是 timespec*（select 经 musl 转换）。NULL=永久阻塞。
    int timeout_ms = -1;
    if(v->r(5)) {
        const struct timespec* ts = (const struct timespec*)v->mmu(v->r(5), sizeof(struct timespec));
        if(!ts) return -EFAULT;
        if(ts->tv_sec < 0 || ts->tv_nsec < 0) return -EINVAL;
        // 上限钳制（tv_sec*1000 在 tv_sec~INT_MAX/1000 处溢出 int）。永久阻塞用 -1。
        if(ts->tv_sec > (int64_t)INT32_MAX / 1000) timeout_ms = INT32_MAX;
        else timeout_ms = (int)(ts->tv_sec * 1000 + ts->tv_nsec / 1000000);
    }
    // 第 6 参 sigmask_data 暂忽略（单线程，原子切换信号掩码无意义）。r0 经 BpfWideArgs 传入。

    // 把 fd_set 的三个位图合成 pollfd 数组（一个 fd 可能同时关心读/写/异常）。
    std::vector<struct pollfd> hfds;
    hfds.reserve(n);
    // 记录每个 pollfd 对应的 guest fd + 关心异常，用于回写 fd_set。
    std::vector<int> gfd_map;
    std::vector<char> want_except;
    int invalid_count = 0;
    // 虚拟 fd（/proc 等，host_fd()<0）算"就地就绪"，不进 host poll（无真实 fd 可等）。
    // 回写阶段会 FD_ZERO 清空全部位图后靠下面的列表回填，故虚拟 fd 的就绪位需单独记录，
    // 否则会被清空（原实现只 continue 导致丢失）。与 do_poll 的就地就绪一致。
    std::vector<int> vfd_r, vfd_w;
    for(int fd = 0; fd < n; ++fd) {
        bool in_r = grfds && FD_ISSET(fd, grfds);
        bool in_w = gwfds && FD_ISSET(fd, gwfds);
        bool in_e = gefds && FD_ISSET(fd, gefds);
        if(!in_r && !in_w && !in_e) continue;

        auto fd_h = ps->find_fd(fd);
        if(!fd_h) {
            invalid_count++;  // fd 未打开：实际 select 对非法 fd 返回 -EBADF；这里近似跳过。
            continue;
        }
        int hfd = fd_h->host_fd();
        if(hfd < 0) {
            if(in_r) vfd_r.push_back(fd);  // 虚拟 fd 读就绪
            if(in_w) vfd_w.push_back(fd);  // 虚拟 fd 写就绪
            continue;
        }
        short events = (in_r ? POLLIN : 0) | (in_w ? POLLOUT : 0);
        hfds.push_back({hfd, events, 0});
        gfd_map.push_back(fd);
        want_except.push_back(in_e ? 1 : 0);
    }
    int virtual_ready = vfd_r.size() + vfd_w.size();

    // preset>0（有非法 fd 或虚拟 fd 已就绪）时强制 timeout=0 立即返回，与 do_poll 一致。
    int preset = invalid_count + virtual_ready;
    int rc = ::poll(hfds.data(), hfds.size(), preset > 0 ? 0 : timeout_ms);
    if(rc == -1) return -errno;

    // 清空并回写三个 fd_set（只置 poll 结果对应的位）。
    if(grfds) FD_ZERO(grfds);
    if(gwfds) FD_ZERO(gwfds);
    if(gefds) FD_ZERO(gefds);
    int ready = 0;
    for(size_t i = 0; i < hfds.size(); ++i) {
        int fd = gfd_map[i];
        if(hfds[i].revents & (POLLIN | POLLHUP | POLLERR)) { if(grfds) FD_SET(fd, grfds); ready++; }
        if(hfds[i].revents & (POLLOUT | POLLERR))           { if(gwfds) FD_SET(fd, gwfds); ready++; }
        // POLLPRI 对应 select 的 except 集合（OOB 数据 / 异常）
        if((hfds[i].revents & POLLPRI) && want_except[i])   { if(gefds) FD_SET(fd, gefds); ready++; }
    }
    // 虚拟 fd 的就地就绪位：回写阶段 FD_ZERO 清空过，这里补置。
    for(int fd : vfd_r) FD_SET(fd, grfds);
    for(int fd : vfd_w) FD_SET(fd, gwfds);
    return ready + preset;
}
