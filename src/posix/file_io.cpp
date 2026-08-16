#include "posix_internal.h"

// 后台 tty 访问门控：do_read/do_write/readv/writev 调。
// POSIX/Linux 实测语义（非前台组访问控制终端）：
//   读：无条件产生 SIGTTIN（TOSTOP 不影响读）。
//   写：仅当 termios c_lflag & TOSTOP 才产生 SIGTTOU；默认 TOSTOP=0，写照常进行。
//   信号 disposition：
//     SIG_IGN + 写 -> 信号忽略，I/O 照常完成（写返回写入字节数）。
//     SIG_IGN + 读 -> Linux 返回 -EIO（忽略读的 SIGTTIN 视作非法后台读）。
//     SIG_DFL     -> 默认动作是停止作业（SIGTTIN/SIGTTOU 的 default action = stop）
//     已 catch    -> handler 返回后被中断的系统调用返回 -1/EINTR
// 返回 nullopt 表示放行真正 I/O；返回非空表示已拦截（已投信号），其值即 syscall 返回值。
// 非 DevFd 第一行短路 -> 对它们永远放行（无后台门控）。
std::optional<int64_t> PosixSyscall::tty_bg_check(vm* v, const std::shared_ptr<Fd>& fd, bool is_read) {
    auto dfd = std::dynamic_pointer_cast<DevFd>(fd).get();
    GuestTty* tty = dfd ? dfd->guest_tty().get() : nullptr;
    if(!tty || !session || session->ctty.get() != tty) return std::nullopt;
    uint64_t fg = tty->fg_pgrp.load(std::memory_order_acquire);
    if(fg == 0 || pgrp->pgid == fg) return std::nullopt;  // 前台组：放行
    // 后台组写 ctty：TOSTOP 未置位时不产生信号，I/O 照常进行（POSIX 默认）。
    // GuestTty 不缓存 termios（直通 host pty），故写时 tcgetattr 查一次当前 c_lflag。
    if(!is_read) {
        struct termios tio;
        if(tcgetattr(fd->host_fd(), &tio) == 0 && !(tio.c_lflag & TOSTOP)) {
            return std::nullopt;  // TOSTOP=0：放行，do_write 正常执行
        }
        // tcgetattr 失败或 TOSTOP 置位：走下面的 SIGTTOU 路径。
    }
    int sig = is_read ? SIGTTIN : SIGTTOU;
    const auto& act = ps->signal_actions[static_cast<size_t>(sig)];
    if(handler_is_ignored(act.handler)) {
        // SIG_IGN：信号被忽略。
        //   写 -> I/O 照常完成（放行，do_write 真正 write）。
        //   读 -> Linux 返回 -EIO（后台读被忽略视为非法）。
        if(is_read) {
            return -EIO;
        }
        // tty 信号由内核发送：sender=0、code=SI_KERNEL。
        queue_signal(v, {sig, 0, SI_KERNEL, 0});  // 仍入队（被忽略），不影响本次 I/O
        return std::nullopt;   // 放行真正 write
    }
    queue_signal(v, {sig, 0, SI_KERNEL, 0});
    // SIG_DFL（停止作业，本次 I/O 不完成；已投递，handle_signals 会置 VM_STOPPED）或
    // 已 catch（handler 返回后返回 -EINTR，job-control 信号默认不复重啜）。
    return -EINTR;
}

int64_t PosixSyscall::do_openat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    if(dirfd != AT_FDCWD && !ps->find_fd(dirfd)) {
        return -EBADF;
    }
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        return -EFAULT;
    }
    int flags = arg_s32(v->r(3));
    mode_t mode = (mode_t)(arg_u32(v->r(4)) & ~ps->umask);

    std::shared_ptr<Fd> handle = ResolvePath(this, guest_abs_path(path, dirfd))->open(flags, mode);
    if(!handle) return -errno;

    if(flags & O_CLOEXEC) handle->cloexec = true;
    return ps->fds_emplace(std::move(handle));
}

int64_t PosixSyscall::do_read(vm* v) {
    auto h = ps->find_fd(arg_s32(v->r(1)));
    if(!h) {
        return -EBADF;
    }
    if(auto r = tty_bg_check(v, h, /*is_read=*/true)) {
        return *r;  // 后台读 ctty：tty_bg_check 已投 SIGTTIN 并定好结果（/proc fd 自动放行）
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu_w(v->r(2), count);
    if(buf == nullptr) {
        return -EFAULT;
    }
    ssize_t rc = h->read(buf, count);  // 虚分派：HostFd::read / ProcFile::read
    if(rc < 0) {
        return (rc == -EINTR) ? SYSCALL_RESTART : rc;
    }
    return rc;
}

int64_t PosixSyscall::do_write(vm* v) {
    auto h = ps->find_fd(arg_s32(v->r(1)));
    if(!h) {
        return -EBADF;
    }
    if(auto r = tty_bg_check(v, h, /*is_read=*/false)) {
        return *r;  // 后台写 ctty：tty_bg_check 已投 SIGTTOU 并定好结果
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu(v->r(2), count);
    if(buf == nullptr) {
        return -EFAULT;
    }
    ssize_t rc = h->write(buf, count);
    if(rc < 0) {
        return (rc == -EINTR) ? SYSCALL_RESTART : rc;
    }
    return rc;
}

int64_t PosixSyscall::do_lseek(vm* v) {
    auto h = ps->find_fd(arg_s32(v->r(1)));
    if(!h) {
        return -EBADF;
    }
    return h->lseek((off_t)v->r(2), arg_s32(v->r(3)));
}

int64_t PosixSyscall::do_truncate(vm* v) {
    std::string path;
    if(!read_c_string(v, v->r(1), path, 4096)) {
        return -EFAULT;
    }
    return ResolvePath(this, guest_abs_path(path))->truncate(static_cast<off_t>(v->r(2)));
}

int64_t PosixSyscall::do_ftruncate(vm* v) {
    auto h = ps->find_fd(arg_s32(v->r(1)));
    if(!h) {
        return -EBADF;
    }
    return h->ftruncate(static_cast<off_t>(v->r(2)));
}

int64_t PosixSyscall::do_close(vm* v) {
    int fd = arg_s32(v->r(1));
    auto h = ps->find_fd(fd);
    if(!h) {
        return -EBADF;
    }
    // pty master fd 关闭且是最后一个 master 引用时触发 SIGHUP（其余 fd 的 on_close 为 no-op）。
    // on_close 在锁外（投 SIGHUP 不能在 fds_mutate 重试循环里）。
    // COW 下别的线程持有的旧快照仍能看到该 fd（host fd 延迟关闭，对齐 Linux file 引用计数语义）。
    h->on_close(this, v);
    ps->fds_mutate([&](SharedState::FdMap& m){
        m.erase(fd);
    });
    return 0;
}

// 把 guest iovec 数组翻译成 host iovec 数组（mmu_w=读要写 / mmu=写要读）。
// guest iovec 与 host iovec 布局一致（{void*, size_t}，BPF 64 位），直接用 host 类型。
// 返回 nullopt = 翻译失败（EFAULT）；返回 vector（可能为空，全 0 长度段）= 成功。
static std::optional<std::vector<iovec>> translate_iovec(vm* v, uint64_t guest_addr, int iovcnt, bool writable) {
    auto guest_vec = static_cast<iovec*>(v->mmu(guest_addr, sizeof(iovec) * iovcnt));
    if(guest_vec == nullptr) {
        return std::nullopt;  // iovec 数组本身越界
    }
    std::vector<iovec> host_vec;
    host_vec.reserve(iovcnt);
    for(int i = 0; i < iovcnt; ++i) {
        size_t len = (size_t)guest_vec[i].iov_len;
        if(len == 0) continue;
        void* buf = writable ? v->mmu_w((uint64_t)guest_vec[i].iov_base, len)
                             : v->mmu((uint64_t)guest_vec[i].iov_base, len);
        if(buf == nullptr) {
            return std::nullopt;  // 某段越界
        }
        host_vec.push_back({buf, len});
    }
    return host_vec;  // 可能空（全 0 段），调用方据此返 0
}

int64_t PosixSyscall::do_readv(vm* v) {
    auto h = ps->find_fd(arg_s32(v->r(1)));
    if(!h) {
        return -EBADF;
    }
    if(auto r = tty_bg_check(v, h, /*is_read=*/true)) {
        return *r;  // 后台读 ctty：已投 SIGTTIN（/proc fd 自动放行）
    }
    int iovcnt = arg_s32(v->r(3));
    if(iovcnt <= 0) {
        return (iovcnt == 0) ? 0 : -EINVAL;
    }
    auto host_vec = translate_iovec(v, v->r(2), iovcnt, /*writable=*/true);
    if(!host_vec) {
        return -EFAULT;
    }
    if(host_vec->empty()) {
        return 0;  // 全 0 长度段：无数据可读
    }
    ssize_t rc = h->readv(host_vec->data(), (int)host_vec->size());
    if(rc < 0) {
        return (rc == -EINTR) ? SYSCALL_RESTART : rc;
    }
    return rc;
}

int64_t PosixSyscall::do_writev(vm* v) {
    auto h = ps->find_fd(arg_s32(v->r(1)));
    if(!h) {
        return -EBADF;
    }
    if(auto r = tty_bg_check(v, h, /*is_read=*/false)) {
        return *r;  // 后台写 ctty：tty_bg_check 已投 SIGTTOU 并定好结果
    }
    int iovcnt = arg_s32(v->r(3));
    if(iovcnt <= 0) {
        return (iovcnt == 0) ? 0 : -EINVAL;
    }
    auto host_vec = translate_iovec(v, v->r(2), iovcnt, /*writable=*/false);
    if(!host_vec) {
        return -EFAULT;
    }
    if(host_vec->empty()) {
        return 0;  // 全 0 长度段：无数据可写
    }
    ssize_t rc = h->writev(host_vec->data(), (int)host_vec->size());
    if(rc < 0) {
        return (rc == -EINTR) ? SYSCALL_RESTART : rc;
    }
    return rc;
}

int64_t PosixSyscall::do_pread(vm* v) {
    auto h = ps->find_fd(arg_s32(v->r(1)));
    if(!h) {
        return -EBADF;
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu_w(v->r(2), count);
    if(buf == nullptr) {
        return -EFAULT;
    }
    ssize_t rc = h->pread(buf, count, (off_t)v->r(4));
    if(rc < 0) {
        return (rc == -EINTR) ? SYSCALL_RESTART : rc;
    }
    return rc;
}

int64_t PosixSyscall::do_pwrite(vm* v) {
    auto h = ps->find_fd(arg_s32(v->r(1)));
    if(!h) {
        return -EBADF;
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu(v->r(2), count);
    if(buf == nullptr) {
        return -EFAULT;
    }
    ssize_t rc = h->pwrite(buf, count, (off_t)v->r(4));
    if(rc < 0) {
        return (rc == -EINTR) ? SYSCALL_RESTART : rc;
    }
    return rc;
}

int64_t PosixSyscall::do_getdents64(vm* v) {
    auto h = ps->find_fd(arg_s32(v->r(1)));
    if(!h) {
        return -EBADF;
    }
    size_t count = arg_size(v->r(3));
    if(count == 0) {
        return -EINVAL;
    }
    void* buf = v->mmu_w(v->r(2), count);
    if(buf == nullptr) {
        return -EFAULT;
    }
    return h->getdents64(buf, count);
}
