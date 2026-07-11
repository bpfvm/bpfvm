#include "posix_internal.h"

// 后台 tty 访问门控：do_read/do_write/readv/writev 调。
// POSIX/Linux 实测语义（非前台组访问控制终端）：
//   读：无条件产生 SIGTTIN（TOSTOP 不影响读）。
//   写：仅当 termios c_lflag & TOSTOP 才产生 SIGTTOU；默认 TOSTOP=0，写照常进行。
//   信号 disposition：
//     SIG_IGN + 写 → 信号忽略，I/O 照常完成（写返回写入字节数）。
//     SIG_IGN + 读 → Linux 返回 -EIO（忽略读的 SIGTTIN 视作非法后台读）。
//     SIG_DFL     → 默认动作是停止作业（SIGTTIN/SIGTTOU 的 default action = stop）
//     已 catch    → handler 返回后被中断的系统调用返回 -1/EINTR
// 返回 nullopt 表示放行真正 I/O；返回非空表示已拦截（已投信号），其值即 syscall 返回值。
std::optional<int64_t> PosixSyscall::tty_bg_check(vm* v, const std::shared_ptr<fd_handle>& fd, bool is_read) {
    const auto& tty = fd->tty;
    if(!tty || !session || session->ctty.get() != tty.get()) return std::nullopt;
    uint64_t fg = tty->fg_pgrp.load(std::memory_order_acquire);
    if(fg == 0 || pgrp->pgid == fg) return std::nullopt;  // 前台组：放行
    // 后台组写 ctty：TOSTOP 未置位时不产生信号，I/O 照常进行（POSIX 默认）。
    // GuestTty 不缓存 termios（直通 host pty），故写时 tcgetattr 查一次当前 c_lflag。
    if(!is_read) {
        struct termios tio;
        if(tcgetattr(fd->fd, &tio) == 0 && !(tio.c_lflag & TOSTOP)) {
            return std::nullopt;  // TOSTOP=0：放行，do_write 正常执行
        }
        // tcgetattr 失败或 TOSTOP 置位：走下面的 SIGTTOU 路径。
    }
    int sig = is_read ? SIGTTIN : SIGTTOU;
    const auto& act = ps->signal_actions[static_cast<size_t>(sig)];
    if(handler_is_ignored(act.handler)) {
        // SIG_IGN：信号被忽略。
        //   写 → I/O 照常完成（放行，do_write 真正 write）。
        //   读 → Linux 返回 -EIO（后台读被忽略视为非法）。
        if(is_read) {
            return -EIO;
        }
        queue_signal(v, sig);  // 仍入队（语义上发生过，但被忽略），不影响本次 I/O
        return std::nullopt;   // 放行真正 write
    }
    queue_signal(v, sig);
    // SIG_DFL（停止作业，本次 I/O 不完成；已投递，handle_signals 会置 VM_STOPPED）或
    // 已 catch（handler 返回后返回 -EINTR，job-control 信号默认不复重啜）。
    return -EINTR;
}

int64_t PosixSyscall::do_openat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        return -EFAULT;
    }
    int flags = arg_s32(v->r(3));
    mode_t mode = (mode_t)(arg_u32(v->r(4)) & ~umask_val);
    // guest_abs：guest 命名空间的绝对路径（用于 pty 特殊设备匹配 + fd_handle::path 存储后者
    // 经 do_fchdir 会进 cwd，故必须保持 guest 视角，而非拼了 root 的宿主路径）。
    // host_path：实际 openat 用的宿主路径（AT_FDCWD 时 = resolve_path，已含 root 前缀）。
    std::string guest_abs = (dirfd == AT_FDCWD) ? guest_abs_path(path) : path;
    std::string host_path = (dirfd == AT_FDCWD) ? resolve_path(path) : path;

    // —— guest pty 合成：tmux/posix_openpt/openpty 都走 open("/dev/ptmx") + ioctl(TIOCGPTN) +
    // open("/dev/pts/N")。bpfvm 拦截这两个特殊路径，合成 host pty（canonical/echo 全交 host
    // 内核）。GuestTty 按 pts 编号登记进 ptmx_registry，open("/dev/pts/N") 复用之。
    // 注：ptmx 不看 dirfd（它必是绝对路径特殊设备）。特殊设备按 guest 路径匹配，不受 chroot
    // 影响（root 内通常没有 /dev）。
    // —— /dev/tty：guest job-control（dash setjobctl）打开它拿控制终端做 tcgetpgrp/tcsetpgrp。
    // 真 /dev/tty 在 host 侧是 bpfvm 自身的 ctty（非 guest pty slave），fd_handle.tty 为空，
    // 后续 TIOCGPGRP 会因 tty 字段不匹配 session->ctty 而 ENOTTY → dash 报 "can't access tty;
    // job control turned off"。故拦截：本会话有 ctty 时，复用一个已绑同一 ctty 的 fd（dup 它
    // 的 host fd，携带同一 GuestTty），使该 fd 就是 ctty 端。无 ctty → ENXIO（与
    // Linux 无 ctty 进程开 /dev/tty 的行为一致）。
    if(guest_abs == "/dev/tty") {
        if(!session || !session->ctty) {
            return -ENXIO;
        }
        const auto& ctty = session->ctty;
        // 找一个已绑同一 ctty 的 guest fd 做 dup 源（PTY 模式下 fd 0/1/2 必是）。
        int src_guest_fd = -1;
        for(const auto& entry : ps->fds) {
            if(entry.second->tty.get() == ctty.get()) {
                src_guest_fd = entry.first;
                break;
            }
        }
        if(src_guest_fd < 0) {
            return -ENXIO;
        }
        int host_fd = dup(ps->fds[src_guest_fd]->fd);
        if(host_fd < 0) { return -errno; }
        auto handle = std::make_shared<fd_handle>(host_fd, guest_abs, ctty);
        if(flags & O_CLOEXEC) handle->cloexec = true;
        int guest_fd = allocate_fd();
        ps->fds[guest_fd] = handle;
        return guest_fd;
    }
    if(guest_abs == "/dev/ptmx") {
        int master = posix_openpt(O_RDWR | O_NOCTTY);
        if(master < 0) { return -errno; }
        if(grantpt(master) < 0 || unlockpt(master) < 0) {
            int e = errno; close(master); return -e;
        }
        int ptn = -1;
        if(ioctl(master, TIOCGPTN, &ptn) < 0) {
            int e = errno; close(master); return -e;
        }
        auto tty = std::make_shared<GuestTty>();
        {
            std::lock_guard<std::mutex> lk(ptmx_registry_mutex);
            ptmx_registry[ptn] = tty;
        }
        // master token：仅由 master fd 持有（use_count = master fd 数），最后一个关闭触发 SIGHUP。
        auto handle = std::make_shared<fd_handle>(master, guest_abs, tty, std::make_shared<PtySide>());
        if(flags & O_CLOEXEC) handle->cloexec = true;
        int guest_fd = allocate_fd();
        ps->fds[guest_fd] = handle;
        return guest_fd;
    }
    // rfind(...,0) == 0 即 starts_with：前缀匹配 "/dev/pts/"（9 字符）。
    if(guest_abs.rfind("/dev/pts/", 0) == 0) {
        // /dev/pts/N：查 registry 取该编号的 GuestTty，打开对应 host slave，包成 fd_handle。
        int ptn = atoi(guest_abs.c_str() + 9);  // 数字从 index 9 起
        std::shared_ptr<GuestTty> tty;
        {
            std::lock_guard<std::mutex> lk(ptmx_registry_mutex);
            auto it2 = ptmx_registry.find(ptn);
            if(it2 != ptmx_registry.end()) tty = it2->second;
        }
        if(!tty) { return -ENOENT; }
        // 打开 host slave，包成 fd_handle，携带同一 GuestTty（与 master 共享）。
        char slave_name[64];
        snprintf(slave_name, sizeof(slave_name), "/dev/pts/%d", ptn);
        int slave = open(slave_name, flags & ~O_CREAT, mode);
        if(slave < 0) { return -errno; }
        auto handle = std::make_shared<fd_handle>(slave, guest_abs, tty);
        if(flags & O_CLOEXEC) handle->cloexec = true;
        int guest_fd = allocate_fd();
        ps->fds[guest_fd] = handle;
        return guest_fd;
    }

    int fd = -1;
    if(dirfd == AT_FDCWD) {
        fd = openat(AT_FDCWD, host_path.c_str(), flags, mode);
    } else {
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
            return -EBADF;
        }
        fd = openat(it->second->fd, path.c_str(), flags, mode);
        if(!it->second->path.empty()) {
            guest_abs = (std::filesystem::path(it->second->path) / path).lexically_normal().string();
        }
    }
    if(fd == -1) {
        return -errno;
    }
    auto handle = std::make_shared<fd_handle>(fd, std::move(guest_abs));
    if(flags & O_CLOEXEC) {
        handle->cloexec = true;
    }
    int guest_fd = allocate_fd();
    ps->fds[guest_fd] = handle;
    return guest_fd;
}

int64_t PosixSyscall::do_read(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        return -EBADF;
    }
    if(auto r = tty_bg_check(v, it->second, /*is_read=*/true)) {
        return *r;  // 后台读 ctty：tty_bg_check 已投 SIGTTIN 并定好结果
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu_w(v->r(2), count);
    if(buf == nullptr) {
        return -EFAULT;
    }
    ssize_t rc = read(it->second->fd, buf, count);
    if(rc == -1) {
        return -errno;
    }
    return rc;
}

int64_t PosixSyscall::do_write(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        return -EBADF;
    }
    if(auto r = tty_bg_check(v, it->second, /*is_read=*/false)) {
        return *r;  // 后台写 ctty：tty_bg_check 已投 SIGTTOU 并定好结果
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu(v->r(2), count);
    if(buf == nullptr) {
        return -EFAULT;
    }
    ssize_t rc = write(it->second->fd, buf, count);
    if(rc == -1) {
        return -errno;
    }
    return rc;
}

int64_t PosixSyscall::do_lseek(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        return -EBADF;
    }
    off_t rc = lseek64(it->second->fd, (off_t)v->r(2), arg_s32(v->r(3)));
    if(rc == (off_t)-1) {
        return -errno;
    }
    return rc;
}

int64_t PosixSyscall::do_truncate(vm* v) {
    std::string path;
    if(!read_c_string(v, v->r(1), path, 4096)) {
        return -EFAULT;
    }
    int rc = truncate(resolve_path(path).c_str(), static_cast<off_t>(v->r(2)));
    if(rc == -1) {
        return -errno;
    }
    return 0;
}

int64_t PosixSyscall::do_ftruncate(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        return -EBADF;
    }
    int rc = ftruncate(it->second->fd, static_cast<off_t>(v->r(2)));
    if(rc == -1) {
        return -errno;
    }
    return 0;
}

int64_t PosixSyscall::do_close(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        return -EBADF;
    }
    // pty master fd 关闭且是最后一个 master 引用时触发 SIGHUP
    drop_fd_handle(v, it->second);
    ps->fds.erase(it);
    return 0;
}

int64_t PosixSyscall::do_readv(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        return -EBADF;
    }
    if(auto r = tty_bg_check(v, it->second, /*is_read=*/true)) {
        return *r;  // 后台读 ctty：已投 SIGTTIN
    }
    int iovcnt = arg_s32(v->r(3));
    if(iovcnt <= 0) {
        return (iovcnt == 0) ? 0 : -EINVAL;
    }
    // guest iovec 与 host iovec 布局一致（{void*, size_t}，BPF 64 位），直接用 host 类型。
    auto guest_vec = static_cast<iovec*>(v->mmu(v->r(2), sizeof(iovec) * iovcnt));
    if(guest_vec == nullptr) {
        return -EFAULT;
    }
    // 把 guest iov 的 iov_base 翻译成 host 指针（mmu_w，read 要写）。宿主 readv 一次性按
    // iov 顺序填充，跨 iov 的短读/EOF 语义与内核一致。
    std::vector<iovec> host_vec;
    host_vec.reserve(iovcnt);
    for(int i = 0; i < iovcnt; ++i) {
        size_t len = (size_t)guest_vec[i].iov_len;
        if(len == 0) continue;
        void* buf = v->mmu_w((uint64_t)guest_vec[i].iov_base, len);
        if(buf == nullptr) {
            return -EFAULT;
        }
        host_vec.push_back({buf, len});
    }
    if(host_vec.empty()) {
        return 0;
    }
    ssize_t rc = readv(it->second->fd, host_vec.data(), (int)host_vec.size());
    if(rc < 0) {
        return -errno;
    }
    return rc;
}

int64_t PosixSyscall::do_writev(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        return -EBADF;
    }
    if(auto r = tty_bg_check(v, it->second, /*is_read=*/false)) {
        return *r;  // 后台写 ctty：tty_bg_check 已投 SIGTTOU 并定好结果
    }
    int iovcnt = arg_s32(v->r(3));
    if(iovcnt <= 0) {
        return (iovcnt == 0) ? 0 : -EINVAL;
    }
    // guest iovec 与 host iovec 布局一致（{void*, size_t}，BPF 64 位），直接用 host 类型。
    auto guest_vec = static_cast<iovec*>(v->mmu(v->r(2), sizeof(iovec) * iovcnt));
    if(guest_vec == nullptr) {
        return -EFAULT;
    }
    std::vector<iovec> host_vec;
    host_vec.reserve(iovcnt);
    for(int i = 0; i < iovcnt; ++i) {
        size_t len = (size_t)guest_vec[i].iov_len;
        if(len == 0) continue;
        void* buf = v->mmu((uint64_t)guest_vec[i].iov_base, len);
        if(buf == nullptr) {
            return -EFAULT;
        }
        host_vec.push_back({buf, len});
    }
    if(host_vec.empty()) {
        return 0;
    }
    ssize_t rc = writev(it->second->fd, host_vec.data(), (int)host_vec.size());
    if(rc < 0) {
        return -errno;
    }
    return rc;
}

int64_t PosixSyscall::do_pread(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        return -EBADF;
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu_w(v->r(2), count);
    if(buf == nullptr) {
        return -EFAULT;
    }
    off_t off = (off_t)v->r(4);
    ssize_t rc = pread(it->second->fd, buf, count, off);
    if(rc == -1) {
        return -errno;
    }
    return rc;
}

int64_t PosixSyscall::do_pwrite(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        return -EBADF;
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu(v->r(2), count);
    if(buf == nullptr) {
        return -EFAULT;
    }
    off_t off = (off_t)v->r(4);
    ssize_t rc = pwrite(it->second->fd, buf, count, off);
    if(rc == -1) {
        return -errno;
    }
    return rc;
}

int64_t PosixSyscall::do_getdents64(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
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
    int rc = (int)::syscall(SYS_getdents64, it->second->fd, buf, (int)count);
    if(rc < 0) {
        return -errno;
    }
    return rc;
}
