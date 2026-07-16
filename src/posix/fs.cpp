//
// fs.cpp — Fd / Path 多态层次的实现。
//
// 两部分：
//   1) HostFd / DevFd 的 I/O 虚方法 + DevFd::open 工厂：
//      把"host fd 直通"的 I/O 动作封装——HostFd 调 host libc
//      同名函数（EINTR 时返回 -EINTR，syscall 层转 SYSCALL_RESTART）。
//      syscall 入口（do_read 等）只做指针翻译和 EINTR
//      处理，通过虚分派选择实现，不再判 is_proc()。
//      （/proc 虚拟文件 fd——ProcFile/ProcDir——实现在 procfs.cpp。）
//   2) Path 多态层次：ResolvePath 工厂 + HostPath/DevPath（按 guest 路径前缀 /proc|/dev|其它
//      分类）。调用方（do_openat/do_statx/...）统一模式：
//        ResolvePath(this, guest_abs_path(path, dirfd))->方法(...);
//      ProcPath 实现在 procfs.cpp（复用本编译单元外不暴露的 lookup）。
//

#include "posix_internal.h"
#include <sys/syscall.h>
#include <stdlib.h>
#include <fcntl.h>
#include <set>

// ptmx 注册表：guest open("/dev/ptmx") 合成的 host pty，按 pts 编号(=TIOCGPTN 返回值)
// 索引到 GuestTty。后续 open("/dev/pts/N") 用 N 查此表，复用同一 GuestTty。
// 文件作用域：唯一使用者是本文件的 DevFd::open。
static std::unordered_map<int, std::shared_ptr<GuestTty>> ptmx_registry;
static std::mutex ptmx_registry_mutex;

// =====================================================================
// HostFd —— host fd 直通
// =====================================================================

ssize_t HostFd::read(void* buf, size_t count) {
    ssize_t rc = ::read(fd_, buf, count);
    if(rc == -1) return (errno == EINTR) ? -EINTR : -errno;
    return rc;
}

ssize_t HostFd::write(const void* buf, size_t count) {
    ssize_t rc = ::write(fd_, buf, count);
    if(rc == -1) return (errno == EINTR) ? -EINTR : -errno;
    return rc;
}

ssize_t HostFd::pread(void* buf, size_t count, off_t off) {
    ssize_t rc = ::pread(fd_, buf, count, off);
    if(rc == -1) return (errno == EINTR) ? -EINTR : -errno;
    return rc;
}

ssize_t HostFd::pwrite(const void* buf, size_t count, off_t off) {
    ssize_t rc = ::pwrite(fd_, buf, count, off);
    if(rc == -1) return (errno == EINTR) ? -EINTR : -errno;
    return rc;
}

off_t HostFd::lseek(off_t off, int whence) {
    off_t rc = lseek64(fd_, off, whence);
    if(rc == (off_t)-1) return -errno;
    return rc;
}

ssize_t HostFd::readv(const struct iovec* iov, int iovcnt) {
    ssize_t rc = ::readv(fd_, iov, iovcnt);
    if(rc == -1) return (errno == EINTR) ? -EINTR : -errno;
    return rc;
}

ssize_t HostFd::writev(const struct iovec* iov, int iovcnt) {
    ssize_t rc = ::writev(fd_, iov, iovcnt);
    if(rc == -1) return (errno == EINTR) ? -EINTR : -errno;
    return rc;
}

ssize_t HostFd::getdents64(void* buf, size_t count) {
    int rc = (int)::syscall(SYS_getdents64, fd_, buf, (int)count);
    if(rc < 0) return -errno;
    return rc;
}

int HostFd::fstatx(struct statx* stx, unsigned int mask, int /*flags*/) {
    // fstat 语义：始终 AT_EMPTY_PATH + 空 path，对 fd 自身的 inode 取属性（与内核
    // fstat(fd) == statx(fd,"",AT_EMPTY_PATH) 等价）。flags 参数（如 AT_SYMLINK_NOFOLLOW）
    // 对 fd 形式无意义——fd 已是 follow 后的结果，不可能是符号链接本身。
#if defined(__ANDROID__)
    int rc = (int)::syscall(SYS_statx, fd_, "", AT_EMPTY_PATH, mask, stx);
#else
    int rc = ::statx(fd_, "", AT_EMPTY_PATH, mask, stx);
#endif
    return rc == -1 ? -errno : 0;
}

int HostFd::ftruncate(off_t len) {
    int rc = ::ftruncate(fd_, len);
    return rc == -1 ? -errno : 0;
}

int HostFd::fchmod(mode_t mode) {
    int rc = ::fchmod(fd_, mode);
    return rc == -1 ? -errno : 0;
}

int HostFd::futimens(const struct timespec times[2], int /*flags*/) {
    // AT_SYMLINK_NOFOLLOW 对 fd 形式无意义（fd 不可能是符号链接本身），host futimens 无 flags 参数。
    int rc = ::futimens(fd_, times);
    return rc == -1 ? -errno : 0;
}

std::shared_ptr<Fd> HostFd::clone() const {
    // host dup 得独立 host fd；cloexec 不复制（由调用方按需设置，与 dup 语义一致）。
    int new_fd = ::dup(fd_);
    if(new_fd < 0) return nullptr;
    return std::make_shared<HostFd>(new_fd, path);
}

// host 透传工厂：openat(AT_FDCWD, host_path)。host_path 由调用方拼好（AT_FDCWD 时含 chroot
// 前缀；DevFd::open 委托开标准设备时直接用 /dev/null 等绝对路径，不经 chroot）。
std::shared_ptr<HostFd> HostFd::open(const std::string& host_path, int flags, mode_t mode,
                                     std::string guest_abs) {
    int fd = ::openat(AT_FDCWD, host_path.c_str(), flags, mode);
    if(fd < 0) return nullptr;   // errno 已由 openat 设
    return std::make_shared<HostFd>(fd, std::move(guest_abs));
}

// =====================================================================
// DevFd —— 设备 fd（pty master/slave、/dev/tty）。I/O 复用 HostFd，只加 tty 语义。
// =====================================================================

std::shared_ptr<Fd> DevFd::clone() const {
    // host dup 得独立 host fd；GuestTty / master_token 共享（pty 语义保持）。
    // cloexec 不复制（由调用方按需设置，与 dup 语义一致）。
    int new_fd = ::dup(fd_);
    if(new_fd < 0) return nullptr;
    return std::make_shared<DevFd>(new_fd, path, tty_, master_token_);
}

// =====================================================================
// 静态工厂：do_openat 的 /dev/* 与 /proc/* 拦截分流到此。
// 约定：命中（本类负责的路径）→ 返回构造好的 fd（cloexec 由 do_openat 统一设置）；
//   非 /dev 或 /proc 路径 → 返回 nullptr、err=0（交回 host openat）；
//   命中但失败 → 返回 nullptr、err=负 errno。
// =====================================================================

static const std::set<std::string> allowed_dev_paths = {
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/full",
};

std::shared_ptr<Fd> DevFd::open(const std::string& guest_abs, int flags, mode_t mode,
                                PosixSyscall* self) {
    // —— guest pty 合成：tmux/posix_openpt/openpty 都走 open("/dev/ptmx") + ioctl(TIOCGPTN) +
    // open("/dev/pts/N")。bpfvm 拦截这两个特殊路径，合成 host pty（canonical/echo 全交 host
    // 内核）。GuestTty 按 pts 编号登记进 ptmx_registry，open("/dev/pts/N") 复用之。
    // 注：ptmx 不看 dirfd（它必是绝对路径特殊设备）。特殊设备按 guest 路径匹配，不受 chroot
    // 影响（root 内通常没有 /dev）。
    // —— /dev/tty：guest job-control（dash setjobctl）打开它拿控制终端做 tcgetpgrp/tcsetpgrp。
    // 真 /dev/tty 在 host 侧是 bpfvm 自身的 ctty（非 guest pty slave），Fd::tty() 为空，
    // 后续 TIOCGPGRP 会因 tty 字段不匹配 session->ctty 而 ENOTTY → dash 报 "can't access tty;
    // job control turned off"。故拦截：本会话有 ctty 时，复用一个已绑同一 ctty 的 fd（dup 它
    // 的 host fd，携带同一 GuestTty），使该 fd 就是 ctty 端。无 ctty → ENXIO（与
    // Linux 无 ctty 进程开 /dev/tty 的行为一致）。
    if(guest_abs == "/dev/tty") {
        const auto& session = self->session;
        if(!session || !session->ctty) {
            errno = ENXIO;
            return nullptr;
        }
        const auto& ctty = session->ctty;
        // 找一个已绑同一 ctty 的 guest fd 做 dup 源（PTY 模式下 fd 0/1/2 必是）。
        int src_guest_fd = -1;
        for(const auto& entry : self->ps->fds) {
            if(entry.second->tty().get() == ctty.get()) {
                src_guest_fd = entry.first;
                break;
            }
        }
        if(src_guest_fd < 0) {
            errno = ENXIO;
            return nullptr;
        }
        int host_fd = dup(self->ps->fds[src_guest_fd]->host_fd());
        if(host_fd < 0) return nullptr;   // errno 已由 dup 设
        return std::make_shared<DevFd>(host_fd, guest_abs, ctty);
    }
    if(guest_abs == "/dev/ptmx") {
        int master = posix_openpt(O_RDWR | O_NOCTTY);
        if(master < 0) return nullptr;   // errno 已由 posix_openpt 设
        if(grantpt(master) < 0 || unlockpt(master) < 0) {
            int e = errno; close(master); errno = e; return nullptr;
        }
        int ptn = -1;
        if(ioctl(master, TIOCGPTN, &ptn) < 0) {
            int e = errno; close(master); errno = e; return nullptr;
        }
        auto tty = std::make_shared<GuestTty>();
        {
            std::lock_guard<std::mutex> lk(ptmx_registry_mutex);
            ptmx_registry[ptn] = tty;
        }
        // master token：仅由 master fd 持有（use_count = master fd 数），最后一个关闭触发 SIGHUP。
        return std::make_shared<DevFd>(master, guest_abs, tty, std::make_shared<PtySide>());
    }
    // rfind(...,0) == 0 即 starts_with：前缀匹配 "/dev/pts/"（9 字符）。
    if(guest_abs.rfind("/dev/pts/", 0) == 0) {
        // /dev/pts/N：查 registry 取该编号的 GuestTty，打开对应 host slave，包成 DevFd。
        int ptn = atoi(guest_abs.c_str() + 9);  // 数字从 index 9 起
        std::shared_ptr<GuestTty> tty;
        {
            std::lock_guard<std::mutex> lk(ptmx_registry_mutex);
            auto it2 = ptmx_registry.find(ptn);
            if(it2 != ptmx_registry.end()) tty = it2->second;
        }
        if(!tty) { errno = ENOENT; return nullptr; }
        // 打开 host slave，包成 DevFd，携带同一 GuestTty（与 master 共享）。
        char slave_name[64];
        snprintf(slave_name, sizeof(slave_name), "/dev/pts/%d", ptn);
        int slave = ::open(slave_name, flags & ~O_CREAT, mode);
        if(slave < 0) return nullptr;   // errno 已由 open 设
        return std::make_shared<DevFd>(slave, guest_abs, tty);
    }
    // 标准设备：委托 HostFd::open 开宿主真设备（不经 chroot 前缀——这些是 bpfvm 进程自身的
    // 设备，chroot/非 chroot 行为一致）。标准设备不需 pty/tty 语义（不进 session->ctty 链，
    // tty_bg_check 对它们自然短路），故直接返 HostFd（已是 Fd 子类）。
    if(allowed_dev_paths.count(guest_abs)) {
        // host_path 直接用 guest_abs（绝对路径 /dev/null，不拼 chroot root）。
        return HostFd::open(guest_abs, flags, mode, guest_abs);
    }
    // 其余 /dev/* 一律 ENOENT（设备抽象封闭，不透传宿主 /dev 目录）。
    errno = ENOENT;
    return nullptr;
}

// =====================================================================
// Path 多态层次：ResolvePath 工厂 + HostPath/DevPath。
// ProcPath 实现在 procfs.cpp。
// =====================================================================

// 路径前缀判定（供 ResolvePath 及 HostPath::link/rename 共用）。
inline bool is_proc(const std::string& p) { return p == "/proc" || p.rfind("/proc/", 0) == 0; }
inline bool is_dev(const std::string& p) { return p == "/dev" || p.rfind("/dev/", 0) == 0; }

// =====================================================================
// ResolvePath —— 按 guest 前缀分类构造子类（替代 PathStub 的 open/readlink/statx 路由）。
// host 路径由 self->resolve_path(guest) 算好（含 chroot 前缀）传进 Path。
// =====================================================================
std::shared_ptr<Path> ResolvePath(PosixSyscall* self, std::string guest) {
    if(is_proc(guest)) return std::make_shared<ProcPath>(self, std::move(guest));
    if(is_dev(guest))  return std::make_shared<DevPath>(self, std::move(guest));
    return std::make_shared<HostPath>(self, std::move(guest));
}

// =====================================================================
// HostPath —— host 文件系统路径
// =====================================================================

Path::Path(PosixSyscall* s, std::string g)
    : self(s), guest(std::move(g)) {
    if(s->ps->root.empty()) {
        host = guest;
    } else {
        host = std::filesystem::path(s->ps->root + guest).lexically_normal().string();
    }
}

std::shared_ptr<Fd> HostPath::open(int flags, mode_t mode) {
    // host 已含 chroot 前缀；guest 存进 Fd::path（供 fchdir/readlinkat 用）。
    return HostFd::open(host, flags, mode, guest);
}

ssize_t HostPath::readlink(char* buf, size_t bufsiz) {
    // host /dev/普通文件：直接 ::readlink 写入 buf（host 已含 chroot 前缀）。
    // 返回值天然按 bufsiz 截断、不含 NUL，与 readlink(2) 语义一致。
    ssize_t rc = ::readlink(host.c_str(), buf, bufsiz);
    return rc < 0 ? -errno : rc;
}

int HostPath::statx(struct statx* stx, unsigned int mask, int flags) {
#if defined(__ANDROID__)
    int rc = (int)::syscall(SYS_statx, AT_FDCWD, host.c_str(), flags, mask, stx);
#else
    int rc = ::statx(AT_FDCWD, host.c_str(), flags, mask, stx);
#endif
    return rc == -1 ? -errno : 0;
}

int HostPath::access(int mode, int flags) {
    return ::faccessat(AT_FDCWD, host.c_str(), mode, flags) == -1 ? -errno : 0;
}

int HostPath::unlink(int flags) {
    return ::unlinkat(AT_FDCWD, host.c_str(), flags) == -1 ? -errno : 0;
}

int HostPath::mkdir(mode_t mode) {
    return ::mkdir(host.c_str(), mode) == -1 ? -errno : 0;
}

int HostPath::symlink(const std::string& target) {
    // 本 path=linkpath（host 已含 chroot 前缀），target 原样。
    return ::symlinkat(target.c_str(), AT_FDCWD, host.c_str()) == -1 ? -errno : 0;
}

int HostPath::chmod(mode_t mode, int flags) {
    // fchmodat 只认 AT_SYMLINK_NOFOLLOW（fchmodat2）；musl chmod() 经 __syscall3 调本 syscall
    // 只传 3 参，r(4) flags 是未初始化值，故屏蔽未知位避免误报 EINVAL。
    flags &= AT_SYMLINK_NOFOLLOW;
    return ::fchmodat(AT_FDCWD, host.c_str(), mode, flags) == -1 ? -errno : 0;
}

int HostPath::truncate(off_t len) {
    return ::truncate(host.c_str(), len) == -1 ? -errno : 0;
}

int HostPath::utimens(const struct timespec times[2], int flags) {
    return ::utimensat(AT_FDCWD, host.c_str(), times, flags) == -1 ? -errno : 0;
}

// link/rename：任一为 /proc 即 EROFS（链接到/重命名 /proc 项无意义）；其余两 host 透传。
int HostPath::link(const Path& other, int flags) {
    if(is_proc(guest) || is_proc(other.guest)) return -EROFS;
    int rc = ::linkat(AT_FDCWD, host.c_str(), AT_FDCWD, other.host.c_str(), flags);
    return rc == -1 ? -errno : 0;
}

int HostPath::rename(const Path& other, unsigned int flags) {
    if(is_proc(guest) || is_proc(other.guest)) return -EROFS;
#if defined(__ANDROID__)
    int rc = (int)::syscall(SYS_renameat2, AT_FDCWD, host.c_str(),
                            AT_FDCWD, other.host.c_str(), flags);
#else
    int rc = ::renameat2(AT_FDCWD, host.c_str(), AT_FDCWD, other.host.c_str(), flags);
#endif
    return rc == -1 ? -errno : 0;
}

// =====================================================================
// DevPath —— 仅 override open（DevFd::open 按 guest 路径匹配特殊设备，不拼 chroot）；
// readlink/statx/access/修改类/link/rename 全部继承 HostPath。
// =====================================================================
std::shared_ptr<Fd> DevPath::open(int flags, mode_t mode) {
    // /dev/* 严格按 guest 路径拦截（pty/tty/标准设备），不受 chroot 影响。
    return DevFd::open(guest, flags, mode, self);
}
