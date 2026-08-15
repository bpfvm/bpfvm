//
// fs.cpp — Fd / Path 多态层次的实现。
//
// 两部分：
//    - HostFd / DevFd 的 I/O 虚方法 + DevFd::open 工厂：
//      把"host fd 直通"的 I/O 动作封装——HostFd 调 host libc
//      同名函数（EINTR 时返回 -EINTR，syscall 层转 SYSCALL_RESTART）。
//      syscall 入口（do_read 等）只做指针翻译和 EINTR
//      处理，通过虚分派选择实现，不再判 is_proc()。
//      （/proc 虚拟文件 ProcFile 实现在 procfs.cpp；虚拟目录 VirtualDir 在本文件，/proc|/dev 共用。）
//    - Path 多态层次：ResolvePath 工厂 + HostPath/DevPath（按 guest 路径前缀 /proc|/dev|其它
//      分类）。调用方（do_openat/do_statx/...）统一模式：
//        ResolvePath(this, guest_abs_path(path, dirfd))->方法(...);
//      ProcPath 实现在 procfs.cpp（复用本编译单元外不暴露的 lookup）。
//

#include "posix_internal.h"
#include <sys/syscall.h>
#include <stdlib.h>
#include <fcntl.h>
#include <map>
#include <optional>
#include <climits>
#include <dirent.h>

// ptmx 注册表：已分配的 host pty 按 pts 编号(=TIOCGPTN)索引到 GuestTty。来源两类：
// guest open("/dev/ptmx") 合成、PTY 模式的初始控制终端（dev_ptmx_register）。
// open("/dev/pts/N") 与 /dev/pts 目录列举都查此表。条目随最后一个 master fd 关闭而
// 摘除（DevFd::on_close，对齐 devpts：master 关即删节点，已开的 slave fd 不受影响）；
// 初始 ctty 的 master 由 pump 线程持有一生，永不摘除。
static std::unordered_map<int, std::shared_ptr<GuestTty>> ptmx_registry;
static std::mutex ptmx_registry_mutex;

void dev_ptmx_register(int ptn, std::shared_ptr<GuestTty> tty) {
    if(ptn < 0 || !tty) return;
    tty->ptn = ptn;
    std::lock_guard<std::mutex> lk(ptmx_registry_mutex);
    ptmx_registry[ptn] = std::move(tty);
}

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
    off_t rc = ::lseek(fd_, off, whence);
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
// VirtualDir -- 虚拟目录 fd（/proc、/dev 等合成目录共用）。
// =====================================================================

// linux_dirent64 布局（host/guest UAPI 二进制兼容）：{u64 d_ino; s64 d_off;
// u16 d_reclen; u8 d_type; char d_name[];}。d_off 是 telldir cookie：取下一项的
// 条目索引，lseek 回到某 d_off 即从对应条目继续列举。
struct proc_linux_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};

ssize_t VirtualDir::getdents64(void* buf, size_t count) {
    // 用 idx 作目录列举游标。idx 0/1 固定为 "." 和 ".."（与真实 getdents 一致，
    // 部分 ls/find 实现依赖这两条），idx>=2 映射到 entries[idx-2]。
    char* cbuf = (char*)buf;
    size_t bufpos = 0;

    auto emit = [&](size_t cookie, const char* name, unsigned char dtype) -> bool {
        size_t namelen = strlen(name);
        size_t reclen = (24 + namelen + 1 + 7) & ~(size_t)7;
        if(bufpos + reclen > count) return false;  // 缓冲区满，下次继续
        auto* de = (proc_linux_dirent64*)(cbuf + bufpos);
        de->d_ino = 1 + cookie;        // 虚拟 inode（非 0 即可）
        de->d_off = (off_t)(cookie + 1);  // telldir cookie = 下一项的索引
        de->d_reclen = (uint16_t)reclen;
        de->d_type = dtype;
        memcpy(de->d_name, name, namelen);
        de->d_name[namelen] = '\0';
        bufpos += reclen;
        return true;
    };

    if(idx == 0) {
        if(!emit(0, ".", DT_DIR)) return (ssize_t)bufpos;
        idx = 1;
    }
    if(idx == 1) {
        if(!emit(1, "..", DT_DIR)) return (ssize_t)bufpos;
        idx = 2;
    }
    for(size_t i = (size_t)idx - 2; i < entries.size(); i++) {
        size_t cookie = i + 2;
        if(!emit(cookie, entries[i].first.c_str(), entries[i].second)) {
            idx = (off_t)cookie;  // 保留游标到本条目（下次重试）
            return (ssize_t)bufpos;
        }
        idx = (off_t)(cookie + 1);
    }
    return (ssize_t)bufpos;      // 0 = EOF（全部读完）
}

off_t VirtualDir::lseek(off_t off, int whence) {
    // 目录 fd 的 lseek：位置即 getdents 游标 idx，亦即 emit() 写进 d_off 的 telldir
    // cookie--lseek 回到某条目的 d_off 后，下一次 getdents 从其后一项继续（musl
    // rewinddir/seekdir 正是 SEEK_SET 到 0 / 到 telldir 值）。SEEK_END 对目录无
    // size 语义，拒之。越过表尾不 clamp：getdents 循环自然判 EOF。
    off_t base;
    switch(whence) {
    case SEEK_SET: base = 0; break;
    case SEEK_CUR: base = idx; break;
    default: return -EINVAL;
    }
    off_t pos = base + off;
    if(pos < 0) return -EINVAL;
    idx = pos;
    return pos;
}

int VirtualDir::fstatx(struct statx* stx, unsigned int /*mask*/, int /*flags*/) {
    memset(stx, 0, sizeof(*stx));
    stx->stx_mask = STATX_BASIC_STATS;
    stx->stx_blksize = 4096;
    stx->stx_nlink = 1;
    stx->stx_uid = 0;
    stx->stx_gid = 0;
    stx->stx_mode = S_IFDIR | 0555;
    stx->stx_size = 0;
    return 0;
}

std::shared_ptr<Fd> VirtualDir::clone() const {
    // 复制得独立 fd（idx 从 0 起，与 host dup 一致：两 fd 独立 seek 但内容相同）。
    auto fd = std::make_shared<VirtualDir>(*this);
    fd->idx = 0;
    return fd;
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

void DevFd::on_close(PosixSyscall* self, vm* v) {
    // pty master fd（master_token_ 非空）且是最后一个引用（use_count()==1，即调用方
    // 的 shared_ptr<Fd> h 持有的就是这最后一份，on_close 返回后调用方把 h 从 fd 表
    // erase，析构后 master_token_ 归零）时，摘除 /dev/pts 注册表条目，并向 ctty 前台组
    // 投 SIGHUP（对齐 Linux pty_close -> tty_vhangup + devpts 删节点）。slave fd
    // （master_token_ 为空）和 /dev/tty 合成端、PTY 初始 stdio 都不做这两件事。
    if(master_token_ && master_token_.use_count() == 1) {
        if(tty_ && tty_->ptn >= 0) {
            std::lock_guard<std::mutex> lk(ptmx_registry_mutex);
            ptmx_registry.erase(tty_->ptn);
        }
        self->deliver_to_ctty_fg(v, tty_.get(), SIGHUP);
    }
}

std::shared_ptr<Fd> SignalFd::clone() const {
    // fork 复制：为子新建独立 pipe（写端 O_NONBLOCK），mask 复制自父。子读端不能
    // 指向父同一 pipe——否则父子读到对方 pending 的信号，破坏 Linux task-pending 语义。
    // cloexec 不复制（由调用方按需设置，与 dup 语义一致）。
    int p[2];
    if(pipe2(p, 0) < 0) {
        return nullptr;
    }
    // 写端设 O_NONBLOCK：信号风暴时 pipe 满 → EAGAIN → 静默丢，绝不阻塞 VM 线程。
    int wf = fcntl(p[1], F_GETFL);
    if(wf >= 0) fcntl(p[1], F_SETFL, wf | O_NONBLOCK);
    // 父读端带 O_NONBLOCK（SFD_NONBLOCK 创建）→ 子读端也继承。
    int rf = fcntl(fd_, F_GETFL);
    if(rf >= 0 && (rf & O_NONBLOCK)) {
        int nrf = fcntl(p[0], F_GETFL);
        if(nrf >= 0) fcntl(p[0], F_SETFL, nrf | O_NONBLOCK);
    }
    return std::make_shared<SignalFd>(p[0], p[1], mask.load(std::memory_order_relaxed));
}

// =====================================================================
// /dev 合成设备层 -- 节点表 dev_nodes：open/statx/access/readlink/
// 目录列举全源于它。HostChr = host 真实存在的字符设备（statx/access 按 host 绝对
// 路径调用拿真实 rdev/dev；open 透传 host 或由 DevFd::open 合成 pty/tty 状态）；
// Dir = 合成目录；Symlink = 指向 /proc/self/fd(N) 的符号链接（与真实 Linux 一致）。
// 动态节点（/dev/pts/N，随 ptmx_registry 增删）与中间段链接改写（/dev/fd/N）不在
// 表内，由 dev_lookup 处理。
// =====================================================================
struct DevInfo {
    enum Kind { HostChr, Dir, Symlink } kind;
    std::string link;       // Symlink：readlink 的 target（如 /proc/self/fd/0）
    // 构造函数（非聚合）规避 -Wmissing-field-initializers。
    DevInfo(Kind k) : kind(k) {}
    DevInfo(Kind k, std::string l) : kind(k), link(std::move(l)) {}
};

static const std::map<std::string, DevInfo> dev_nodes = {
    {"/dev",         DevInfo{DevInfo::Dir}},
    {"/dev/pts",     DevInfo{DevInfo::Dir}},
    {"/dev/null",    DevInfo{DevInfo::HostChr}},
    {"/dev/zero",    DevInfo{DevInfo::HostChr}},
    {"/dev/full",    DevInfo{DevInfo::HostChr}},
    {"/dev/random",  DevInfo{DevInfo::HostChr}},
    {"/dev/urandom", DevInfo{DevInfo::HostChr}},
    {"/dev/tty",     DevInfo{DevInfo::HostChr}},
    {"/dev/ptmx",    DevInfo{DevInfo::HostChr}},
    {"/dev/console", DevInfo{DevInfo::HostChr}},
    {"/dev/fd",      DevInfo{DevInfo::Symlink, "/proc/self/fd"}},
    {"/dev/stdin",   DevInfo{DevInfo::Symlink, "/proc/self/fd/0"}},
    {"/dev/stdout",  DevInfo{DevInfo::Symlink, "/proc/self/fd/1"}},
    {"/dev/stderr",  DevInfo{DevInfo::Symlink, "/proc/self/fd/2"}},
};

// Kind -> 目录列举的 d_type（与节点类型一一对应：HostChr=DT_CHR、Dir=DT_DIR、
// Symlink=DT_LNK；同 procfs 的 gen_dtype 从节点描述现算 d_type）。
static unsigned char kind_dtype(DevInfo::Kind k) {
    switch(k) {
    case DevInfo::HostChr: return DT_CHR;
    case DevInfo::Dir:     return DT_DIR;
    case DevInfo::Symlink: return DT_LNK;
    }
    return DT_UNKNOWN;
}

// "/dev/pts/N" 的后缀数字解析：整串为非负十进制数才有效，
// 否则返回 -1（调用方按不存在处理 -> ENOENT）。
static int parse_dev_suffix(const char* s) {
    if(!*s) return -1;
    char* end = nullptr;
    long v = strtol(s, &end, 10);
    if(*end != '\0' || v < 0 || v > INT_MAX) return -1;
    return (int)v;
}

// 入参 guest_abs 已由 ResolvePath 去过尾斜杠。中间段符号链接（如 /dev/fd/3 的 fd 段）
// 把 target+剩余段经 escape 返回（对齐 procfs lookup 的 escape 机制），调用方经
// ResolvePath 重解析走完剩余部分；此时返回 nullopt。
static std::optional<DevInfo> dev_lookup(const std::string& guest_abs, std::string& escape) {
    auto it = dev_nodes.find(guest_abs);
    if(it != dev_nodes.end()) return it->second;

    // /dev/pts/N：查 ptmx_registry 存在性（与 open("/dev/pts/N") 一致）。
    if(guest_abs.rfind("/dev/pts/", 0) == 0) {
        int ptn = parse_dev_suffix(guest_abs.c_str() + 9);
        if(ptn < 0) return std::nullopt;
        std::lock_guard<std::mutex> lk(ptmx_registry_mutex);
        if(ptmx_registry.count(ptn)) return DevInfo{DevInfo::HostChr};
        return std::nullopt;
    }

    // /dev/fd 指向目录，走它取子项（/dev/fd/N，进程替换/按 fd 重开）是真实用法：按中间段
    // 链接语义 follow，target+剩余段经 escape 交回调用方重解析（/dev/fd/3 ->
    // /proc/self/fd/3，procfs 未实现则终点 ENOENT）。
    if(guest_abs.rfind("/dev/fd/", 0) == 0) {
        escape = dev_nodes.at("/dev/fd").link + guest_abs.substr(strlen("/dev/fd"));
        return std::nullopt;
    }
    return std::nullopt;
}

// /dev、/dev/pts 目录列举的 (name, d_type) 条目表（供 VirtualDir 构造用）。
static std::vector<std::pair<std::string, unsigned char>> dev_dir_entries(const std::string& guest) {
    if(guest == "/dev/pts") {
        // /dev/pts：列举 ptmx_registry 里所有已分配的 pts 编号（动态快照）。
        std::vector<std::pair<std::string, unsigned char>> e;
        std::lock_guard<std::mutex> lk(ptmx_registry_mutex);
        for(const auto& [ptn, _] : ptmx_registry) {
            e.emplace_back(std::to_string(ptn), DT_CHR);
        }
        return e;
    }
    // /dev：节点表里 /dev 的直接子项（子路径仅一段）。std::map 按键序输出。
    std::vector<std::pair<std::string, unsigned char>> e;
    for(const auto& [path, info] : dev_nodes) {
        if(path.size() > 5 && path.compare(0, 5, "/dev/") == 0 &&
           path.find('/', 5) == std::string::npos) {
            e.emplace_back(path.substr(5), kind_dtype(info.kind));
        }
    }
    return e;
}

// 入参 guest_abs 已由 ResolvePath 去过尾斜杠。
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
    // Linux 无 ctty 进程开 /dev/tty 的行为一致）。/dev/console 同此逻辑（musl syslog、
    // busybox init 用；bpfvm 无独立系统控制台，复用 ctty）。
    if(guest_abs == "/dev/tty" || guest_abs == "/dev/console") {
        const auto& session = self->session;
        if(!session || !session->ctty) {
            errno = ENXIO;
            return nullptr;
        }
        const auto& ctty = session->ctty;
        // 找一个已绑同一 ctty 的 guest DevFd 做 dup 源（PTY 模式下 fd 0/1/2 必是）。
        std::shared_ptr<Fd> src;
        for(const auto& entry : *self->ps->fds_snap()) {
            auto dfd = std::dynamic_pointer_cast<DevFd>(entry.second).get();
            if(dfd && dfd->guest_tty().get() == ctty.get()) {
                src = entry.second;
                break;
            }
        }
        if(!src) {
            errno = ENXIO;
            return nullptr;
        }
        int host_fd = dup(src->host_fd());
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
        dev_ptmx_register(ptn, tty);
        // master token：仅由 master fd 持有（use_count = master fd 数），最后一个关闭触发 SIGHUP。
        return std::make_shared<DevFd>(master, guest_abs, tty, std::make_shared<PtySide>());
    }
    // rfind(...,0) == 0 即 starts_with：前缀匹配 "/dev/pts/"（9 字符）。
    if(guest_abs.rfind("/dev/pts/", 0) == 0) {
        // /dev/pts/N：查 registry 取该编号的 GuestTty，打开对应 host slave，包成 DevFd。
        int ptn = parse_dev_suffix(guest_abs.c_str() + 9);  // 数字从 index 9 起
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
    // 标准设备（节点表 HostChr，前面 pty/tty 分支未拦截的）：委托 HostFd::open 开宿主
    // 真设备（不经 chroot 前缀--这些是 bpfvm 进程自身的设备，chroot/非 chroot 行为一致）。
    // 标准设备不需 pty/tty 语义（不进 session->ctty 链，tty_bg_check 对它们自然短路），
    // 故直接返 HostFd（已是 Fd 子类）。host_path 直接用 guest_abs（不拼 chroot root）。
    auto it = dev_nodes.find(guest_abs);
    if(it != dev_nodes.end() && it->second.kind == DevInfo::HostChr) {
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
    // /proc、/dev 统一去尾斜杠：虚拟层内部按精确/组件匹配，而 Linux path resolution
    // 忽略非根尾斜杠。host 路径不剥--尾斜杠对内核有"必须是目录"的语义
    // （如 open("newfile/", O_CREAT) 须 EISDIR），交内核判。
    if(is_proc(guest)) {
        while(guest.size() > 1 && guest.back() == '/') guest.pop_back();
        return std::make_shared<ProcPath>(self, std::move(guest));
    }
    if(is_dev(guest)) {
        while(guest.size() > 1 && guest.back() == '/') guest.pop_back();
        return std::make_shared<DevPath>(self, std::move(guest));
    }
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

// link/rename：任一为 /proc|/dev 即 EXDEV（与 Linux 跨挂载点一致：host fs 与虚拟层互为
// 独立文件系统。同时拦住 chroot 下 rootfs 的 proc/、dev/ 挂载点占位目录被真实写入--
// 那会让 guest 把文件改名进虚拟层看不见的阴影目录）；其余走 host 透传。
int HostPath::link(const Path& other, int flags) {
    if(is_proc(guest) || is_proc(other.guest) || is_dev(guest) || is_dev(other.guest)) return -EXDEV;
    int rc = ::linkat(AT_FDCWD, host.c_str(), AT_FDCWD, other.host.c_str(), flags);
    return rc == -1 ? -errno : 0;
}

int HostPath::rename(const Path& other, unsigned int flags) {
    if(is_proc(guest) || is_proc(other.guest) || is_dev(guest) || is_dev(other.guest)) return -EXDEV;
#if defined(__ANDROID__)
    int rc = (int)::syscall(SYS_renameat2, AT_FDCWD, host.c_str(),
                            AT_FDCWD, other.host.c_str(), flags);
#else
    int rc = ::renameat2(AT_FDCWD, host.c_str(), AT_FDCWD, other.host.c_str(), flags);
#endif
    return rc == -1 ? -errno : 0;
}

// =====================================================================
// DevPath -- /dev 合成设备层的按路径操作（类注释见 fs.h）。
// =====================================================================
std::shared_ptr<Fd> DevPath::open(int flags, mode_t mode) {
    // 中间段符号链接（/dev/fd/N 的 fd 段）已 follow 出 /dev -> escape 是 target+剩余段
    // 的完整路径，经 ResolvePath 重解析走剩余部分（O_NOFOLLOW 只管末段，此处不判）。
    std::string escape;
    auto info = dev_lookup(guest, escape);
    if(!escape.empty()) {
        return ResolvePath(self, escape)->open(flags, mode);
    }
    if(info && info->kind == DevInfo::Dir) {
        return std::make_shared<VirtualDir>(guest, dev_dir_entries(guest));
    }
    if(info && info->kind == DevInfo::Symlink) {
        // O_NOFOLLOW：末段是符号链接，按 open(2) 判 ELOOP（do_openat 不看此 flag，
        // 虚拟符号链接须自查）。
        if(flags & O_NOFOLLOW) { errno = ELOOP; return nullptr; }
        // follow target（/proc/self/fd[N]，经 ResolvePath 重解析；procfs 未实现该目录 -> ENOENT）。
        return ResolvePath(self, info->link)->open(flags, mode);
    }
    // 其余（HostChr/未命中）交 DevFd::open。
    return DevFd::open(guest, flags, mode, self);
}

ssize_t DevPath::readlink(char* buf, size_t bufsiz) {
    // 中间段符号链接跳出 /dev（如 /dev/fd/3）-> escape 交 ResolvePath 读真实符号链接。
    std::string escape;
    auto info = dev_lookup(guest, escape);
    if(!escape.empty()) {
        return ResolvePath(self, escape)->readlink(buf, bufsiz);
    }
    if(!info) return -ENOENT;
    // Symlink：返回符号链接 target（按 bufsiz 截断，不含 NUL，与 readlink(2) 一致）。
    if(info->kind == DevInfo::Symlink) {
        size_t n = info->link.size() < bufsiz ? info->link.size() : bufsiz;
        memcpy(buf, info->link.data(), n);
        return (ssize_t)n;
    }
    return -EINVAL;   // HostChr/Dir 非符号链接
}

int DevPath::statx(struct statx* stx, unsigned int mask, int flags) {
    // 中间段符号链接跳出 /dev（如 /dev/fd/3）-> escape 交 ResolvePath 的 statx 走完
    // 剩余部分（同 ProcPath::statx 的 escape 分支）。
    std::string escape;
    auto info = dev_lookup(guest, escape);
    if(!escape.empty()) {
        return ResolvePath(self, escape)->statx(stx, STATX_BASIC_STATS, flags);
    }
    if(!info) return -ENOENT;
    if(info->kind == DevInfo::HostChr) {
        // host 真实设备：绝对路径 stat（不拼 chroot），拿真实 rdev/dev/mode。
#if defined(__ANDROID__)
        int rc = (int)::syscall(SYS_statx, AT_FDCWD, guest.c_str(), flags, mask, stx);
#else
        int rc = ::statx(AT_FDCWD, guest.c_str(), flags, mask, stx);
#endif
        return rc == -1 ? -errno : 0;
    }
    if(info->kind == DevInfo::Dir) {
        // /dev、/dev/pts 合成目录。
        memset(stx, 0, sizeof(*stx));
        stx->stx_mask = STATX_BASIC_STATS;
        stx->stx_blksize = 4096;
        stx->stx_nlink = 1;
        stx->stx_uid = 0;
        stx->stx_gid = 0;
        stx->stx_mode = S_IFDIR | 0555;
        stx->stx_size = 0;
        return 0;
    }
    if(flags & AT_SYMLINK_NOFOLLOW) {
        memset(stx, 0, sizeof(*stx));
        stx->stx_mask = STATX_BASIC_STATS;
        stx->stx_blksize = 4096;
        stx->stx_nlink = 1;
        stx->stx_mode = S_IFLNK | 0777;
        stx->stx_size = info->link.size();
        return 0;
    }
    // follow：重解析 target（procfs 未实现 /proc/self/fd -> ENOENT，与 open 一致）。
    return ResolvePath(self, info->link)->statx(stx, mask, flags);
}

int DevPath::access(int mode, int flags) {
    // 中间段符号链接跳出 /dev（如 /dev/fd/3）-> escape 交 ResolvePath 的 access 测
    // 真实目标（同 ProcPath::access 的 escape 分支）。
    std::string escape;
    auto info = dev_lookup(guest, escape);
    if(!escape.empty()) {
        return ResolvePath(self, escape)->access(mode, flags);
    }
    if(!info) return -ENOENT;
    if(info->kind == DevInfo::HostChr) {
        // host 真实设备：绝对路径测访问性（不拼 chroot）。
        return ::faccessat(AT_FDCWD, guest.c_str(), mode, flags) == -1 ? -errno : 0;
    }
    // Dir/Symlink：合成节点，存在即允许（F_OK/R_OK/W_OK 不真验权限）。
    return 0;
}
