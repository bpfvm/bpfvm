#ifndef POSIX_FS_H__
#define POSIX_FS_H__
//
// fs.h —— Fd / Path 多态层次及配套结构。
//

#include <string>
#include <memory>
#include <vector>
#include <utility>
#include <atomic>
#include <sys/types.h>   // off_t / ssize_t / mode_t
#include <sys/stat.h>    // struct statx
#include <sys/uio.h>     // struct iovec

class PosixSyscall;

// —— /proc 虚拟文件支持 ——
// bpfvm 是 host-fd 直通模型，/proc 没有 host 文件可 open，故引入一条并行的虚拟文件通道。
// 一次打开的实例（快照式）：open 时调 ProcNode::generate() 生成全量内容存进 data，
// read 按 pos 切片。与 Linux 一致（进程改 argv 后 /proc 仍反映旧值）。
struct ProcInstance {
    off_t pos = 0;
    std::string data;
    ssize_t read(void* buf, size_t count);  // 从 pos 读，推进 pos，EOF 返回 0
    off_t lseek(off_t off, int whence);     // SEEK_SET/CUR/END
};

// /proc 树上的一个节点（全局静态注册，被多次打开共享）。文件/目录/符号链接都用此接口。
// 三类实体各占一种子类（ProcFile/ProcDir/ProcLink），故 is_dir()/is_link() 互斥。
// 把符号链接也纳入 ProcNode 是为了让 procfs_lookup 成为唯一的路径分发入口：
// readlinkat/statx/open 各调一次 lookup 再经虚方法下沉，无需再额外查 procfs_readlink。
struct ProcNode {
    virtual ~ProcNode() = default;
    virtual bool is_dir() const = 0;
    virtual bool is_link() const { return false; }
    // 文件：生成全量内容（open 时调一次，快照式）；目录/链接：返回空。
    virtual std::string generate(PosixSyscall* self) { (void)self; return {}; }
    // 目录：列出子项 {name, d_type}（d_type 见 DT_* in <dirent.h>）；文件/链接：返回空。
    virtual std::vector<std::pair<std::string, unsigned char>> list(PosixSyscall* self) { (void)self; return {}; }
    // 符号链接：返回目标字符串（readlinkat 用）；非链接返回 false。空目标=进程已退出等。
    virtual bool readlink(PosixSyscall* self, std::string& target) { (void)self; (void)target; return false; }
    // statx 填充：文件默认 S_IFREG|0444 且 size=generate().size()；目录 S_IFDIR|0555；
    // 符号链接 S_IFLNK|0777 且 size=readlink().size()（见 ProcLink）。
    virtual void statx(struct statx& stx, PosixSyscall* self);
};

// guest tty 设备的 bpfvm 侧状态。
// 本对象只持有 bpfvm 必须管的进程语义：
//   fg_pgrp  —— 本设备当前前台进程组。tty 信号（SIGINT/SIGTSTP/...）发给 fg_pgrp 的所有成员。
//   owner_   —— 当前归属 session（裸指针，不参与生命周期：TIOCSCTTY 抢夺判定用）。
struct Session;
struct GuestTty {
    std::atomic<uint64_t> fg_pgrp{0};
    Session* owner_ = nullptr;
    GuestTty() = default;
};

// pty master 端的共享 token。DevFd(pty master) 持有它的 shared_ptr，use_count 即 master fd
// 引用数（对应内核 master tty_struct::count）。归零（drop_fd_handle 里 use_count()==1 判断，
// erase 析构后归零）触发 SIGHUP。slave fd 不持有 PtySide——slave 关闭不发 SIGHUP，故无需计数。
struct PtySide {};

// =====================================================================
// Fd —— 多态 fd 基类。
// 把"host fd 直通"与"/proc 虚拟文件"两种 fd 统一为同一接口，消除 syscall 入口的
// is_proc() 判空分流：每个 do_* 只保留公共逻辑（指针翻译、EINTR、tty 门控），
// I/O 动作通过虚方法下沉到 HostFd / ProcFd 各自实现。
//
// 虚方法约定：接收已翻译的 host 指针（不碰 vm/mmu），返回 ssize_t：
//   >=0 成功字节数（read/write 等），0 = EOF，<0 = 负 errno（如 -EINVAL/-EROFS/-EINTR）。
// EINTR 由各实现返回 -EINTR，syscall 层统一转 SYSCALL_RESTART。
// =====================================================================
struct Fd {
    bool cloexec = false;       // FD_CLOEXEC（F_GETFD/F_SETFD 用，两类 fd 公共）
    std::string path;           // guest 视角绝对路径（fchdir/readlinkat/openat-dirfd 用）
    virtual ~Fd() = default;

    // —— 分流的 I/O 虚方法（默认 = 不支持，子类覆盖）——
    virtual ssize_t read(void* buf, size_t count) { (void)buf; (void)count; return -EINVAL; }
    virtual ssize_t write(const void* buf, size_t count) { (void)buf; (void)count; return -EINVAL; }
    virtual ssize_t pread(void* buf, size_t count, off_t off) { (void)buf; (void)count; (void)off; return -EINVAL; }
    virtual ssize_t pwrite(const void* buf, size_t count, off_t off) { (void)buf; (void)count; (void)off; return -EINVAL; }
    virtual off_t lseek(off_t off, int whence) { (void)off; (void)whence; return -EINVAL; }
    virtual ssize_t readv(const struct iovec* iov, int iovcnt) { (void)iov; (void)iovcnt; return -EINVAL; }
    virtual ssize_t writev(const struct iovec* iov, int iovcnt) { (void)iov; (void)iovcnt; return -EINVAL; }
    virtual ssize_t getdents64(void* buf, size_t count, PosixSyscall* /*self*/) { (void)buf; (void)count; return -ENOTDIR; }
    virtual int ftruncate(off_t len) { (void)len; return -EINVAL; }

    // dup/fork 复制：HostFd ::dup 得独立 host fd；ProcFd 复制快照得独立 instance。
    virtual std::shared_ptr<Fd> clone() const = 0;

    // —— host fd 访问（仅 HostFd 有效；ProcFd 返回 -1）——
    // socket/epoll/mmap/*at 系等纯 host fd 透传场景用此。ProcFd 返回 -1 → host syscall
    // 自然失败（EBADF），行为与重构前一致。
    virtual int host_fd() const { return -1; }

    // —— pty/tty 专用（仅 HostFd 持有；ProcFd 返回空）——
    // tty_bg_check / TIOCSCTTY/TIOCSPGRP/TIOCGPGRP / drop SIGHUP 通过这些取 GuestTty。
    // ProcFd::tty() 返回 nullptr 使 tty_bg_check 第一行短路，无需在调用方判类型。
    virtual std::shared_ptr<GuestTty> tty() const { return nullptr; }
    virtual std::shared_ptr<PtySide> master_token() const { return nullptr; }
};

// HostFd —— host fd 直通（普通文件/pipe/socket）。
// 各 I/O 虚方法直接调 host libc 同名函数。不含任何 tty/pty 语义（设备 fd 见 DevFd）。
struct HostFd: Fd {
    const int fd_;                                     // host fd（>=0）
    explicit HostFd(int fd, std::string path_ = {})
        : fd_(fd) { path = std::move(path_); }
    ~HostFd() override { if(fd_ >= 0) close(fd_); }

    ssize_t read(void* buf, size_t count) override;
    ssize_t write(const void* buf, size_t count) override;
    ssize_t pread(void* buf, size_t count, off_t off) override;
    ssize_t pwrite(const void* buf, size_t count, off_t off) override;
    off_t lseek(off_t off, int whence) override;
    ssize_t readv(const struct iovec* iov, int iovcnt) override;
    ssize_t writev(const struct iovec* iov, int iovcnt) override;
    ssize_t getdents64(void* buf, size_t count, PosixSyscall* /*self*/) override;
    int ftruncate(off_t len) override;
    std::shared_ptr<Fd> clone() const override;

    int host_fd() const override { return fd_; }
    // tty()/master_token()/isatty() 不重写：回落 Fd 基类默认（nullptr/nullptr/false），
    // 使 tty_bg_check、drop_fd_handle、ioctl TIOC* 等在普通 host fd 上自然短路。
    // host 透传工厂：openat(AT_FDCWD, host_path)。host_path 已含 chroot 前缀；guest_abs 存进
    // Fd::path（供 fchdir/readlinkat 用）。失败返 nullptr，errno 已设（host syscall 失败自带）。
    static std::shared_ptr<HostFd> open(const std::string& host_path, int flags, mode_t mode,
                                        std::string guest_abs);
};

// DevFd —— 设备 fd（pty master/slave、/dev/tty、PTY 模式初始 stdio）。
// 继承 HostFd：I/O 与 host fd 访问完全复用（设备端就是一个 host fd，读写直通 host libc），
// 仅额外承载 tty/pty 语义——tty_bg_check 的 job-control 门控、drop_fd_handle 的 SIGHUP 计数、
// ioctl TIOCSCTTY/TIOCSPGRP/TIOCGPGRP 的 tty 身份比对都经 tty()/master_token() 多态取到。
//
// master/slave 区分靠 master_token_ 有无（沿用 PtySide 计数模型，无 enum）：
//   - pty master（/dev/ptmx）：构造时传 make_shared<PtySide>()，use_count()==1 时关闭触发 SIGHUP。
//   - pty slave（/dev/pts/N）、/dev/tty 合成端、PTY 初始 stdio：不传 master_token_（slave 关不发 SIGHUP）。
// master 与 slave 共享同一 GuestTty（经 ptmx_registry，与 HostFd 时代一致）。
struct DevFd: HostFd {
    std::shared_ptr<GuestTty> tty_;                    // 非空 = pty 端（master/slave 共享）
    std::shared_ptr<PtySide> master_token_;            // 非空 = pty master（use_count 计 SIGHUP）
    DevFd(int fd, std::string path_, std::shared_ptr<GuestTty> t,
          std::shared_ptr<PtySide> m = {})
        : HostFd(fd, std::move(path_)), tty_(std::move(t)), master_token_(std::move(m)) {}
    std::shared_ptr<Fd> clone() const override;        // 返回 DevFd，保留 tty_/master_token_
    std::shared_ptr<GuestTty> tty() const override { return tty_; }
    std::shared_ptr<PtySide> master_token() const override { return master_token_; }
    // /dev/* 严格拦截（不 fallback 到 host openat）：仅调用方已知是 /dev/* 路径时才调本函数。
    //   /dev/tty、/dev/ptmx、/dev/pts/N —— 合成 DevFd（pty 设备）。
    //   /dev/null、/dev/zero、/dev/urandom、/dev/random、/dev/full —— 委托 HostFd::open 开宿主
    //     真设备（不经 chroot 前缀：这些是 bpfvm 进程自身的设备，两模式行为一致）。
    //   其余 /dev/* —— err=-ENOENT（设备抽象封闭，不透传宿主 /dev 目录）。
    // 返回基类 Fd：pty 设备是 DevFd、标准设备是 HostFd，调用方统一存 shared_ptr<Fd>。
    // 失败返 nullptr，errno 已设。仅按 guest_abs 匹配，不看 dirfd（绝对路径特殊设备）。
    static std::shared_ptr<Fd> open(const std::string& guest_abs, int flags, mode_t mode,
                                    PosixSyscall* self);
};

// ProcFd —— 虚拟 /proc 文件（无 host fd，fd=-1）。
// read/lseek/getdents 从 ProcInstance 快照切片；write 返回 -EROFS（/proc 只读）。
struct ProcFd: Fd {
    std::shared_ptr<ProcNode> node;
    std::shared_ptr<ProcInstance> instance;
    ProcFd(std::shared_ptr<ProcNode> n, std::shared_ptr<ProcInstance> inst, std::string path_)
        : node(std::move(n)), instance(std::move(inst)) { path = std::move(path_); }

    ssize_t read(void* buf, size_t count) override;
    ssize_t write(const void* buf, size_t count) override;
    ssize_t pread(void* buf, size_t count, off_t off) override;
    ssize_t pwrite(const void* buf, size_t count, off_t off) override { (void)buf; (void)count; (void)off; return -EROFS; }
    off_t lseek(off_t off, int whence) override;
    ssize_t readv(const struct iovec* iov, int iovcnt) override;
    ssize_t writev(const struct iovec* iov, int iovcnt) override { (void)iov; (void)iovcnt; return -EROFS; }
    ssize_t getdents64(void* buf, size_t count, PosixSyscall* self) override;
    int ftruncate(off_t len) override;
    std::shared_ptr<Fd> clone() const override;
    // /proc/* 严格拦截（不 fallback 到 host openat）：仅调用方已知是 /proc/* 路径时才调本函数。
    // 命中 lookup 即构造 ProcFd（快照式）。/proc 下查不到节点 → ENOENT（设备封闭）。
    // 失败返 nullptr，errno 已设（如 EROFS：以写模式打开只读 proc 文件）。
    static std::shared_ptr<Fd> open(const std::string& guest_abs, int flags,
                                    PosixSyscall* self);
};

// =====================================================================
// Path —— 路径解析多态基类：把所有"按路径"操作统一到对象上。
// do_openat/do_readlinkat/do_statx/do_unlinkat/... 先 ResolvePath(self,guest) 拿到对应子类，
// 再调对应虚方法，不再各自重复 /dev|/proc|host 前缀分发。子类按路径前缀分流：
//   /proc  → ProcPath（open 经 ProcFd::open；readlink/statx/access 经 ProcNode；修改类返 EROFS）
//   /dev   → DevPath （open 经 DevFd::open；其余继承 HostPath 走 host）
//   其它   → HostPath（open 经 HostFd::open；readlink/statx/修改类调 host libc）
// Path 不开 fd、不快照——这些是真正 open 时才做的事。持有：
//   self  —— PosixSyscall*（ProcPath/DevPath 的 open 等要读进程状态，构造时存进成员）
//   guest —— guest 视角绝对路径（/proc、/dev 匹配 + 存进 Fd::path 用）
//   host  —— host 视角路径（含 chroot 前缀，ResolvePath 内算好；proc/dev 子类多数不用）
// =====================================================================
struct Path {
    PosixSyscall* self;   // 调用方 syscall handler（ProcPath/DevPath 用）
    std::string guest;    // guest 视角绝对路径
    std::string host;     // host 视角路径（含 chroot 前缀）
    Path(PosixSyscall* s, std::string g);
    virtual ~Path() = default;

    // open：返回已打开的 Fd（ProcFd/DevFd/HostFd），失败返 nullptr 且 errno 已设。
    virtual std::shared_ptr<Fd> open(int flags, mode_t mode) = 0;
    // readlink：把目标写入 buf（按 bufsiz 截断，不含 NUL，与 readlink(2) 一致）。
    //   返回写入字节数（>=0=成功）；<0=负 errno（ENOENT=目标进程已退出；EINVAL=非符号链接；...）。
    virtual ssize_t readlink(char* buf, size_t bufsiz) = 0;
    // statx：填 stx。返回 0=成功；<0=负 errno。
    virtual int statx(struct statx& stx, unsigned int mask, int flags) = 0;
    // access：返回 0=成功；<0=负 errno。
    virtual int access(int mode, int flags) = 0;

    // —— 修改类（统一返回 0=成功，<0=负 errno）——
    // 默认 -EROFS（/proc 只读 procfs）。HostPath override 走 host libc；DevPath 继承 HostPath。
    virtual int unlink(int /*flags*/) { return -EROFS; }
    virtual int mkdir(mode_t /*mode*/) { return -EROFS; }
    virtual int symlink(const std::string& /*target*/) { return -EROFS; }
    virtual int chmod(mode_t /*mode*/, int /*flags*/) { return -EROFS; }
    virtual int truncate(off_t /*len*/) { return -EROFS; }
    virtual int utimens(const struct timespec /*times*/[2], int /*flags*/) { return -EROFS; }

    // 双路径：本 path=old/src，other=new/dst。默认 -EROFS；HostPath override（任一是 /proc 即 EROFS）。
    virtual int link(const Path& /*other*/, int /*flags*/) { return -EROFS; }
    virtual int rename(const Path& /*other*/, unsigned int /*flags*/) { return -EROFS; }
};


// 工厂：按 guest 前缀分类返回对应 Path 子类（/proc→ProcPath、/dev→DevPath、其它→HostPath）。
// host 路径由 self->resolve_path(guest) 算好（含 chroot 前缀）传进 Path。
std::shared_ptr<Path> ResolvePath(PosixSyscall* self, std::string guest);

// HostPath —— host 文件系统路径。open 经 HostFd::open；readlink/statx/access/修改类调 host libc。
struct HostPath: Path {
    using Path::Path;
    std::shared_ptr<Fd> open(int flags, mode_t mode) override;                // HostFd::open(host,...,guest)
    ssize_t readlink(char* buf, size_t bufsiz) override;                     // ::readlink(host) 直写 buf
    int statx(struct statx& stx, unsigned int mask, int flags) override;     // ::statx(host)
    int access(int mode, int flags) override;                                // ::faccessat(host)
    int unlink(int flags) override;                                          // ::unlinkat(host)
    int mkdir(mode_t mode) override;                                         // ::mkdir(host)
    int symlink(const std::string& target) override;                         // ::symlinkat(target→host)
    int chmod(mode_t mode, int flags) override;                              // ::fchmodat(host)
    int truncate(off_t len) override;                                        // ::truncate(host)
    int utimens(const struct timespec times[2], int flags) override;         // ::utimensat(host)
    // 任一为 /proc 即 EROFS；否则 host libc（两 host 都已含 chroot 前缀）。
    int link(const Path& other, int flags) override;                         // ::linkat
    int rename(const Path& other, unsigned int flags) override;              // ::renameat2
};

// DevPath —— /dev 路径。仅 open 被 DevFd::open 拦截（pty/tty/标准设备）；
// readlink/statx/access/修改类全部继承 HostPath（与 PathStub 时代语义一致：/dev 交 host）。
struct DevPath: HostPath {
    using HostPath::HostPath;
    std::shared_ptr<Fd> open(int flags, mode_t mode) override;  // DevFd::open(guest,...,self)
};

// ProcPath —— /proc 路径。open/readlink/statx/access 查虚拟节点；修改类继承基类 -EROFS。
struct ProcPath: Path {
    using Path::Path;
    std::shared_ptr<Fd> open(int flags, mode_t mode) override;               // ProcFd::open(guest,self)
    ssize_t readlink(char* buf, size_t bufsiz) override;                     // magic_readlink + lookup
    int statx(struct statx& stx, unsigned int mask, int flags) override;     // lookup + node->statx
    int access(int mode, int flags) override;                                // lookup 存在性
};

#endif
