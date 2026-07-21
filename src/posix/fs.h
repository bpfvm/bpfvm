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
#include <unistd.h>     // close（HostFd 析构用）
#include <sys/types.h>   // off_t / ssize_t / mode_t
#include <sys/stat.h>    // struct statx
#include <sys/uio.h>     // struct iovec

class PosixSyscall;
class vm;

// 信号事件 POD（完整定义见 posix_syscall.h，下移避免循环 include）。
// 此处前向声明让 SignalFd::deliver 的方法声明可用；实现在 signal.cpp（可见完整定义）。
struct SigEvent;

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
// 引用数（对应内核 master tty_struct::count）。归零（DevFd::on_close 里 use_count()==1 判断，
// erase 析构后归零）触发 SIGHUP。slave fd 不持有 PtySide——slave 关闭不发 SIGHUP，故无需计数。
struct PtySide {};

// =====================================================================
// Fd —— 多态 fd 基类。
// 把"host fd 直通"与"/proc 虚拟文件"两种 fd 统一为同一接口，消除 syscall 入口的
// is_proc() 判空分流：每个 do_* 只保留公共逻辑（指针翻译、EINTR、tty 门控），
// I/O 动作通过虚方法下沉到 HostFd / ProcFile / ProcDir 各自实现。
//
// 虚方法约定：接收已翻译的 host 指针（不碰 vm/mmu），返回 ssize_t：
//   >=0 成功字节数（read/write 等），0 = EOF，<0 = 负 errno（如 -EINVAL/-EROFS/-EINTR）。
// EINTR 由各实现返回 -EINTR，syscall 层统一转 SYSCALL_RESTART。
//
// pty/tty 语义不暴露在基类（不是所有 fd 都是 pty 端）：SIGHUP-on-close 经
// on_close() 多态下沉到 DevFd；身份比对（TIOCSCTTY/TIOCSPGRP/TIOCGPGRP/tty_bg_check）
// 由调用方 dynamic_pointer_cast<DevFd> 拿到子类后用 guest_tty() 取。
// =====================================================================
struct Fd {
    bool cloexec = false;       // FD_CLOEXEC（F_GETFD/F_SETFD 用，两类 fd 公共）
    std::string path;           // guest 视角绝对路径（fchdir/readlinkat/openat-dirfd 用）
    virtual ~Fd() = default;

    // —— 分流的 I/O 虚方法（默认 = 不支持，子类覆盖）——
    virtual ssize_t read(void* buf, size_t count) { (void)buf; (void)count; return -EINVAL; }
    virtual ssize_t write(const void* buf, size_t count) { (void)buf; (void)count; return -EROFS; }
    virtual ssize_t pread(void* buf, size_t count, off_t off) { (void)buf; (void)count; (void)off; return -EINVAL; }
    virtual ssize_t pwrite(const void* buf, size_t count, off_t off) { (void)buf; (void)count; (void)off; return -EROFS; }
    virtual off_t lseek(off_t off, int whence) { (void)off; (void)whence; return -EINVAL; }
    virtual ssize_t readv(const struct iovec* iov, int iovcnt) { (void)iov; (void)iovcnt; return -EINVAL; }
    virtual ssize_t writev(const struct iovec* iov, int iovcnt) { (void)iov; (void)iovcnt; return -EROFS; }
    virtual ssize_t getdents64(void* buf, size_t count) { (void)buf; (void)count; return -ENOTDIR; }
    virtual int fstatx(struct statx* stx, unsigned int mask, int flags) { (void)stx; (void)mask; (void)flags; return -EBADF; }
    virtual int ftruncate(off_t len) { (void)len; return -EINVAL; }
    virtual int fchmod(mode_t mode) { (void)mode; return -EROFS; }
    virtual int futimens(const struct timespec times[2], int flags) { (void)times; (void)flags; return -EROFS; }

    // dup/fork 复制：HostFd ::dup 得独立 host fd；ProcFile/ProcDir 复制快照得独立游标。
    virtual std::shared_ptr<Fd> clone() const = 0;

    // —— host fd 访问（仅 HostFd 有效；ProcFile/ProcDir 返回 -1）——
    // socket/epoll/mmap/*at 系等纯 host fd 透传场景用此。ProcFile/ProcDir 返回 -1 → host syscall
    // 自然失败（EBADF），行为与重构前一致。
    virtual int host_fd() const { return -1; }

    // 销毁前副作用（所有 fd 关闭路径在 erase 前统一调）。默认 no-op。
    // DevFd override：pty master 末次关闭时向 ctty 前台组投 SIGHUP
    // （对齐 Linux pty_close → tty_vhangup）。其余子类（HostFd/SignalFd/ProcFile/ProcDir）
    // 用默认 no-op。
    // 约束：不得在持有 fds 锁（fds_mutate 重试循环）时调用——SIGHUP 投递会重入 fd 表。
    // 调用方须先 find_fd 拿到 shared_ptr 快照、退出锁、再调本方法，最后才 erase。
    virtual void on_close(PosixSyscall* /*self*/, vm* /*v*/) {}
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
    ssize_t getdents64(void* buf, size_t count) override;
    int fstatx(struct statx* stx, unsigned int mask, int flags) override;
    int ftruncate(off_t len) override;
    int fchmod(mode_t mode) override;
    int futimens(const struct timespec times[2], int flags) override;

    std::shared_ptr<Fd> clone() const override;
    int host_fd() const override { return fd_; }
    // host 透传工厂：openat(AT_FDCWD, host_path)。host_path 已含 chroot 前缀；guest_abs 存进
    // Fd::path（供 fchdir/readlinkat 用）。失败返 nullptr，errno 已设（host syscall 失败自带）。
    static std::shared_ptr<HostFd> open(const std::string& host_path, int flags, mode_t mode,
                                        std::string guest_abs);
};

// DevFd —— 设备 fd（pty master/slave、/dev/tty、PTY 模式初始 stdio）。
// 继承 HostFd：I/O 与 host fd 访问完全复用（设备端就是一个 host fd，读写直通 host libc），
// 仅额外承载 tty/pty 语义——fd 销毁时的 SIGHUP 投递经 on_close() 多态、
// ioctl TIOCSCTTY/TIOCSPGRP/TIOCGPGRP 与 tty_bg_check 的 tty 身份比对经 guest_tty()
// （调用方 dynamic_pointer_cast<DevFd> 后取）。
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
    // fd 销毁前副作用：master 末次关闭发 SIGHUP（所有 fd 关闭路径在 erase 前统一调）。
    void on_close(PosixSyscall* self, vm* v) override;
    // 身份访问器：返回 tty_ 的 shared_ptr（供 do_ioctl/tty_bg_check/DevFd::open 找 ctty fd
    // 比对；TIOCSCTTY 的 session->ctty 绑定也用此 shared_ptr 直接赋值）。
    const std::shared_ptr<GuestTty>& guest_tty() const { return tty_; }
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

// SignalFd —— signalfd 读端（pipe 模拟）。继承 HostFd：read/readv/poll/dup/fcntl 复用
// host fd 现成逻辑（pipe 本就是 host fd）；其余操作（write/pwrite/writev/lseek/ftruncate/
// fchmod/...）按 Linux signalfd 语义拦截返回错误，防止 guest 把数据写进内部 pipe 污染
// 信号流。额外承载内部 pipe 写端 + 监听 mask。
//   read_fd（= HostFd::fd_）—— 返给 guest 的读端，read/readv/poll 直通。
//   write_fd                —— VM 内部持有的写端（O_NONBLOCK，pipe 满则丢，与 Linux 一致）。
//   mask                    —— 监听信号集（bit (sig-1)）。
// fork 经 clone() 复制：子读端不能指向父同一 pipe（否则父子读到对方 pending），故 clone()
// 为子新建独立 pipe。task-wide 共享队列语义：handle_signals 里遍历 ps->fds 找 signalfd，
// 命中第一个 mask 匹配的就投一个（多个 signalfd 读同一 pending 队列，先到先得）。
struct SignalFd: HostFd {
    int write_fd;          // 内部 pipe 写端（O_NONBLOCK）
    // 监听信号集（bit (sig-1)）。atomic：deliver（handle_signals 路径，某线程 A 的
    // safepoint）与 do_signalfd4 的 mask 更新（线程 B 调 signalfd() 重建 mask）可能
    // 跨线程并发（CLONE_FILES 共享 fd 表 + CLONE_SIGHAND），pending_signals 锁是 per-vm
    // 的不足以保护；用 atomic 保证读到的要么旧要么新 mask，两者都自洽。
    std::atomic<uint64_t> mask;
    SignalFd(int read_fd, int write_fd, uint64_t mask_)
        : HostFd(read_fd), write_fd(write_fd), mask(mask_) {}
    ~SignalFd() override { if(write_fd >= 0) close(write_fd); }
    // 读端 fd_ 由 HostFd 析构关闭；写端在此关闭。

    std::shared_ptr<Fd> clone() const override;   // fork：独立新 pipe

    // —— 拦截对 signalfd 无意义的操作（对齐 Linux 行为，防止污染内部 pipe）——
    // 实测 Linux：write/writev/ftruncate → EINVAL；pwrite/pread → ESPIPE；
    // lseek 在 signalfd 上 rc=0（no-op），保留 HostFd 透传即可（无需 override）。
    ssize_t write(const void* buf, size_t count) override { (void)buf; (void)count; return -EINVAL; }
    ssize_t pwrite(const void* buf, size_t count, off_t off) override { (void)buf; (void)count; (void)off; return -ESPIPE; }
    ssize_t writev(const struct iovec* iov, int iovcnt) override { (void)iov; (void)iovcnt; return -EINVAL; }
    ssize_t pread(void* buf, size_t count, off_t off) override { (void)buf; (void)count; (void)off; return -ESPIPE; }
    int ftruncate(off_t len) override { (void)len; return -EINVAL; }

    // 投递：sig 在 mask 内则构造 signalfd_siginfo 写 pipe，返回 true（已消费）。
    // pipe 满（EAGAIN）/已关闭（EBADF）静默忽略，与 Linux signalfd 溢出语义一致。
    // ev 的 sender/code/status 透传给 ssi_pid/ssi_code/ssi_status。
    bool deliver(const SigEvent& ev);
};

// =====================================================================
// Path —— 路径解析多态基类：把所有"按路径"操作统一到对象上。
// do_openat/do_readlinkat/do_statx/do_unlinkat/... 先 ResolvePath(self,guest) 拿到对应子类，
// 再调对应虚方法，不再各自重复 /dev|/proc|host 前缀分发。子类按路径前缀分流：
//   /proc  → ProcPath（open 经 lookup→ProcFile/ProcDir；readlink/statx/access 经 lookup；修改类返 EROFS）
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

    // open：返回已打开的 Fd（ProcFile/ProcDir/DevFd/HostFd），失败返 nullptr 且 errno 已设。
    virtual std::shared_ptr<Fd> open(int flags, mode_t mode) = 0;
    // follow：返回 follow 符号链接后的 guest 路径（给 execve/execveat 用——它们需要真实
    //   可加载文件，而非 /proc 符号链接）。HostPath/DevPath 不穿透，返回自身 guest；
    //   ProcPath override：命中 LinkGen（/proc/<pid>/{exe,cwd,root}）返回目标 guest 路径，
    //   其余（文件/目录/符号链接跳出 /proc）返回 escape 或自身 guest。
    virtual std::string follow() { return guest; }
    // readlink：把目标写入 buf（按 bufsiz 截断，不含 NUL，与 readlink(2) 一致）。
    //   返回写入字节数（>=0=成功）；<0=负 errno（ENOENT=目标进程已退出；EINVAL=非符号链接；...）。
    virtual ssize_t readlink(char* buf, size_t bufsiz) = 0;
    // statx：填 stx。返回 0=成功；<0=负 errno。
    virtual int statx(struct statx* stx, unsigned int mask, int flags) = 0;
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
    std::shared_ptr<Fd> open(int flags, mode_t mode) override;               // HostFd::open(host,...,guest)
    ssize_t readlink(char* buf, size_t bufsiz) override;                     // ::readlink(host) 直写 buf
    int statx(struct statx* stx, unsigned int mask, int flags) override;     // ::statx(host)
    int access(int mode, int flags) override;                                // ::faccessat(host)
    int unlink(int flags) override;                                          // ::unlinkat(host)
    int mkdir(mode_t mode) override;                                         // ::mkdir(host)
    int symlink(const std::string& target) override;                         // ::symlinkat(target→host)
    int chmod(mode_t mode, int flags) override;                              // ::fchmodat(host)
    int truncate(off_t len) override;                                        // ::truncate(host)
    int utimens(const struct timespec times[2], int flags) override;         // ::utimensat(host)
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
    std::shared_ptr<Fd> open(int flags, mode_t mode) override;               // lookup→ProcFile/ProcDir/穿透
    std::string follow() override;                                           // 穿透 LinkGen（exe/cwd/root）
    ssize_t readlink(char* buf, size_t bufsiz) override;                     // lookup（跟随符号链接）
    int statx(struct statx* stx, unsigned int mask, int flags) override;     // lookup + 按 mode 填字段
    int access(int mode, int flags) override;                                // lookup 存在性
};

#endif
