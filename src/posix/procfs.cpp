//
// procfs.cpp — /proc 虚拟文件系统模拟
//
// 全部 procfs 逻辑（lookup 路径分发、gen_pid_* 内容生成）都是自由函数，不挂在
// PosixSyscall 上；经 PosixSyscall 的 public 进程标识
// 字段（pid/ppid/tg/pgrp/session/comm_/ps）与 *_of 静态转发（options_of/maps_of/
// flags_of）+ find_task/sys/list_pids 读 vm/进程内部。
//
// /proc 基于 guest 绝对路径匹配（仿 /dev/tty、/dev/ptmx 等特殊设备），不拼 chroot
// root 前缀。[pid] 用 guest 的 pid/tgid，完全按 guest 语义生成 —— 这是"模拟"而非
// "直通 host /proc"的核心。
//
// 内容策略：快照式。open 时调一次 generate 生成全量内容存进 ProcFile::data，
// read 按 pos 切片。与 Linux 一致（进程改 argv 后 /proc 仍反映旧值）。
//

#include "posix_internal.h"

#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <map>

// =====================================================================
// make_comm — basename，截断到 15 字节（Linux TASK_COMM_LEN-1）
// =====================================================================

std::string make_comm(const std::string& path) {
    auto slash = path.find_last_of('/');
    std::string base = (slash != std::string::npos) ? path.substr(slash + 1) : path;
    if(base.size() > 15) base.resize(15);  // TASK_COMM_LEN = 16（含 NUL）
    return base;
}

struct IGen {
    virtual ~IGen() = default;
    virtual mode_t mode() const = 0;
};

struct NoneGen: IGen {
    mode_t mode() const override { return 0; }
};

// Gen —— Type Erasure 包装类，统一持有 FileGen/DirGen/LinkGen。
struct Gen {
    std::shared_ptr<IGen> ptr;
    Gen() : ptr(std::make_shared<NoneGen>()) {}

    // 允许任何继承自 IGen 的对象（如 FileGen）在初始化列表中自动隐式转换为 Gen
    template <typename T, typename = std::enable_if_t<std::is_base_of_v<IGen, T>>>
    Gen(T obj) : ptr(std::make_shared<T>(std::move(obj))) {}

    mode_t mode() const { return ptr->mode(); }

    // 辅助方法：取出底层具体的指针以便调用 operator()
    template<typename T>
    T* as() const { return dynamic_cast<T*>(ptr.get()); }
};

struct FileGen: IGen {
    std::function<std::string()> func;
    FileGen(std::function<std::string()> f) : func(std::move(f)) {}

    mode_t mode() const override { return S_IFREG; }
    std::string operator()() { return func(); }
};

struct LinkGen: IGen {
    std::function<std::string()> func;
    LinkGen(std::function<std::string()> f) : func(std::move(f)) {}

    mode_t mode() const override { return S_IFLNK; }
    std::string operator()() { return func(); }
};

struct DirGen: IGen {
    // DirGen 内部返回的是包装类 Gen 的 Map
    std::function<std::map<std::string, Gen>()> func;
    DirGen(std::function<std::map<std::string, Gen>()> f) : func(std::move(f)) {}

    mode_t mode() const override { return S_IFDIR; }
    std::map<std::string, Gen> operator()() { return func(); }
};

// ProcFile —— 虚拟 /proc 文件（无 host fd，fd=-1）。
// 快照式：构造时调 gen.func() 生成全量内容存进 data，read 按 pos 切片。
// 与 Linux 一致（进程改 argv 后 /proc 仍反映旧值）。write 返回 -EROFS（/proc 只读）。
struct ProcFile: Fd {
    off_t pos = 0;            // 读游标（read/readv 推进；pread/lseek 不随之）
    std::string data;         // 构造时的全量快照
    // 构造即快照：调一次 gen.func() 冻结内容（与旧实现的 fd->data = node->generate() 等价，
    // 只是挪进构造函数，使 ProcFile 一经构造即可独立 read）。
    ProcFile(std::string path_, FileGen g): data(g.func()) { path = std::move(path_); }

    ssize_t read(void* buf, size_t count) override;
    ssize_t pread(void* buf, size_t count, off_t off) override;
    off_t lseek(off_t off, int whence) override;
    ssize_t readv(const struct iovec* iov, int iovcnt) override;
    int fstatx(struct statx* stx, unsigned int mask, int flags) override;
    std::shared_ptr<Fd> clone() const override;
};

ssize_t ProcFile::read(void* buf, size_t count) {
    if(pos < 0) return -EINVAL;
    if((size_t)pos >= data.size()) return 0;  // EOF
    size_t avail = data.size() - (size_t)pos;
    size_t n = count < avail ? count : avail;
    memcpy(buf, data.data() + pos, n);
    pos += (off_t)n;
    return (ssize_t)n;
}

ssize_t ProcFile::pread(void* buf, size_t count, off_t off) {
    // 按 off 读取快照（不推进 pos，与 pread 语义一致）。
    if(off < 0) return -EINVAL;
    if((size_t)off >= data.size()) return 0;
    size_t avail = data.size() - (size_t)off;
    size_t n = count < avail ? count : avail;
    memcpy(buf, data.data() + off, n);
    return (ssize_t)n;
}

off_t ProcFile::lseek(off_t off, int whence) {
    off_t base;
    switch(whence) {
    case SEEK_SET: base = 0; break;
    case SEEK_CUR: base = pos; break;
    case SEEK_END: base = (off_t)data.size(); break;
    default: return -EINVAL;
    }
    off_t np = base + off;
    if(np < 0) return -EINVAL;
    pos = np;
    return pos;
}

ssize_t ProcFile::readv(const struct iovec* iov, int iovcnt) {
    // 按 iovec 顺序从快照切片填充（与 readv 语义一致）。
    ssize_t total = 0;
    for(int i = 0; i < iovcnt; ++i) {
        size_t len = iov[i].iov_len;
        if(len == 0) continue;
        ssize_t rc = read(iov[i].iov_base, len);
        if(rc <= 0) break;
        total += rc;
        if((size_t)rc < len) break;  // EOF 或短读
    }
    return total;
}

std::shared_ptr<Fd> ProcFile::clone() const {
    // 复制快照得独立 fd（pos 从 0 起，与 host dup 一致：两 fd 独立 seek 但内容相同）。
    auto fd = std::make_shared<ProcFile>(*this);
    fd->pos = 0;
    return fd;
}

// fstatx（fstat 语义）：虚拟 /proc 文件 inode。与 ProcPath::statx 路径形式一致，
// mode 恒 S_IFREG|0444，size 恒 0（procfs 文件无固定大小，与真实 Linux 一致）。
int ProcFile::fstatx(struct statx* stx, unsigned int /*mask*/, int /*flags*/) {
    memset(stx, 0, sizeof(*stx));
    stx->stx_mask = STATX_BASIC_STATS;
    stx->stx_blksize = 4096;
    stx->stx_nlink = 1;
    stx->stx_uid = 0;
    stx->stx_gid = 0;
    stx->stx_mode = S_IFREG | 0444;
    stx->stx_size = 0;
    return 0;
}


// ProcDir —— 虚拟 /proc 目录（无 host fd，fd=-1）。
// 快照式：构造时调 gen.func() 生成全量子项存进 entries，getdents 按 idx 切片。
struct ProcDir: Fd {
    using Entries = std::vector<std::pair<std::string, Gen>>;
    off_t idx = 0;            // getdents 游标（"."/.. 占 idx 0/1，真实条目从 idx 2 起）
    Entries entries;
    ProcDir(std::string path_, DirGen g): entries(make_entries(std::move(g))) { path = std::move(path_); }
    ssize_t getdents64(void* buf, size_t count) override;
    int fstatx(struct statx* stx, unsigned int mask, int flags) override;
    std::shared_ptr<Fd> clone() const override;
private:
    // 把 DirGen 返回的 map 转成 vector（保留插入序、可重复 read）。
    static Entries make_entries(DirGen g) {
        auto m = g.func();
        return Entries(m.begin(), m.end());
    }
};

// linux_dirent64 布局（host/guest UAPI 二进制兼容）：{u64 d_ino; s64 d_off;
// u16 d_reclen; u8 d_type; char d_name[];}。d_off 是 telldir cookie——指向"本条目
// 之后下一项的位置"。本虚拟目录用条目索引作 cookie，语义自洽：lseek 回到某 d_off
// 即跳到对应条目继续列举（与用 idx 做游标一致），不依赖缓冲区内字节偏移。
struct proc_linux_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};

// mode_t → d_type：ProcDir::entries 存的是 Gen（节点描述），其 mode() 决定 d_type。
static unsigned char gen_dtype(const Gen& g) {
    mode_t m = g.mode();
    if(S_ISDIR(m))  return DT_DIR;
    if(S_ISLNK(m))  return DT_LNK;
    return DT_REG;
}

ssize_t ProcDir::getdents64(void* buf, size_t count) {
    // 用 idx 作目录列举游标。idx 0/1 固定为 "." 和 ".."（与真实 getdents 一致，
    // 部分 ls/find 实现依赖这两条），idx>=2 映射到 entries[idx-2]。
    char* cbuf = (char*)buf;
    size_t bufpos = 0;

    // 内联辅助：往 cbuf+bufpos 写一条目录项，成功写入推进 bufpos 并返回 true，
    // 缓冲区放不下返回 false（调用方停止，保留当前 idx 供下次继续）。
    auto emit = [&](size_t cookie, const char* name, unsigned char dtype) -> bool {
        size_t namelen = strlen(name);
        size_t reclen = (24 + namelen + 1 + 7) & ~(size_t)7;
        if(bufpos + reclen > count) return false;  // 缓冲区满，下次继续
        auto* de = (proc_linux_dirent64*)(cbuf + bufpos);
        de->d_ino = 1 + cookie;        // 虚拟 inode（与旧版一致，非 0 即可）
        de->d_off = (off_t)(cookie + 1);  // telldir cookie = 下一项的索引
        de->d_reclen = (uint16_t)reclen;
        de->d_type = dtype;
        memcpy(de->d_name, name, namelen);
        de->d_name[namelen] = '\0';
        bufpos += reclen;
        return true;
    };

    // "." / ".."
    if(idx == 0) {
        if(!emit(0, ".", DT_DIR)) return (ssize_t)bufpos;
        idx = 1;
    }
    if(idx == 1) {
        if(!emit(1, "..", DT_DIR)) return (ssize_t)bufpos;
        idx = 2;
    }
    // 真实条目
    for(size_t i = (size_t)idx - 2; i < entries.size(); i++) {
        size_t cookie = i + 2;
        if(!emit(cookie, entries[i].first.c_str(), gen_dtype(entries[i].second))) {
            idx = (off_t)cookie;  // 保留游标到本条目（下次重试）
            return (ssize_t)bufpos;
        }
        idx = (off_t)(cookie + 1);
    }
    return (ssize_t)bufpos;      // 0 = EOF（全部读完）
}

std::shared_ptr<Fd> ProcDir::clone() const {
    // 复制快照得独立 fd（idx 从 0 起，与 host dup 一致：两 fd 独立 seek 但内容相同）。
    auto fd = std::make_shared<ProcDir>(*this);
    fd->idx = 0;
    return fd;
}

int ProcDir::fstatx(struct statx* stx, unsigned int /*mask*/, int /*flags*/) {
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


// =====================================================================
// 全局静态节点：/proc 顶层非 [pid] 文件
// =====================================================================
static std::string gen_cpuinfo() {
    long n = sysconf(_SC_NPROCESSORS_CONF);
    if(n <= 0) n = 1;
    std::string out;
    for(long i = 0; i < n; i++) {
        out += "processor\t: " + std::to_string(i) + "\n";
        out += "vendor_id\t: GenuineBPF\n";
        out += "cpu family\t: 0\n";
        out += "model\t\t: 0\n";
        out += "model name\t: BPF Virtual CPU\n";
        out += "cpu MHz\t\t: 0.000\n";
        out += "cache size\t: 0 KB\n";
        out += "bogomips\t: 0.00\n\n";
    }
    return out;
}

static std::string gen_meminfo() {
    struct sysinfo si;
    sysinfo(&si);
    // si.mem_unit 是字节单位（现代内核为 1）。转 kB：pages * mem_unit / 1024。
    unsigned long unit = si.mem_unit ? si.mem_unit : 1;
    auto kb = [unit](unsigned long pages) { return pages * unit / 1024; };
    std::string out;
    out += "MemTotal:       " + std::to_string(kb(si.totalram)) + " kB\n";
    out += "MemFree:        " + std::to_string(kb(si.freeram)) + " kB\n";
    out += "Buffers:        " + std::to_string(kb(si.bufferram)) + " kB\n";
    out += "Cached:         0 kB\n";
    out += "SwapTotal:      " + std::to_string(kb(si.totalswap)) + " kB\n";
    out += "SwapFree:       " + std::to_string(kb(si.freeswap)) + " kB\n";
    return out;
}

static std::string gen_uptime() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    char buf[64];
    snprintf(buf, sizeof(buf), "%.2f 0.00\n", (double)ts.tv_sec + ts.tv_nsec / 1e9);
    return buf;
}

static std::string gen_version() {
    return "Linux version 6.12.0 (bpfvm) (clang)\n";
}

static std::string gen_filesystems() {
    return "nodev\tproc\nnodev\ttmpfs\nnodev\tdevtmpfs\nnodev\tsysfs\n";
}

static std::string gen_loadavg() {
    return "0.00 0.00 0.00 1/1 1\n";
}

static std::string gen_mounts() {
    return "proc / proc rw,relatime 0 0\ntmpfs /tmp tmpfs rw,relatime 0 0\n";
}

// =====================================================================
// /proc/[pid]/* 内容生成器（自由函数；经 PosixSyscall 的 public 字段与 *_of 转发读内部）
// =====================================================================
static char proc_state(vm* task) {
    if(!task) return 'R';
    uint32_t f = PosixSyscall::flags_of(task);
    if(f & vm::VM_EXITED) return 'Z';
    if(f & vm::VM_STOPPED) return 'T';
    if(f & vm::VM_BLOCKED) return 'S';
    return 'R';
}

// stat/status/comm 在 [pid] 与 [tid] 下函数体相同：参数 id 既是 stat 的第一字段、
// status 的 Pid 字段，也用于 lookup 该 task 取 comm/state/进程级字段。区别仅在语义
// 注释（[pid] 视角下 id=tgid，[tid] 视角下 id=tid），故共用一份实现，由调用方传不同 id。
//
// [pid]/stat：第一字段是 tgid。[tid]/stat：第一字段是 tid。状态/comm 取该 task 自身，
// pgid/sid/ppid 等进程级字段同组线程一致（继承自 leader）。
static std::string gen_task_stat(uint64_t id) {
    auto task_vm = PosixSyscall::find_task(id);
    auto proc = PosixSyscall::sys(task_vm.get());
    uint64_t ppid = proc->tg->ppid.load();
    uint64_t pgid = proc->pgrp->pgid;
    uint64_t sid = proc->session->sid;
    const std::string& comm = proc->comm_;
    char state = task_vm ? proc_state(task_vm.get()) : 'Z';
    std::string out;
    out += std::to_string(id) + " (" + comm + ") " + state + " ";
    out += std::to_string(ppid) + " " + std::to_string(pgid) + " " + std::to_string(sid) + " ";
    out += "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 "; // tty_nr..num_threads（近似）
    out += "0 0 0 0 ";                        // itrealvalue/starttime/vsize/rss
    out += "0 0 0 0 0 ";                      // rsslim..kstkesp
    out += "0 0 0 0 0 ";                      // kstkeip..sigcatch
    out += "0 0 0 0 0 0 0 ";                  // wcan..delayacct
    out += "0 0\n";                           // guest_time/cguest_time
    return out;
}

// [pid]/status：Pid 字段报 tgid。[tid]/status：Pid 字段报 tid（线程视角），
// Tgid 仍是组长 tgid。
static std::string gen_task_status(uint64_t id) {
    auto task_vm = PosixSyscall::find_task(id);
    auto proc = PosixSyscall::sys(task_vm.get());
    char state = task_vm ? proc_state(task_vm.get()) : 'Z';
    std::string out;
    out += "Name:\t" + proc->comm_ + "\n";
    out += "Umask:\t" + std::to_string(proc->ps->umask) + "\n";
    out += "State:\t" + std::string(1, state) + "\n";
    out += "Tgid:\t" + std::to_string(proc->tg->tgid) + "\n";
    out += "Ngid:\t0\n";
    out += "Pid:\t" + std::to_string(id) + "\n";
    out += "PPid:\t" + std::to_string(proc->tg->ppid.load()) + "\n";
    out += "TracerPid:\t0\n";
    out += "Uid:\t0\t0\t0\t0\n";
    out += "Gid:\t0\t0\t0\t0\n";
    out += "FDSize:\t32\n";
    out += "Groups:\n";
    out += "VmSize:\t    0 kB\n";
    out += "VmRSS:\t    0 kB\n";
    return out;
}

static std::string gen_pid_cmdline(uint64_t pid) {
    auto task_vm = PosixSyscall::find_task(pid);
    if(!task_vm) return {};
    const auto& argv = PosixSyscall::options_of(task_vm.get()).argv;
    std::string out;
    for(const auto& a : argv) { out += a; out += '\0'; }
    return out;
}

static std::string gen_pid_environ(uint64_t pid) {
    auto task_vm = PosixSyscall::find_task(pid);
    if(!task_vm) return {};
    const auto& envp = PosixSyscall::options_of(task_vm.get()).envp;
    std::string out;
    for(const auto& e : envp) { out += e; out += '\0'; }
    return out;
}

// comm：[pid]/comm 是进程名；[tid]/comm 是该线程自己的名字（pthread_setname_np 可
// 单独设置，与 [pid]/comm 独立）。函数体相同——按 id 取该 task 的 comm。
static std::string gen_task_comm(uint64_t id) {
    auto task_vm = PosixSyscall::find_task(id);
    auto proc = PosixSyscall::sys(task_vm.get());
    return proc ? (proc->comm_ + "\n") : std::string();
}

static std::string gen_pid_maps(uint64_t pid) {
    auto task_vm = PosixSyscall::find_task(pid);
    if(!task_vm) return {};
    std::string out;
    char line[160];
    std::lock_guard<std::mutex> lock(*PosixSyscall::maps_mutex_of(task_vm.get()));
    for(const auto& m : PosixSyscall::maps_of(task_vm.get())) {
        char perms[5] = "----";
        if(m.flags & PF_R) perms[0] = 'r';
        if(m.flags & PF_W) perms[1] = 'w';
        if(m.flags & PF_X) perms[2] = 'x';
        perms[3] = 'p';
        snprintf(line, sizeof(line), "%016lx-%016lx %s %08lx 00:00 0\n",
                 (unsigned long)m.paddr, (unsigned long)(m.paddr + m.size), perms, 0UL);
        out += line;
    }
    return out;
}


// 进程目录与线程目录**内容完全相同**的条目集（进程级共享数据：mm/fs/argv/envp/挂载）。
// comm/stat/status 三者两目录语义不同（进程名/tgid vs 线程名/tid），但实现共用（gen_task_*），不在此共享。
static std::map<std::string, Gen> proc_task_common_entries(pid_t id) {
    return std::map<std::string, Gen>{
        {"mounts",  FileGen([]{ return gen_mounts();})},
        {"root",    LinkGen([]{ return "/";})},
        {"statm",   FileGen([]{ return std::string("0 0 0 0 0 0 0\n"); })},
        {"cmdline", FileGen([id]{ return gen_pid_cmdline(id); })},
        {"environ", FileGen([id]{ return gen_pid_environ(id); })},
        {"maps",    FileGen([id]{ return gen_pid_maps(id); })},
        {"cwd",     LinkGen([id]{
            auto task_vm = PosixSyscall::find_task(id);
            auto proc = PosixSyscall::sys(task_vm.get());
            return proc ? proc->ps->cwd : std::string();
        })},
        {"exe",     LinkGen([id]{
            auto task_vm = PosixSyscall::find_task(id);
            auto proc = PosixSyscall::sys(task_vm.get());
            return proc ? proc->ps->exe_path : std::string();
        })},
    };
}

// /proc/[pid]/task 的内容生成：枚举线程组内所有 tid（含 leader），每个 [tid] 是个 DirGen，
// 内容 = 共享条目集（进程级数据）+ 线程视角的 comm/stat/status，不含 task 子目录
// （真实 Linux：只有 tgid 目录才有 task，线程目录不嵌套）。
// tg->threads 是 weak_ptr<vm> 快照；lock 成功即活线程。
static std::map<std::string, Gen> proc_pid_task_entries(pid_t pid) {
    std::map<std::string, Gen> tasks;
    auto task_vm = PosixSyscall::find_task(pid);
    if(!task_vm) return tasks;
    auto proc = PosixSyscall::sys(task_vm.get());
    if(!proc) return tasks;
    for(const auto& w : proc->tg->threads) {
        auto t = w.lock();
        if(!t) continue;
        auto tp = PosixSyscall::sys(t.get());
        if(!tp) continue;
        tasks.emplace(std::to_string(tp->pid), DirGen([tid = tp->pid] {
            auto entries = proc_task_common_entries(tid);
            entries.emplace("comm",   FileGen([tid]{ return gen_task_comm(tid); }));
            entries.emplace("stat",   FileGen([tid]{ return gen_task_stat(tid); }));
            entries.emplace("status", FileGen([tid]{ return gen_task_status(tid); }));
            return entries;
        }));
    }
    return tasks;
}

// /proc/[pid] 的内容：共享条目集 + 进程视角的 comm/stat/status + task 子目录（仅 tgid 有）。
static std::map<std::string, Gen> proc_pid_entries(pid_t pid) {
    auto entries = proc_task_common_entries(pid);
    entries.emplace("comm",   FileGen([pid]{ return gen_task_comm(pid); }));
    entries.emplace("stat",   FileGen([pid]{ return gen_task_stat(pid); }));
    entries.emplace("status", FileGen([pid]{ return gen_task_status(pid); }));
    // /proc/[pid]/task —— DirGen 延迟执行，仅在 getdents/lookup 时取 tg->threads 快照。
    entries.emplace("task", DirGen([pid]{ return proc_pid_task_entries(pid); }));
    return entries;
}

const static std::map<std::string, Gen> procs = {
    {"cpuinfo",    FileGen(gen_cpuinfo)},
    {"meminfo",    FileGen(gen_meminfo)},
    {"uptime",     FileGen(gen_uptime)},
    {"version",    FileGen(gen_version)},
    {"filesystems",FileGen(gen_filesystems)},
    {"loadavg",    FileGen(gen_loadavg)},
    {"mounts",     LinkGen([]{return "self/mounts";})},
};

static DirGen proc_root(PosixSyscall* self) {
    return DirGen([self] {
        std::map<std::string, Gen> entries = procs;
        for(uint64_t pid : PosixSyscall::list_pids()) {
            entries.emplace(std::to_string(pid), DirGen([pid] {
                return proc_pid_entries(pid);
            }));
        }
        entries.emplace("self", LinkGen([self]{
            return std::to_string(self->tg->tgid);
        }));
        entries.emplace("thread-self", LinkGen([self]{
            return std::to_string(self->tg->tgid) + "/task/" + std::to_string(self->pid);
        }));
        return entries;
    });
}

// lookup — 按 guest 绝对路径遍历 /proc 虚拟目录树，返回终点节点（FileGen/DirGen/LinkGen）。
// 跟踪符号链接，若链接 target 跳出 /proc 时，通过escape返回跳出路径（绝对路径）
static Gen lookup(PosixSyscall* self, const std::string& guest_abs, std::string& escape) {
    auto to_segs = [](const std::string& p) {
        std::vector<std::string> v;
        // 调用方保证路径是 /proc 开头。砍掉 "/proc" 前缀（substr(5)：/proc→""，/proc/x→"/x"），
        for(const auto& part : std::filesystem::path(p.substr(5)).relative_path()) {
            if(!part.empty()) v.push_back(part.string());
        }
        return v;
    };
    std::vector<std::string> segs = to_segs(guest_abs);
    Gen current = proc_root(self);
    size_t i = 0;
    std::string cur_path = "/proc";
    while(i < segs.size()) {
        if(auto link = current.as<LinkGen>()) {
            std::string target = (*link)();
            if(target.empty()) return {};   // 目标无效（如进程已退出）
            std::filesystem::path resolved = std::filesystem::path(target);
            if(resolved.is_relative()) {
                resolved = std::filesystem::path(cur_path).parent_path() / target;
            }
            resolved = resolved.lexically_normal();
            std::string rs = resolved.string();
            if(rs.empty() || rs.rfind("/proc", 0) != 0) {
                // 跳出 /proc：target + 剩余段（segs[i+1..]）拼成完整 host 目标路径，交给调用方。
                // 注意 segs[i] 是当前符号链接段本身，已被消费，剩余段从 i+1 起。
                std::filesystem::path full(rs);
                for(size_t k = i + 1; k < segs.size(); k++) full /= segs[k];
                escape = full.string();
                return {};
            }
            auto tsegs = to_segs(rs);
            // 用 target 的段替换当前符号链接段 segs[i]（符号链接段已消费，不能残留，
            // 否则会被当普通段重复匹配）。erase segs[i] 后插入 tsegs，i 指向 tsegs 首段。
            segs.erase(segs.begin() + i);
            segs.insert(segs.begin() + i, tsegs.begin(), tsegs.end());
            current = proc_root(self);
            cur_path = "/proc";
            continue;
        }
        if(current.as<NoneGen>()) return {};
        auto dir = current.as<DirGen>();
        if(!dir) return {};   // 非目录且还有剩余段：无法继续遍历
        const std::string& seg = segs[i];
        auto entries = (*dir)();
        auto it = entries.find(seg);
        if(it == entries.end()) return {};
        current = it->second;
        cur_path += "/" + seg;
        // 匹配到符号链接且后面还有剩余段：暂不推进 i，让下一轮循环顶部的 LinkGen 分支
        // 先跟随它（解析 target，可能跳出 /proc 触发 escape）。否则会丢失剩余段
        // （如 /proc/thread-self/cwd/busybox：cwd 是链接，后面还有 busybox）。
        if(current.as<LinkGen>() && i + 1 < segs.size()) continue;
        i++;
    }
    return current;   // FileGen / DirGen / LinkGen（末段为符号链接时，未跟随）
}

// 把符号链接 target 按 POSIX 语义解析成绝对 guest 路径：相对 target 相对 link_path 的
// 父目录，用 std::filesystem::lexically_normal 规范化（消解 . 和 ..）。
// 注意 link_path 先 strip 尾斜杠——符号链接本质是文件（/proc/self 是链接，不是目录），
// 但 path("/proc/self/").parent_path() 会得 "/proc/self"（把尾斜杠当目录语义），错。
// readlink 不用此函数（返回原始 target，与 readlink(2) 一致）。
static std::string resolve_symlink(const std::string& link_path, const std::string& target) {
    if(target.empty()) return {};
    std::filesystem::path resolved = std::filesystem::path(target);
    if(resolved.is_relative()) {
        std::string base = link_path;
        while(base.size() > 1 && base.back() == '/') base.pop_back();  // 去尾斜杠
        resolved = std::filesystem::path(base).parent_path() / target;
    }
    return resolved.lexically_normal().string();
}

// open：命中 lookup 即构造 ProcFile/ProcDir（快照式）。/proc 下查不到节点 → ENOENT（设备封闭）。
std::shared_ptr<Fd> ProcPath::open(int flags, mode_t mode) {
    std::string escape;
    auto node = lookup(self, guest, escape);
    // 中间段符号链接跳出 /proc（如 /proc/1/root/bin）→ escape 是 target+剩余段的完整 host 路径，
    // 经 ResolvePath 重解析（套 chroot + 按前缀分发）走完剩余部分。
    if(!escape.empty()) {
        return ResolvePath(self, escape)->open(flags, mode);
    }
    if(node.as<NoneGen>()) {
        errno = ENOENT;   // /proc 下不存在的路径
        return nullptr;
    }
    // /proc 整棵只读：任何写/截断访问一律 EROFS（与 Linux 只读 procfs 挂载一致）。
    if(flags & (O_WRONLY | O_RDWR | O_TRUNC | O_APPEND)) {
        errno = EROFS;
        return nullptr;
    }
    // 末段符号链接 follow（O_NOFOLLOW 由 do_openat 提前判 ELOOP，能走到这说明要 follow）。
    // target 经 resolve_symlink 规范成绝对 guest 路径后，经 ResolvePath 重解析（套 chroot +
    // 按前缀分发：/proc→procfs、/dev→DevFd、其余→HostFd），其 open 返回真实 fd。
    if(auto link = node.as<LinkGen>()) {
        std::string target = resolve_symlink(guest, (*link)());
        if(target.empty()) { errno = ENOENT; return nullptr; }
        return ResolvePath(self, target)->open(flags, mode);
    }
    if(auto dir = node.as<DirGen>()) {
        return std::make_shared<ProcDir>(guest, *dir);
    }
    if(auto file = node.as<FileGen>()) {
        return std::make_shared<ProcFile>(guest, *file);
    }
    errno = EINVAL;
    return nullptr;
}

// follow：execve/execveat 用——返回 follow 后的真实可加载文件路径。
// 中间段符号链接跳出 /proc → 直接返回 escape（完整 host 路径）；
// 末段符号链接 → 返回 resolve_symlink 后的绝对 target；其余返回 guest 自身。
std::string ProcPath::follow() {
    std::string escape;
    auto node = lookup(self, guest, escape);
    if(!escape.empty()) return escape;
    if(auto link = node.as<LinkGen>()) {
        return resolve_symlink(guest, (*link)());
    }
    return guest;
}

ssize_t ProcPath::readlink(char* buf, size_t bufsiz) {
    std::string escape;
    auto node = lookup(self, guest, escape);
    // 中间段符号链接跳出 /proc（如 /proc/self/root/lib：root→/，再读 /lib 链接）→ escape 是
    // 完整 host 路径，交给 ResolvePath 的 readlink 读真实符号链接（套 chroot + 按前缀分发）。
    if(!escape.empty()) {
        return ResolvePath(self, escape)->readlink(buf, bufsiz);
    }
    if(node.as<NoneGen>()) {
        return -ENOENT;
    }
    if(!S_ISLNK(node.mode())) {
        return -EINVAL;
    }
    // readlink(2) 返回原始 target（不做路径规范化，与内核一致）。
    std::string target = (*node.as<LinkGen>())();
    if(target.empty()) return -ENOENT;  // 目标进程已退出或 exe_path 未设
    size_t n = target.size() < bufsiz ? target.size() : bufsiz;
    memcpy(buf, target.data(), n);
    return (ssize_t)n;
}

int ProcPath::statx(struct statx* stx, unsigned int /*mask*/, int flags) {
    std::string escape;
    auto node = lookup(self, guest, escape);
    // 中间段符号链接跳出 /proc（如 /proc/1/root/bin）：escape 是完整 host 路径，交给
    // ResolvePath 的 statx（套 chroot + 按前缀分发）走完剩余部分。
    if(!escape.empty()) {
        return ResolvePath(self, escape)->statx(stx, STATX_BASIC_STATS, flags);
    }
    if(node.as<NoneGen>()) {
        return -ENOENT;
    }
    if(!(flags & AT_SYMLINK_NOFOLLOW)) {
        if(auto link = node.as<LinkGen>()) {
            std::string target = resolve_symlink(guest, (*link)());
            if(target.empty()) return -ENOENT;
            if(target.rfind("/proc", 0) == 0) {
                std::string _;
                node = lookup(self, target, _);
                if(node.as<NoneGen>()) return -ENOENT;
            } else {
                return ResolvePath(self, target)->statx(stx, STATX_BASIC_STATS, flags);
            }
        }
    }
    memset(stx, 0, sizeof(*stx));
    stx->stx_mask = STATX_BASIC_STATS;
    stx->stx_blksize = 4096;
    stx->stx_nlink = 1;
    stx->stx_uid = 0;
    stx->stx_gid = 0;
    if(node.as<FileGen>()) {
        stx->stx_mode = S_IFREG | 0444;
    } else if(node.as<DirGen>()) {
        stx->stx_mode = S_IFDIR | 0555;
    } else if(node.as<LinkGen>()) {
        stx->stx_mode = S_IFLNK | 0777;
    }
    return 0;
}

// access：查虚拟节点存在性（存在即允许，mode 仅测 F_OK/R_OK——proc 文件皆可读）。
int ProcPath::access(int mode, int flags) {
    std::string escape;
    auto node = lookup(self, guest, escape);
    // 中间段符号链接跳出 /proc → escape 是完整 host 路径，交给 ResolvePath 的 access
    // （套 chroot + 按前缀分发）测真实文件可访问性。
    if(!escape.empty()) {
        return ResolvePath(self, escape)->access(mode, flags);
    }
    return node.as<NoneGen>() ? -ENOENT : 0;
}
