//
// procfs.cpp — /proc 虚拟文件系统模拟
//
// bpfvm 是 host-fd 直通模型：HostFd 包着真实 host fd，read/write/getdents/statx
// 直接转发 host libc。/proc 没有 host 文件可 open，故引入一条并行的虚拟文件通道：
// ProcFd（fd=-1，持 ProcNode + 快照 ProcInstance），read/lseek/getdents 经 Fd 多态分流。
//
// 全部 procfs 逻辑（procfs_lookup 路径分发、procfs_readlink 符号链接拦截、gen_pid_*
// 内容生成）都是自由函数，不挂在 PosixSyscall 上；经 PosixSyscall 的 public 进程标识
// 字段（pid/ppid/tg/pgrp/session/comm_/ps）与 *_of 静态转发（options_of/maps_of/
// flags_of）+ find_task/sys/list_pids 读 vm/进程内部。
//
// /proc 基于 guest 绝对路径匹配（仿 /dev/tty、/dev/ptmx 等特殊设备），不拼 chroot
// root 前缀。[pid] 用 guest 的 pid/tgid，完全按 guest 语义生成 —— 这是"模拟"而非
// "直通 host /proc"的核心。
//
// 内容策略：快照式。open 时调一次 ProcNode::generate() 生成全量内容存进
// ProcInstance::data，read 按 pos 切片。与 Linux 一致（进程改 argv 后 /proc 仍反映旧值）。
//

#include "posix_internal.h"

#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <sstream>

// =====================================================================
// ProcInstance — 一次打开的实例（pos 独立；dup/fork 各得独立 instance）
// =====================================================================

ssize_t ProcInstance::read(void* buf, size_t count) {
    if(pos < 0) return -EINVAL;
    if((size_t)pos >= data.size()) return 0;  // EOF
    size_t avail = data.size() - (size_t)pos;
    size_t n = count < avail ? count : avail;
    memcpy(buf, data.data() + pos, n);
    pos += (off_t)n;
    return (ssize_t)n;
}

off_t ProcInstance::lseek(off_t off, int whence) {
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

// =====================================================================
// make_comm — basename，截断到 15 字节（Linux TASK_COMM_LEN-1）
// =====================================================================

std::string make_comm(const std::string& path) {
    auto slash = path.find_last_of('/');
    std::string base = (slash != std::string::npos) ? path.substr(slash + 1) : path;
    if(base.size() > 15) base.resize(15);  // TASK_COMM_LEN = 16（含 NUL）
    return base;
}

// =====================================================================
// ProcNode 默认实现
// =====================================================================

void ProcNode::statx(struct statx& stx, PosixSyscall* self) {
    memset(&stx, 0, sizeof(stx));
    stx.stx_mask = STATX_BASIC_STATS;
    stx.stx_blksize = 4096;
    stx.stx_nlink = 1;
    stx.stx_uid = 0;
    stx.stx_gid = 0;
    if(is_dir()) {
        stx.stx_mode = S_IFDIR | 0555;
    } else {
        stx.stx_mode = S_IFREG | 0444;
        stx.stx_size = (uint64_t)generate(self).size();
    }
}

// =====================================================================
// ProcNode 子类
// =====================================================================

// 普通文件节点：构造时给定生成函数。
struct ProcFile : ProcNode {
    using Gen = std::function<std::string(PosixSyscall*)>;
    Gen gen;
    explicit ProcFile(Gen g) : gen(std::move(g)) {}
    bool is_dir() const override { return false; }
    std::string generate(PosixSyscall* self) override { return gen(self); }
};

// 目录节点：构造时给定列举函数（返回子项 name→d_type）。
struct ProcDir : ProcNode {
    using Ls = std::function<std::vector<std::pair<std::string, unsigned char>>(PosixSyscall*)>;
    Ls ls;
    explicit ProcDir(Ls l) : ls(std::move(l)) {}
    bool is_dir() const override { return true; }
    std::vector<std::pair<std::string, unsigned char>> list(PosixSyscall* self) override { return ls(self); }
};

// 符号链接节点：构造时给定目标生成函数（readlink/statx 用）。目标为空串表示目标进程
// 已退出等无效情形（readlinkat 据此返 ENOENT，与 Linux 一致）。把符号链接也做成
// ProcNode 子类，使 procfs_lookup 成为唯一的路径分发入口（readlinkat/statx 各调一次，
// 经 readlink()/statx() 虚方法下沉，不再需要平行的 procfs_readlink）。
struct ProcLink : ProcNode {
    using Tgt = std::function<std::string(PosixSyscall*)>;
    Tgt tgt;
    explicit ProcLink(Tgt t) : tgt(std::move(t)) {}
    bool is_dir() const override { return false; }
    bool is_link() const override { return true; }
    bool readlink(PosixSyscall* self, std::string& target) override { target = tgt(self); return true; }
    void statx(struct statx& stx, PosixSyscall* self) override {
        memset(&stx, 0, sizeof(stx));
        stx.stx_mask = STATX_BASIC_STATS;
        stx.stx_blksize = 4096;
        stx.stx_nlink = 1;
        stx.stx_uid = 0;
        stx.stx_gid = 0;
        stx.stx_mode = S_IFLNK | 0777;
        stx.stx_size = (uint64_t)tgt(self).size();
    }
};

// =====================================================================
// 全局静态节点：/proc 顶层非 [pid] 文件
// =====================================================================

static std::string gen_cpuinfo(PosixSyscall*) {
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

static std::string gen_meminfo(PosixSyscall*) {
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

static std::string gen_uptime(PosixSyscall*) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    char buf[64];
    snprintf(buf, sizeof(buf), "%.2f 0.00\n", (double)ts.tv_sec + ts.tv_nsec / 1e9);
    return buf;
}

static std::string gen_version(PosixSyscall*) {
    return "Linux version 6.12.0 (bpfvm) (clang)\n";
}

static std::string gen_filesystems(PosixSyscall*) {
    return "nodev\tproc\nnodev\ttmpfs\nnodev\tdevtmpfs\nnodev\tsysfs\n";
}

static std::string gen_loadavg(PosixSyscall*) {
    return "0.00 0.00 0.00 1/1 1\n";
}

static std::string gen_mounts(PosixSyscall*) {
    return "proc / proc rw,relatime 0 0\ntmpfs /tmp tmpfs rw,relatime 0 0\n";
}

// =====================================================================
// /proc/[pid]/* 内容生成器（自由函数；经 PosixSyscall 的 public 字段与 *_of 转发读内部）
// =====================================================================

namespace {

char proc_state(vm* task) {
    if(!task) return 'R';
    uint32_t f = PosixSyscall::flags_of(task);
    if(f & vm::VM_EXITED) return 'Z';
    if(f & vm::VM_STOPPED) return 'T';
    if(f & vm::VM_BLOCKED) return 'S';
    return 'R';
}

std::string gen_pid_stat(uint64_t pid) {
    auto task_vm = PosixSyscall::find_task(pid);
    auto proc = PosixSyscall::sys(task_vm.get());
    uint64_t ppid = proc->tg->ppid.load();
    uint64_t pgid = proc->pgrp->pgid;
    uint64_t sid = proc->session->sid;
    const std::string& comm = proc->comm_;
    char state = task_vm ? proc_state(task_vm.get()) : 'Z';
    std::string out;
    out += std::to_string(pid) + " (" + comm + ") " + state + " ";
    out += std::to_string(ppid) + " " + std::to_string(pgid) + " " + std::to_string(sid) + " ";
    out += "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 "; // tty_nr..num_threads（近似）
    out += "0 0 0 0 ";                        // itrealvalue/starttime/vsize/rss
    out += "0 0 0 0 0 ";                      // rsslim..kstkesp
    out += "0 0 0 0 0 ";                      // kstkeip..sigcatch
    out += "0 0 0 0 0 0 0 ";                  // wcan..delayacct
    out += "0 0\n";                           // guest_time/cguest_time
    return out;
}

std::string gen_pid_status(uint64_t pid) {
    auto task_vm = PosixSyscall::find_task(pid);
    auto proc = PosixSyscall::sys(task_vm.get());
    char state = task_vm ? proc_state(task_vm.get()) : 'Z';
    std::string out;
    out += "Name:\t" + proc->comm_ + "\n";
    out += "Umask:\t" + std::to_string(proc->ps->umask) + "\n";
    out += "State:\t" + std::string(1, state) + "\n";
    out += "Tgid:\t" + std::to_string(proc->tg->tgid) + "\n";
    out += "Ngid:\t0\n";
    out += "Pid:\t" + std::to_string(pid) + "\n";
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

std::string gen_pid_cmdline(uint64_t pid) {
    auto task_vm = PosixSyscall::find_task(pid);
    if(!task_vm) return {};
    const auto& argv = PosixSyscall::options_of(task_vm.get()).argv;
    std::string out;
    for(const auto& a : argv) { out += a; out += '\0'; }
    return out;
}

std::string gen_pid_environ(uint64_t pid) {
    auto task_vm = PosixSyscall::find_task(pid);
    if(!task_vm) return {};
    const auto& envp = PosixSyscall::options_of(task_vm.get()).envp;
    std::string out;
    for(const auto& e : envp) { out += e; out += '\0'; }
    return out;
}

std::string gen_pid_comm(uint64_t pid) {
    auto task_vm = PosixSyscall::find_task(pid);
    auto proc = PosixSyscall::sys(task_vm.get());
    return proc ? (proc->comm_ + "\n") : std::string();
}

std::string gen_pid_maps(uint64_t pid) {
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

// =====================================================================
// 辅助：判断纯数字段（[pid]）
// =====================================================================

static bool is_pid_segment(const std::string& s) {
    if(s.empty()) return false;
    for(char c : s) if(!isdigit((unsigned char)c)) return false;
    return true;
}

static std::vector<std::string> split_proc_path(const std::string& guest_abs) {
    // /proc → []；/proc/cpuinfo → ["cpuinfo"]；/proc/1/stat → ["1","stat"]
    std::vector<std::string> segs;
    std::string rest = (guest_abs == "/proc") ? "" : guest_abs.substr(6);
    std::stringstream ss(rest);
    std::string item;
    while(std::getline(ss, item, '/')) {
        if(!item.empty()) segs.push_back(item);
    }
    return segs;
}

// 展开 /proc/self → /proc/<tgid>，/proc/thread-self → /proc/<tgid>/task/<tid>。
// 返回展开后的规范路径（若首段不是 self/thread-self 则原样返回）。
// 自由函数：经 self 读 public 字段（tg->tgid / pid）。
std::string normalize_proc_path(const std::string& guest_abs, PosixSyscall* self) {
    auto segs = split_proc_path(guest_abs);
    if(segs.empty()) return guest_abs;
    if(segs[0] == "self") {
        std::string out = "/proc/" + std::to_string(self->tg->tgid);
        for(size_t i = 1; i < segs.size(); i++) { out += "/"; out += segs[i]; }
        return out;
    }
    if(segs[0] == "thread-self") {
        std::string out = "/proc/" + std::to_string(self->tg->tgid)
                        + "/task/" + std::to_string(self->pid);
        for(size_t i = 1; i < segs.size(); i++) { out += "/"; out += segs[i]; }
        return out;
    }
    return guest_abs;
}

} // anonymous namespace

// =====================================================================
// lookup — 内部路径解析：基于 guest 绝对路径匹配分发到 ProcNode 子类（文件/目录/符号链接），
// 不拼 chroot 前缀（仿 /dev/*）。不命中（非 /proc 路径或 /proc 下不存在的路径）返回 nullptr。
// 对外不暴露：procfs 的三个语义操作（procfs_open/readlink/statx）经此分发后下沉到节点虚方法。
// =====================================================================

static std::shared_ptr<ProcNode> lookup(const std::string& guest_abs_, PosixSyscall* self) {
    if(guest_abs_ != "/proc" && guest_abs_.rfind("/proc/", 0) != 0) {
        return nullptr;
    }
    // 先展开 self/thread-self，使后续按数字 pid 统一处理。
    std::string guest_abs = normalize_proc_path(guest_abs_, self);
    auto segs = split_proc_path(guest_abs);

    // /proc 根目录
    if(segs.empty()) {
        return std::make_shared<ProcDir>([](PosixSyscall*) {
            std::vector<std::pair<std::string, unsigned char>> entries = {
                {"self", DT_LNK}, {"thread-self", DT_LNK},
                {"cpuinfo", DT_REG}, {"meminfo", DT_REG}, {"uptime", DT_REG},
                {"version", DT_REG}, {"filesystems", DT_REG}, {"loadavg", DT_REG},
                {"mounts", DT_LNK},
            };
            for(uint64_t pid : PosixSyscall::list_pids()) {
                entries.push_back({std::to_string(pid), DT_DIR});
            }
            return entries;
        });
    }

    const std::string& first = segs[0];

    // 注：/proc/self、/proc/thread-self 是 magic symlink——stat/lstat/open 都解析到
    // /proc/<tgid>（目录），只有 readlink 返回 magic 目标 "<tgid>"。故它们不在此返回
    // ProcLink（那会让 stat 报 S_IFLNK），而是在 normalize_proc_path 阶段已被改写成
    // /proc/<tgid>，落到下面的 [pid] 分支；readlink 目标由 readlinkat 路径单独处理。

    // [pid] 子树：解析+校验 pid 一次，整个 /proc/<pid>/... 层级在此块内分发，
    // 不再落到函数尾部的二次解析（旧实现那里未再 find_task 校验）。
    if(is_pid_segment(first)) {
        uint64_t pid_num = strtoull(first.c_str(), nullptr, 10);
        if(!PosixSyscall::find_task(pid_num)) return nullptr;  // pid 不存在
        if(segs.size() == 1) {
            // /proc/<pid> 目录本身：列出该进程的子项（与 Linux /proc/[pid] 一致）。
            return std::make_shared<ProcDir>([](PosixSyscall*) {
                return std::vector<std::pair<std::string, unsigned char>>{
                    {"exe", DT_LNK}, {"cwd", DT_LNK}, {"root", DT_LNK},
                    {"fd", DT_DIR}, {"task", DT_DIR},
                    {"stat", DT_REG}, {"status", DT_REG}, {"cmdline", DT_REG},
                    {"environ", DT_REG}, {"comm", DT_REG}, {"maps", DT_REG},
                    {"statm", DT_REG},
                };
            });
        }
        // segs.size() >= 2：/proc/<pid>/<second>
        const std::string& second = segs[1];

        // 真符号链接（exe/cwd/root）：readlink 目标由节点持有，statx 报 S_IFLNK。
        // 目标为空串 = 进程已退出/exe_path 未设（readlinkat 据此返 ENOENT）。
        if(second == "exe") {
            return std::make_shared<ProcLink>([pid_num](PosixSyscall*) -> std::string {
                auto proc = PosixSyscall::sys(PosixSyscall::find_task(pid_num).get());
                return proc ? proc->ps->exe_path : std::string();
            });
        }
        if(second == "cwd") {
            return std::make_shared<ProcLink>([pid_num](PosixSyscall*) -> std::string {
                auto proc = PosixSyscall::sys(PosixSyscall::find_task(pid_num).get());
                return proc ? proc->ps->cwd : std::string();
            });
        }
        if(second == "root") {
            return std::make_shared<ProcLink>([](PosixSyscall*) { return std::string("/"); });
        }

        // /proc/<pid>/fd/ 目录
        if(second == "fd") {
            if(segs.size() == 2) {
                // 列举该 pid 的打开 fd。ps->fds 是目标进程的字段，需通过 sys() 访问。
                // 当前仅能精确列举 self（caller == target）。近似：返回空。
                // TODO: 给 PosixSyscall 加 fd 列举接口后精确化。
                return std::make_shared<ProcDir>([pid_num](PosixSyscall*) {
                    return std::vector<std::pair<std::string, unsigned char>>{};
                });
            }
            // /proc/<pid>/fd/<n>：近似返回 anon_inode（精确化需 fd 列举接口）
            return std::make_shared<ProcLink>([](PosixSyscall*) { return std::string("anon_inode:[fd]"); });
        }

        // /proc/<pid>/task 目录
        if(second == "task") {
            if(segs.size() == 2) {
                return std::make_shared<ProcDir>([pid_num](PosixSyscall*) {
                    // 近似：仅列 leader tid（pid 在 lookup 入口已校验存在）。精确实现需遍历 tg->threads。
                    return std::vector<std::pair<std::string, unsigned char>>{
                        {std::to_string(pid_num), DT_DIR}};
                });
            }
            return nullptr;  // /proc/<pid>/task/<tid>/... 待扩展
        }

        // /proc/<pid>/<文件>
        if(segs.size() == 2) {
            if(second == "stat")     return std::make_shared<ProcFile>([pid_num](PosixSyscall*) { return gen_pid_stat(pid_num); });
            if(second == "status")   return std::make_shared<ProcFile>([pid_num](PosixSyscall*) { return gen_pid_status(pid_num); });
            if(second == "cmdline")  return std::make_shared<ProcFile>([pid_num](PosixSyscall*) { return gen_pid_cmdline(pid_num); });
            if(second == "environ")  return std::make_shared<ProcFile>([pid_num](PosixSyscall*) { return gen_pid_environ(pid_num); });
            if(second == "comm")     return std::make_shared<ProcFile>([pid_num](PosixSyscall*) { return gen_pid_comm(pid_num); });
            if(second == "maps")     return std::make_shared<ProcFile>([pid_num](PosixSyscall*) { return gen_pid_maps(pid_num); });
            if(second == "statm")    return std::make_shared<ProcFile>([](PosixSyscall*) { return std::string("0 0 0 0 0 0 0\n"); });
            return nullptr;
        }

        return nullptr;
    }

    // 非 [pid] 的顶层具名文件（/proc/cpuinfo 等）。深层路径（非 [pid] 却有多段）不存在。
    if(segs.size() != 1) return nullptr;
    if(first == "cpuinfo")     return std::make_shared<ProcFile>(gen_cpuinfo);
    if(first == "meminfo")     return std::make_shared<ProcFile>(gen_meminfo);
    if(first == "uptime")      return std::make_shared<ProcFile>(gen_uptime);
    if(first == "version")     return std::make_shared<ProcFile>(gen_version);
    if(first == "filesystems") return std::make_shared<ProcFile>(gen_filesystems);
    if(first == "loadavg")     return std::make_shared<ProcFile>(gen_loadavg);
    if(first == "mounts")      return std::make_shared<ProcFile>(gen_mounts);
    return nullptr;
}

// =====================================================================
// magic_readlink — 仅处理 3 个 magic symlink 的 readlink 目标（内部）
// =====================================================================
// /proc/self、/proc/thread-self、/proc/mounts 是 Linux 的 magic symlink：stat/lstat/open
// 都解析到它们指向的目录/文件（self/thread-self → /proc/<tgid> 目录；mounts → 文件），
// 只有 readlink 报告 magic 目标（self → "<tgid>"，thread-self → "<tgid>/task/<tid>"，
// mounts → "self/mounts"）。故它们在 lookup 里被 normalize_proc_path 改写、落到
// [pid]/具名文件分支（stat/open 走那条），而 readlink 目标单独由本函数给出。
// 其余真符号链接（[pid]/exe|cwd|root|fd/N）已是 ProcLink 节点，readlink 走 node->readlink()。
static bool magic_readlink(const std::string& guest_abs, PosixSyscall* self, std::string& link_target) {
    if(guest_abs == "/proc/self") {
        link_target = std::to_string(self->tg->tgid);
        return true;
    }
    if(guest_abs == "/proc/thread-self") {
        link_target = std::to_string(self->tg->tgid) + "/task/" + std::to_string(self->pid);
        return true;
    }
    if(guest_abs == "/proc/mounts") {
        link_target = "self/mounts";
        return true;
    }
    return false;
}

// =====================================================================
// ProcFd::open — /proc 文件/目录的静态工厂（与 DevFd::open / HostFd::open 对称）。
// 实现放此文件：内部复用本文件 file-static 的 lookup，避免把路径分发泄露到 fs.cpp。
// 调用方（ProcPath::open，/proc 前缀已路由进来）故 /proc 下查不到节点 = ENOENT（不 fallback）。
// 命中 → 返回 ProcFd（快照式）；失败返 nullptr 且 errno 已设（ENOENT/EROFS）。
// =====================================================================
std::shared_ptr<Fd> ProcFd::open(const std::string& guest_abs, int flags, PosixSyscall* self) {
    auto node = lookup(guest_abs, self);
    if(!node) {
        errno = ENOENT;   // /proc 下不存在的路径
        return nullptr;
    }
    if(!node->is_dir() && (flags & (O_WRONLY | O_RDWR | O_TRUNC | O_APPEND))) {
        errno = EROFS;  // /proc 只读
        return nullptr;
    }
    auto inst = std::make_shared<ProcInstance>();
    if(!node->is_dir()) {
        inst->data = node->generate(self);  // 快照（目录不预生成 data）
    }
    return std::make_shared<ProcFd>(node, inst, guest_abs);
}

// =====================================================================
// ProcPath —— /proc 路径的虚方法实现（复用本文件 file-static 的 lookup/magic_readlink）。
// 修改类（unlink/mkdir/symlink/chmod/truncate/utimens/link/rename）继承 Path 基类的 -EROFS，
// 与原 PathStub 时代语义一致（/proc 只读 procfs）。
// =====================================================================

// open：命中 lookup 即构造 ProcFd（快照式）。/proc 下查不到节点 → ENOENT（设备封闭）。
std::shared_ptr<Fd> ProcPath::open(int flags, mode_t /*mode*/) {
    return ProcFd::open(guest, flags, self);
}

// readlink：magic symlink 必须先查（它们在 lookup 里被 normalize 成目录/文件，readlink 目标
//   只能由 magic_readlink 给出）。真符号链接（ProcLink）随后经 node->readlink() 取。
// 目标在内部仍用 string 生成完整内容，再按 bufsiz 截断 memcpy 进 buf（readlink(2) 语义：
// 不含 NUL，返回写入字节数）。空目标 = 进程已退出 → ENOENT。
ssize_t ProcPath::readlink(char* buf, size_t bufsiz) {
    std::string target;
    if(!magic_readlink(guest, self, target)) {
        if(auto node = lookup(guest, self)) {
            if(!node->readlink(self, target)) {
                return -EINVAL;  // 命中 /proc 节点但非符号链接（文件/目录）
            }
        } else {
            return -ENOENT;      // /proc 下不存在的路径（封闭，不 fallback 到 host）
        }
    }
    if(target.empty()) return -ENOENT;  // 目标进程已退出或 exe_path 未设
    size_t n = target.size() < bufsiz ? target.size() : bufsiz;
    memcpy(buf, target.data(), n);
    return (ssize_t)n;
}

// statx：lookup 命中即 node->statx 填充（真符号链接 ProcLink 自动报 S_IFLNK）。
int ProcPath::statx(struct statx& stx, unsigned int /*mask*/, int /*flags*/) {
    if(auto node = lookup(guest, self)) {
        node->statx(stx, self);
        return 0;
    }
    return -ENOENT;  // /proc 下不存在（封闭）
}

// access：查虚拟节点存在性（存在即允许，mode 仅测 F_OK/R_OK——proc 文件皆可读）。
int ProcPath::access(int /*mode*/, int /*flags*/) {
    return lookup(guest, self) ? 0 : -ENOENT;
}
