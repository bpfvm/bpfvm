#include "posix_syscall.h"
#include "include/bpf_call.h"
namespace bpf{
    #define BPF_NO_SYSCALL
#ifdef __unused
    #undef __unused
#endif
    #include "include/signal.h"
    #include "include/sys/stat.h"
    #include "include/termios.h"
    #include "include/sys/uio.h"
}

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <memory>
#include <chrono>
#include <time.h>
#include <string.h>
#include <cstring>
#include <unistd.h>
#include <filesystem>
#include <signal.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sched.h>
#include <linux/futex.h>
#include <algorithm>
#include <vector>

#undef sa_handler
#undef sa_sigaction

MpscQueue::MpscQueue() {
    for(size_t i = 0; i < k_capacity; ++i) {
        slots[i].seq.store(i, std::memory_order_relaxed);
    }
}

bool MpscQueue::try_push(int value) {
    uint64_t pos = tail.load(std::memory_order_relaxed);
    while(true) {
        slot& s = slots[pos & k_mask];
        uint64_t seq = s.seq.load(std::memory_order_acquire);
        intptr_t dif = (intptr_t)seq - (intptr_t)pos;
        if(dif == 0) {
            if(tail.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                s.value = value;
                s.seq.store(pos + 1, std::memory_order_release);
                return true;
            }
        } else if(dif < 0) {
            return false;
        } else {
            pos = tail.load(std::memory_order_relaxed);
        }
    }
}

bool MpscQueue::try_pop(int& value) {
    uint64_t pos = head.load(std::memory_order_relaxed);
    while(true) {
        slot& s = slots[pos & k_mask];
        uint64_t seq = s.seq.load(std::memory_order_acquire);
        intptr_t dif = (intptr_t)seq - (intptr_t)(pos + 1);
        if(dif == 0) {
            if(head.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                value = s.value;
                s.seq.store(pos + k_capacity, std::memory_order_release);
                return true;
            }
        } else if(dif < 0) {
            return false;
        } else {
            pos = head.load(std::memory_order_relaxed);
        }
    }
}

std::atomic<uint64_t> PosixSyscall::next_pid{1};
std::unordered_map<uint64_t, std::shared_ptr<vm>> PosixSyscall::pid_map{};
std::mutex PosixSyscall::pid_map_mutex;

static inline int32_t arg_s32(uint64_t v) {
    return static_cast<int32_t>(v);
}

static inline uint32_t arg_u32(uint64_t v) {
    return static_cast<uint32_t>(v);
}

static inline size_t arg_size(uint64_t v) {
    return static_cast<size_t>(v);
}

// futex 等待桶：每个 (地址空间, guest addr) 一个 bucket，持有等待者 vm* 列表。
// 地址空间用 ThreadGroup 裸指针标识（CLONE_VM 线程共享 tg；fork 后不同 tg 即不同地址空间）。
//
// 列表里的 vm* 必然存活：拥有它的线程正阻塞在 futex_wait 内，未跑 fini，vm 不会析构；
// 等待者返回前必先把自己摘掉（被 unblock 路径由 waker 摘，kill/超时/信号路径自己摘），故列表
// 不会残留死 vm。这也顺带让 bucket 在 waiters 空时即 erase，避免表泄漏与 tg 指针悬垂。
struct FutexBucket {
    std::vector<vm*> waiters;
};
struct FutexKeyHash {
    size_t operator()(const std::pair<ThreadGroup*, uint64_t>& p) const {
        return reinterpret_cast<size_t>(p.first) * 31 + (size_t)(p.second >> 2);
    }
};
static std::mutex g_futex_mutex;
static std::unordered_map<std::pair<ThreadGroup*, uint64_t>, FutexBucket, FutexKeyHash> g_futex_table;

// 从 bucket 摘除一个 vm（若存在），bucket 空则 erase。调用方持 g_futex_mutex。
static void futex_detach(ThreadGroup* tg, uint64_t addr, vm* v) {
    auto it = g_futex_table.find({tg, addr});
    if(it == g_futex_table.end()) return;
    auto& w = it->second.waiters;
    auto pos = std::find(w.begin(), w.end(), v);
    if(pos != w.end()) {
        w.erase(pos);
    }
    if(w.empty()) g_futex_table.erase(it);
}


PosixSyscall::PosixSyscall() {
    pid = next_pid.fetch_add(1);
    tg = std::make_shared<ThreadGroup>(pid);
    ps->fds.emplace(0, std::make_shared<fd_handle>(dup(STDIN_FILENO)));
    ps->fds.emplace(1, std::make_shared<fd_handle>(dup(STDOUT_FILENO)));
    ps->fds.emplace(2, std::make_shared<fd_handle>(dup(STDERR_FILENO)));

    char buf[PATH_MAX];
    if(::getcwd(buf, sizeof(buf)) != nullptr) {
        ps->cwd = buf;
    } else {
        ps->cwd = "/";
    }
    // pid 1 自成会话 leader + 进程组 leader。
    session = std::make_shared<Session>(pid);
    pgrp = std::make_shared<ProcessGroup>(pid, session);
}

PosixSyscall::PosixSyscall(uint64_t ppid, const std::unordered_map<int, std::shared_ptr<fd_handle>>& opened, std::string cwd_,
                           std::shared_ptr<ProcessGroup> pgrp_, std::shared_ptr<Session> session_)
    : pgrp(std::move(pgrp_)), session(std::move(session_)) {
    pid = next_pid.fetch_add(1);
    tg = std::make_shared<ThreadGroup>(pid);
    this->ppid = ppid;
    ps->fds = opened;
    ps->cwd = cwd_;
}

void PosixSyscall::init(const std::shared_ptr<vm>& v){
    tid = pthread_self();
    // 只有 pid 1（主进程）在此注册自身：它没有父 task 替它 push 到 threads。
    // 其余 task（fork / clone 产生的子）由创建方在 do_fork / do_clone 持 tg->mtx 注册，
    // 避免子线程 host 尚未跑到 init() 时 leader 就 exit_group 漏杀它。
    if(pid == 1) {
        std::lock_guard<std::mutex> lock(tg->mtx);
        tg->threads.push_back(v);
    }
    std::lock_guard<std::mutex> lock(pid_map_mutex);
    //这里只对1号进程添加，其他进程由fork添加，因为推迟到这里就太晚了
    if(pid == 1) pid_map[pid] = v;
}

void PosixSyscall::fini(const std::shared_ptr<vm>& v) {
    // clear-child-tid：清零 *tid_address_ 并 futex_wake（musl pthread 退出依赖此机制）。
    // tid_address_ 是 CLONE_CHILD_CLEARTID 设的，指向 musl 的 __thread_list_lock（int），
    // musl __pthread_exit 不调 __tl_unlock，依赖此机制释放锁。
    auto clear_child_tid = [&]() {
        if(tid_address_ == 0) return;
        auto* ctid = static_cast<int*>(v->mmu_w(tid_address_, sizeof(int)));
        if(!ctid) return;
        // 持 g_futex_mutex 清零 + wake，避免与 futex_wait 的 *p 检查产生 lost wakeup：
        // futex_wait 在持锁时检查 *p==val 并注册进 waiters；这里持锁清零后摘一个等待者
        // 并 wakeup()，确保等待者要么看到 *p 已变（EAGAIN 返回），要么被 wake 唤醒。
        std::lock_guard<std::mutex> flock(g_futex_mutex);
        *ctid = 0;
        auto it = g_futex_table.find({tg.get(), tid_address_});
        if(it == g_futex_table.end() || it->second.waiters.empty()) {
            return;
        }
        vm* w = it->second.waiters.back();
        it->second.waiters.pop_back();
        if(it->second.waiters.empty()) g_futex_table.erase(it);
        w->unblock();
    };
    clear_child_tid();

    // 线程组生命周期：减 live_threads，判定是否本组最后一个退出的线程。
    bool last = (tg->live_threads.fetch_sub(1, std::memory_order_acq_rel) == 1);

    // 本线程的信号上下文复位（与 last / pid_map 无关）。
    signal_depth(v.get()) = 0;

    // pid 1（init）不参与线程组清理，提前返回。
    if(pid == 1) {
        return;
    }

    // 释放本线程的地址空间引用：僵尸不再持地址空间。
    // 必须在 clear-child-tid（用 mmu_w 访问 maps）之后；本 vm 此后不再访存。
    maps_ptr(v.get()) = std::make_shared<std::list<memmap>>();

    // 非 leader 线程：从 pid_map 移除（不可 waitpid）。leader 留给 waitpid 回收。
    if(pid != tg->tgid) {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        pid_map.erase(pid);
    }

    if(!last) {
        return;
    }

    // 标记整组 exited 并唤醒 waitpid。tg->exit_code 由 do_exit/do_exit_group 用 CAS
    // 首次写入，被 VM_KILLED 的线程不走 do_exit 故不碰；此处仅在仍为 -1（整组无人正常
    // 退出，且不是经 do_kill→do_exit(128+sig) 被信号杀）时兜底置 137，正常路径不命中。
    int expected = -1;
    tg->exit_code.compare_exchange_strong(expected, 128 + 9, std::memory_order_acq_rel);
    tg->exited.store(true, std::memory_order_release);
    tg->cv.notify_all();

    // 把本组派生的孤儿重定向到 pid 1。children 的 ppid 记的是本组 tg->tgid（leader pid），
    // 故用 tg->tgid 匹配；由最后一个退出的线程执行即可——不必是 leader，规避 leader 先于
    // last 退出时漏 reparent 的窗口。
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        for(auto& entry : pid_map) {
            auto child_sys = sys(entry.second.get());
            if(child_sys && child_sys->ppid.load() == tg->tgid) {
                child_sys->ppid.store(1);
            }
        }
    }

    // 清理进程级资源。maps 已在上方 per-thread 释放（exit_mm 语义），此处仅清 fd 表。
    ps->fds.clear();
}

void PosixSyscall::queue_signal(vm* v, int sig) {
    if(sig == SIGKILL) {
        flags(v).fetch_or(vm::VM_KILLED, std::memory_order_release);
        v->wakeup();
    } else if(sig == SIGSTOP) {
        flags(v).fetch_or(vm::VM_STOPPED, std::memory_order_release);
        v->wakeup();
    } else if(sig == SIGCONT) {
        flags(v).fetch_and(~vm::VM_STOPPED, std::memory_order_release);
        v->wakeup();
    } else {
        // Best-effort: drop if the queue is full to avoid blocking the VM thread.
        if(pending_signals.try_push(sig)) {
            flags(v).fetch_or(vm::VM_SIGNAL_PENDING, std::memory_order_release);
            // 排队信号也要 wakeup()：vm 可能正阻塞在 futex 的 exit_cv 上，而 SIGUSR1
            // 无法可靠打断 pthread_cond_wait（glibc 内部重试 EINTR），必须靠 broadcast
            // exit_cv 让等待者醒来查 VM_SIGNAL_PENDING 并返回 -EINTR 交回 safepoint。
            v->wakeup();
        }
    }
    if (tid != 0) {
        pthread_kill(tid, SIGUSR1);
    }
}

bool PosixSyscall::handle_signals(vm* v) {
    int sig = 0;
    if(!pending_signals.try_pop(sig)) {
        // Queue is empty. Clear VM_SIGNAL_PENDING with a seq_cst fence, then
        // re-check to close the race window with a concurrent queue_signal:
        // if another thread pushed between try_pop and the clear, the second
        // try_pop will catch it; if it pushed after the clear, it will have
        // set VM_SIGNAL_PENDING again, so the next safepoint() will retry.
        flags(v).fetch_and(~vm::VM_SIGNAL_PENDING, std::memory_order_seq_cst);
        if(!pending_signals.try_pop(sig)) {
            return true;
        }
        flags(v).fetch_or(vm::VM_SIGNAL_PENDING, std::memory_order_relaxed);
    }
    if(sig <= 0 || sig >= NSIG) {
        return true;
    }
    const uint64_t sig_dfl = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_DFL));
    const uint64_t sig_ign = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_IGN));
    uint64_t handler = ps->signal_actions[static_cast<size_t>(sig)].handler;
    if(options(v).verbose) {
        std::lock_guard<std::mutex> lock(log_mutex);
        printf("[#%d] signal %d handler=0x%lx return=0x%lx\n",
               id(), sig, static_cast<unsigned long>(handler), pc(v));
    }
    if(handler == sig_ign) {
        return true;
    }
    if(handler == sig_dfl) {
        switch(sig) {
        case SIGTERM:
        case SIGINT:
        case SIGABRT:
        case SIGSEGV:
        case SIGILL:
        case SIGFPE:
            // 致命信号默认动作 = 终止整个线程组（POSIX/Linux 语义：default action of
            // fatal signals is process termination，等价 exit_group），不只杀当前线程。
            v->r(1) = 128 + static_cast<uint64_t>(sig);
            return do_exit_group(v);
        case SIGTSTP:
        case SIGTTIN:
        case SIGTTOU:
            flags(v).fetch_or(vm::VM_STOPPED, std::memory_order_release);
            v->wakeup();
            return true;
        default:
            return true;
        }
    }

    if(!v->mmu(handler)) {
        v->r(1) = 128 + static_cast<uint64_t>(SIGSEGV);
        return do_exit_group(v);
    }
    if(!v->push_frame(pc(v), true)) {
        v->r(1) = 128 + static_cast<uint64_t>(SIGBUS);
        return do_exit_group(v);
    }
    v->r(1) = static_cast<uint64_t>(sig);
    pc(v) = handler;
    return true;
}

std::shared_ptr<PosixSyscall> PosixSyscall::sys(vm* v) {
    if (v == nullptr) {
        return nullptr;
    }
    return std::dynamic_pointer_cast<PosixSyscall>(options(v).sys);
}


int PosixSyscall::allocate_fd(int min_fd) {
    int fd = min_fd;
    while(ps->fds.count(fd)) {
        fd++;
    }
    return fd;
}

bool PosixSyscall::read_c_string(vm* v, uint64_t addr, std::string& out, size_t max_len) {
    out.clear();
    if(addr == 0) {
        return false;
    }
    for(size_t i = 0; i < max_len; i++) {
        void* p = v->mmu(addr + i);
        if(p == nullptr) {
            return false;
        }
        char c = *(char*)p;
        if(c == '\0') {
            return true;
        }
        out.push_back(c);
    }
    return false;
}

bool PosixSyscall::read_c_string_array(vm* v, uint64_t addr, std::vector<std::string>& out, size_t max_count, size_t max_str_len) {
    out.clear();
    if(addr == 0) {
        return true;
    }
    for(size_t i = 0; i < max_count; i++) {
        void* p = v->mmu(addr + i * sizeof(uint64_t));
        if(p == nullptr) {
            return false;
        }
        uint64_t str_addr = *(uint64_t*)p;
        if(str_addr == 0) {
            return true;
        }
        std::string value;
        if(!read_c_string(v, str_addr, value, max_str_len)) {
            return false;
        }
        out.push_back(std::move(value));
    }
    return false;
}

std::string PosixSyscall::resolve_path(const std::string& path) {
    if(path.empty()) {
        return path;
    }
    std::filesystem::path input(path);
    if(input.is_absolute()) {
        return input.lexically_normal().string();
    }
    std::filesystem::path base = ps->cwd.empty() ? std::filesystem::path("/") : std::filesystem::path(ps->cwd);
    return (base / input).lexically_normal().string();
}

bool PosixSyscall::do_clock_gettime(vm* v) {
    clockid_t clock_id = (clockid_t)arg_s32(v->r(1));
    struct timespec* tp = (struct timespec*)v->mmu_w(v->r(2), sizeof(*tp));
    if(tp == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    if(clock_gettime(clock_id, tp) == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_mmap(vm* v) {
    /* 标准 Linux mmap 调用约定：mmap(addr, len, prot, flags, fd, offset)。
     *   前 5 个用户参数（addr, len, prot, flags, fd）落在 r1..r5；第 6 个 offset
     *   经 BpfWideArgs pass 用前置内联 asm 写到 r0（syscall 6 参特例 ABI：
     *   r0 在 call 前作输入、call 后被返回值覆盖）。
     *
     * 地址模型：guest vaddr（memmap.paddr）与 host 真实内存（memmap.data）是两套
     * 独立空间。host 内存永远用 mmap(nullptr,...) 独立分配，与 addr 无关；addr 只
     * 决定 guest vaddr 的取值：
     *   - 无 MAP_FIXED：addr 仅作 hint，Linux 允许忽略。沿用尾部分配（接着上一个
     *     guest 映射尾部），返回新分配的 guest 地址。
     *   - MAP_FIXED：必须把映射放在 guest 空间的 addr 处。先按 Linux 语义 unmap 掉
     *     与 [addr, addr+len) 重叠的旧 guest 映射，再令 memmap.paddr = addr。
     *     addr 未页对齐返回 -EINVAL。长度向上页对齐（Linux 要求）。 */
    uint64_t addr_hint = v->r(1);
    size_t len = arg_size(v->r(2));
    int prot = arg_s32(v->r(3));
    int flags = arg_s32(v->r(4));
    int fd = arg_s32(v->r(5));
    off_t offset = (off_t)v->r(0);

    // 长度向上页对齐（Linux mmap 要求，否则 EINVAL）。
    static constexpr size_t PAGE = 0x1000;
    len = (len + PAGE - 1) & ~(PAGE - 1);
    if (len == 0) {
        v->r(0) = -EINVAL;
        return true;
    }

    const bool fixed = flags & MAP_FIXED;
    if (fixed && (addr_hint % PAGE) != 0) {
        v->r(0) = -EINVAL;   // MAP_FIXED 要求 addr 页对齐
        return true;
    }

    int host_fd = -1;
    if (!(flags & MAP_ANONYMOUS)) {
        auto it = ps->fds.find(fd);
        if (it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        host_fd = it->second->fd;
    }

    // host 内存始终独立分配（addr_hint 是 guest 空间地址，与 host 无关；host 端不
    // 用 MAP_FIXED，避免 guest 间接控制 host 地址布局）。
    void* addr = mmap(nullptr, len, prot, flags & ~MAP_FIXED, host_fd, offset);
    if(addr == MAP_FAILED) {
        v->r(0) = -errno;
        return true;
    }

    // MAP_FIXED：按 Linux 语义先 unmap 与 [addr_hint, addr_hint+len) 重叠的旧 guest
    // 映射。本 VM 映射粒度粗（一个 memmap 一段），这里删除所有与该区间相交的整段
    // 映射（不做 VMA 切分，多数 MAP_FIXED 用法是整段覆盖，足够）。
    if (fixed) {
        const uint64_t base = addr_hint;
        const uint64_t end = addr_hint + len;
        auto& ml = maps(v);
        std::lock_guard<std::mutex> lock(*maps_mutex(v));
        for (auto it = ml.begin(); it != ml.end();) {
            const bool overlap = (it->paddr < end) && (base < it->paddr + it->size);
            if (overlap) it = ml.erase(it);
            else ++it;
        }
        v->flush_tlb();
    }

    memmap mem;
    mem.size = len;
    mem.set_data((unsigned char*)addr, mem.size);
    mem.flags = 0;
    if(prot & PROT_READ) {
        mem.flags |= PF_R;
    }
    if(prot & PROT_WRITE) {
        mem.flags |= PF_W;
    }
    if(prot & PROT_EXEC) {
        mem.flags |= PF_X;
    }
    if (fixed) {
        mem.paddr = addr_hint;   // guest 空间固定地址
        v->r(0) = mem.paddr;
        v->addmem(std::move(mem));
    } else {
        // 非 fixed：guest 地址「接在上一个映射尾部」分配。必须把「算地址 + 插入」
        // 放进同一把锁，否则多线程并发 mmap 时各自读到同一个 ml.back()、算出同一个
        // next，释放锁后各自 insert → 多个 memmap 分配到重叠的 guest 地址（绑定不同
        // host 内存、TLB 互相覆盖、munmap 后 host 指针失效 → SIGSEGV）。
        // addmem 内部会自行加锁，因此这里直接操作 maps（与 addmem 的有序插入逻辑一致），
        // 不重复走 addmem。
        //
        // 页对齐（Linux mmap 总是返回页对齐地址）：mallocng 等分配器强依赖 4096
        // 对齐——meta_area 用 `meta & -4096` 反推 meta_area 起点；若 mmap 返回非对齐
        // 地址，meta 落在错误 meta_area 里，`area->check != ctx.secret` 立即崩溃。
        auto& ml = maps(v);
        std::lock_guard<std::mutex> lock(*maps_mutex(v));
        uint64_t next = ml.back().paddr + ml.back().size;
        mem.paddr = (next + PAGE - 1) & ~(PAGE - 1);
        v->r(0) = mem.paddr;
        auto it = ml.begin();
        while(it != ml.end() && it->paddr < mem.paddr) {
            it++;
        }
        ml.insert(it, std::move(mem));
    }
    v->flush_tlb();
    return true;
}

bool PosixSyscall::do_munmap(vm* v) {
    if(!v->unmap(v->r(1))) {
        v->r(0) = -EINVAL;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_exit(vm* v) {
    int code = arg_s32(v->r(1));
    v->r(0) = (uint64_t)(unsigned int)code;
    // CAS(-1 -> code)：首个正常退出者赢，后续不覆盖。致命信号默认动作走 do_exit_group，不经过此函数。
    int expected = -1;
    tg->exit_code.compare_exchange_strong(expected, code, std::memory_order_acq_rel);
    return false;  // fini 减 live_threads + clear-child-tid
}

bool PosixSyscall::do_exit_group(vm* v) {
    int code = arg_s32(v->r(1));
    v->r(0) = (uint64_t)(unsigned int)code;
    // CAS(-1 -> code)：首个正常退出者赢，被置 VM_KILLED 的线程不走 do_exit，不会覆盖。
    int expected = -1;
    tg->exit_code.compare_exchange_strong(expected, code, std::memory_order_acq_rel);
    {
        // 杀掉线程组内所有其他线程。走目标线程自己的 queue_signal(SIGKILL)：
        std::lock_guard<std::mutex> lock(tg->mtx);
        for(auto& weak_vm : tg->threads) {
            auto tvm = weak_vm.lock();
            if(tvm && tvm.get() != v) {
                options(tvm.get()).sys->queue_signal(tvm.get(), SIGKILL);
            }
        }
    }
    return false;  // 调用线程退出 → fini
}


bool PosixSyscall::do_nanosleep(vm* v) {
    const struct timespec* req = static_cast<const struct timespec*>(v->mmu(v->r(1)));
    if(req == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }

    struct timespec* rem = nullptr;
    if(v->r(2) != 0) {
        rem = static_cast<struct timespec*>(v->mmu_w(v->r(2), sizeof(*rem)));
        if(rem == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
    }

    struct timespec host_req = {};
    if(req != nullptr) {
        host_req = *req;
    }

    struct timespec host_rem = {};
    int rc = nanosleep(&host_req, rem != nullptr ? &host_rem : nullptr);
    if(rc == -1) {
        if(rem != nullptr) {
            *rem = host_rem;
        }
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_openat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int flags = arg_s32(v->r(3));
    mode_t mode = (mode_t)(arg_u32(v->r(4)) & ~umask_val);
    int fd = -1;
    std::string resolved;
    if(dirfd == AT_FDCWD) {
        resolved = resolve_path(path);
        fd = openat(AT_FDCWD, resolved.c_str(), flags, mode);
    } else {
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        fd = openat(it->second->fd, path.c_str(), flags, mode);
        if(!it->second->path.empty()) {
            resolved = (std::filesystem::path(it->second->path) / path).lexically_normal().string();
        }
    }
    if(fd == -1) {
        v->r(0) = -errno;
        return true;
    }
    auto handle = std::make_shared<fd_handle>(fd, std::move(resolved));
    if(flags & O_CLOEXEC) {
        handle->cloexec = true;
    }
    int guest_fd = allocate_fd();
    ps->fds[guest_fd] = handle;
    v->r(0) = guest_fd;
    return true;
}

bool PosixSyscall::do_read(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu_w(v->r(2), count);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    int rc = read(it->second->fd, buf, count);
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = rc;
    return true;
}

bool PosixSyscall::do_write(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu(v->r(2), count);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    int rc = write(it->second->fd, buf, count);
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = rc;
    return true;
}

bool PosixSyscall::do_lseek(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    int rc = lseek64(it->second->fd, (off_t)v->r(2), arg_s32(v->r(3)));
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = rc;
    return true;
}

bool PosixSyscall::do_truncate(vm* v) {
    std::string path;
    if(!read_c_string(v, v->r(1), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int rc = truncate(resolve_path(path).c_str(), static_cast<off_t>(v->r(2)));
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_ftruncate(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    int rc = ftruncate(it->second->fd, static_cast<off_t>(v->r(2)));
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_close(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    ps->fds.erase(it);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_unlinkat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int flags = arg_s32(v->r(3));
    int rc = -1;
    if(dirfd == AT_FDCWD) {
        rc = unlinkat(AT_FDCWD, resolve_path(path).c_str(), flags);
    } else {
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        rc = unlinkat(it->second->fd, path.c_str(), flags);
    }
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_mkdirat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    mode_t mode = (mode_t)(arg_u32(v->r(3)) & ~umask_val);
    int rc;
    if(dirfd == AT_FDCWD) {
        rc = mkdir(resolve_path(path).c_str(), mode);
    } else {
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        rc = mkdirat(it->second->fd, path.c_str(), mode);
    }
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_symlinkat(vm* v) {
    std::string target;
    std::string linkpath;
    if(!read_c_string(v, v->r(1), target, 4096) || !read_c_string(v, v->r(3), linkpath, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int new_dirfd = arg_s32(v->r(2));
    int rc = -1;
    if(new_dirfd == AT_FDCWD) {
        rc = symlinkat(target.c_str(), AT_FDCWD, resolve_path(linkpath).c_str());
    } else {
        auto it = ps->fds.find(new_dirfd);
        if(it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        rc = symlinkat(target.c_str(), it->second->fd, linkpath.c_str());
    }
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_linkat(vm* v) {
    std::string oldpath;
    std::string newpath;
    if(!read_c_string(v, v->r(2), oldpath, 4096) || !read_c_string(v, v->r(4), newpath, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int olddirfd = arg_s32(v->r(1));
    int newdirfd = arg_s32(v->r(3));
    int flags = arg_s32(v->r(5));

    int host_olddirfd = AT_FDCWD;
    if (olddirfd != AT_FDCWD) {
        auto it = ps->fds.find(olddirfd);
        if (it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        host_olddirfd = it->second->fd;
    }

    int host_newdirfd = AT_FDCWD;
    if (newdirfd != AT_FDCWD) {
        auto it = ps->fds.find(newdirfd);
        if (it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        host_newdirfd = it->second->fd;
    }

    std::string resolved_old = oldpath;
    if (olddirfd == AT_FDCWD) {
        resolved_old = resolve_path(oldpath);
    }
    std::string resolved_new = newpath;
    if (newdirfd == AT_FDCWD) {
        resolved_new = resolve_path(newpath);
    }

    int rc = linkat(host_olddirfd, resolved_old.c_str(), host_newdirfd, resolved_new.c_str(), flags);
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_renameat2(vm* v) {
    std::string old_path;
    std::string new_path;
    if(!read_c_string(v, v->r(2), old_path, 4096) || !read_c_string(v, v->r(4), new_path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int old_dirfd = arg_s32(v->r(1));
    int new_dirfd = arg_s32(v->r(3));
    unsigned int flags = arg_u32(v->r(5));

    int host_old_dirfd = AT_FDCWD;
    if (old_dirfd != AT_FDCWD) {
        auto it = ps->fds.find(old_dirfd);
        if (it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        host_old_dirfd = it->second->fd;
    }

    int host_new_dirfd = AT_FDCWD;
    if (new_dirfd != AT_FDCWD) {
        auto it = ps->fds.find(new_dirfd);
        if (it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        host_new_dirfd = it->second->fd;
    }

    std::string resolved_old = old_path;
    std::string resolved_new = new_path;
    if(old_dirfd == AT_FDCWD) {
        resolved_old = resolve_path(old_path);
    }
    if(new_dirfd == AT_FDCWD) {
        resolved_new = resolve_path(new_path);
    }
#if defined(__ANDROID__)
    // Android bionic 不暴露 renameat2() libc 包装函数，直接走 syscall。
    int rc = (int)::syscall(SYS_renameat2, host_old_dirfd, resolved_old.c_str(),
                            host_new_dirfd, resolved_new.c_str(), flags);
#else
    int rc = renameat2(host_old_dirfd, resolved_old.c_str(),
                       host_new_dirfd, resolved_new.c_str(), flags);
#endif
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_readlinkat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    size_t bufsiz = arg_size(v->r(4));
    char* buf = (char*)v->mmu_w(v->r(3), bufsiz);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    ssize_t rc;
    if(dirfd == AT_FDCWD) {
        rc = readlink(resolve_path(path).c_str(), buf, bufsiz);
    } else {
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        rc = readlinkat(it->second->fd, path.c_str(), buf, bufsiz);
    }
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = rc;
    return true;
}

bool PosixSyscall::do_execve(vm* v) {
    std::string path;
    std::vector<std::string> argv_strings;
    std::vector<std::string> envp_strings;
    if(!read_c_string(v, v->r(1), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    if(!read_c_string_array(v, v->r(2), argv_strings, 1024, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    if(!read_c_string_array(v, v->r(3), envp_strings, 1024, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }

    auto fresh = vm::create();
    ElfLoadInfo load_info = fresh->load_elf(resolve_path(path).c_str());
    if(load_info.entry == 0) {
        v->r(0) = -ENOEXEC;
        return true;
    }
    const uint64_t entry = load_info.entry;
    // setup_stack 直接接收 load_info，用它合成 auxv（musl __init_tls 靠
    // AT_PHDR/AT_PHENT/AT_PHNUM/AT_ENTRY 定位 PT_TLS）。
    if(!fresh->setup_stack(argv_strings, envp_strings, load_info)) {
        v->r(0) = -E2BIG;
        return true;
    }
    if(!fresh->mmu(entry)) {
        v->r(0) = -ENOEXEC;
        return true;
    }
    // execve 替换整个 guest 地址空间为新程序：同步 v->options 里「跑什么程序」的字段
    //（entry/argv/envp），让后续 dump_stats/调试读到的是新程序而非旧残留。
    // 宿主侧配置（verbose/breakpoint/insn_limit/sys 等）跨 execve 保留不变。
    options(v).entry = entry;
    options(v).argv = std::move(argv_strings);
    options(v).envp = std::move(envp_strings);
    {
        std::lock_guard<std::mutex> lock(*maps_mutex(v));
        maps(v).swap(maps(fresh.get()));
    }
    v->flush_tlb();
    // execve 替换了整个 guest 地址空间：旧程序编译的 JIT 函数全部失效。
    // 且新旧程序共享相同的 guest 地址区间（都从 0x400000 链接），必须清空缓存，
    // 否则会误命中旧程序的编译产物。
    v->clear_jit_cache();

    decltype(ps->signal_actions) new_actions{};
    const uint64_t sig_dfl = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_DFL));
    const uint64_t sig_ign = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_IGN));
    for(size_t i = 0; i < new_actions.size(); i++) {
        if(ps->signal_actions[i].handler == sig_ign) {
            new_actions[i].handler = sig_ign;
        } else {
            new_actions[i].handler = sig_dfl;
        }
    }
    ps->signal_actions = new_actions;
    signal_depth(v) = 0;

    std::unordered_map<int, std::shared_ptr<fd_handle>> new_fds;
    for (const auto& entry : ps->fds) {
        if (!entry.second->cloexec) {
            new_fds.insert(entry);
        }
    }
    ps->fds.swap(new_fds);
    v->r(1) = fresh->r(1);
    v->r(10) = STACK_BASE + STACK_SIZE - 8;
    pc(v) = entry;
    v->push_frame(0);
    pc(v) -= sizeof(bpf_insn);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_clone(vm* v) {
    uint64_t flags  = v->r(1);
    uint64_t stack  = v->r(2);
    uint64_t ptid   = v->r(3);
    uint64_t ctid   = v->r(4);
    uint64_t newtls = v->r(5);

    bool is_thread = (flags & CLONE_THREAD) != 0;
    bool share_vm = (flags & CLONE_VM) != 0;

    auto child = vm::create();
    options(child.get()) = options(v);
    /* CLONE_THREAD 是新线程，不在任何信号处理上下文 → signal_depth=0。
     * 非 CLONE_THREAD（如 fork / 裸 clone 新进程）继承父 signal_depth，
     * 与 fork 语义一致（fork 复制整个执行状态）。 */
    signal_depth(child.get()) = is_thread ? 0 : signal_depth(v);

    /* 共享或拷贝进程级状态（fds/signal_actions/cwd）。
     * CLONE_THREAD: 整体共享 ps（musl 总是同时传 CLONE_FILES|SIGHAND|FS|THREAD）。
     * 非 CLONE_THREAD: 拷贝 ps（同 fork 语义）——dup 父 fd 成独立 host fd，
     *   否则子进程会丢掉所有打开的文件描述符。 */
    std::unordered_map<int, std::shared_ptr<fd_handle>> child_fds;
    if(!is_thread) {
        for(const auto& entry : ps->fds) {
            int new_host_fd = dup(entry.second->fd);
            if(new_host_fd < 0) {
                v->r(0) = -errno;
                return true;
            }
            auto new_handle = std::make_shared<fd_handle>(new_host_fd, entry.second->path);
            new_handle->cloexec = entry.second->cloexec;
            child_fds[entry.first] = new_handle;
        }
    }
    auto child_sys = std::make_shared<PosixSyscall>(
        is_thread ? ppid.load() : tg->tgid,
        is_thread ? ps->fds : child_fds,
        ps->cwd, pgrp, session);
    if(!is_thread) {
        child_sys->ps->signal_actions = ps->signal_actions;
    } else {
        child_sys->ps = ps;
        child_sys->tg = tg;
        tg->live_threads.fetch_add(1);
    }
    child_sys->umask_val = umask_val;
    options(child.get()).sys = child_sys;

    /* 地址空间：CLONE_VM 共享 maps（同一 shared_ptr，后续 mmap 互通可见）；
     * 否则 CoW 拷贝（同 fork）。 */
    if(share_vm) {
        maps_ptr(child.get()) = maps_ptr(v);
        maps_mutex(child.get()) = maps_mutex(v);
    } else {
        std::lock_guard<std::mutex> lock(*maps_mutex(v));
        for(auto& map : maps(v)) {
            memmap child_map;
            child_map.size  = map.size;
            child_map.paddr = map.paddr;
            child_map.flags = map.flags;

            if(map.flags & PF_W) {
                if(!map.cow_data && map.data.get_deleter().owned) {
                    map.cow_data = std::shared_ptr<unsigned char>(
                        map.data.get(), DataDeleter{map.data.get_deleter().size, true});
                    map.data.get_deleter().owned = false;
                }
                child_map.set_data(map.data.get(), map.size, false);
                child_map.cow_data = map.cow_data;
            } else {
                child_map.set_data(map.data.get(), map.size, false);
            }
            child->addmem(std::move(child_map));
        }
    }
    if(share_vm) {
        v->flush_tlb();
    } else {
        /* fork（非 CLONE_VM）就地修改父地址空间：每段 writable map 建立 cow_data、
         * data.owned 置 false。父线程组里其它线程（如 pthread_create 出来的 worker）的
         * TLB 此时是陈旧的——条目仍是 cow=false、host_base 指向原页，会绕过 CoW 直接写
         * 共享页，破坏 CoW 不变式。必须把同组所有线程的 TLB 一并刷新（仅 v->flush_tlb()
         * 只清了调用线程）。CLONE_THREAD 不改 maps，无需此步。 */
        std::lock_guard<std::mutex> tlock(tg->mtx);
        for(auto& weak : tg->threads) {
            if(auto t = weak.lock()) t->flush_tlb();
        }
    }

    /* child 继承父所有寄存器（含 r9=func，供 musl __clone.s child 路径 callx r9）。
     * r(0)=0（clone 返回值），r(10)=新栈顶（arg 已由 .s 压在 *(u64*)(r10+0)），
     * pc=syscall 返回点（call 后下一条指令）。 */
    for(size_t i = 0; i < 11; i++) {
        child->r(i) = v->r(i);
    }
    child->r(0) = 0;
    /* 栈来源：clone 调用者通过 r(2) 提供新栈顶；stack==NULL（如 fork 经 do_clone
     * 传入）时继承父 r(10)——fork 的子进程是父地址空间的 CoW 副本，栈也在其中，
     * 直接用父栈指针即可（上面 r(i)=v->r(i) 已拷贝了 r(10)，这里 stack!=0 才覆盖）。 */
    if(stack != 0) {
        child->r(10) = stack;
    }
    pc(child.get()) = pc(v) + sizeof(bpf_insn);

    /* CLONE_SETTLS：新线程用调用者提供的 tls。
     * 否则（非 CLONE_THREAD，如 fork / 裸 clone 新进程）继承父 tp：子进程是父
     * 地址空间的副本（CoW），struct pthread 仍在同样的虚拟地址，TP 指向它依然
     * 有效。若不继承，子进程 tp_=0 → __pthread_self() 返回 NULL → musl 后续写
     * self->tid（偏移 0x30）会 invalid write at 0x30 崩溃。 */
    if(flags & CLONE_SETTLS) {
        tp(child.get()) = newtls;
    } else if(!is_thread) {
        tp(child.get()) = tp(v);
    }

    /* CLONE_PARENT_SETTID / CLONE_CHILD_SETTID：写 child tid（pid_t = int, 4 字节）。
     * musl 传 ptid=&new->tid、ctid=&__thread_list_lock（后者配合 CLEARTID 用）。
     * CLONE_VM 下父子地址空间共享，用父 mmu_w。 */
    if(flags & CLONE_PARENT_SETTID) {
        auto* p = static_cast<int*>(v->mmu_w(ptid, sizeof(int)));
        if(p) *p = (int)child_sys->pid;
    }
    if(flags & CLONE_CHILD_SETTID) {
        auto* p = static_cast<int*>(v->mmu_w(ctid, sizeof(int)));
        if(p) *p = (int)child_sys->pid;
    }
    if(flags & CLONE_CHILD_CLEARTID) {
        child_sys->tid_address_ = ctid;
    }

    /* 启动 host 线程 */
    pthread_attr_t attr;
    pthread_t worker;
    int rc = pthread_attr_init(&attr);
    if(rc != 0) {
        v->r(0) = -rc;
        return true;
    }
    rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if(rc != 0) {
        pthread_attr_destroy(&attr);
        v->r(0) = -rc;
        return true;
    }
    auto* holder = new std::shared_ptr<vm>(child);
    rc = pthread_create(&worker, &attr, [](void* arg) -> void* {
        auto* child = static_cast<std::shared_ptr<vm>*>(arg);
        (*child)->run();
        delete child;
        return nullptr;
    }, holder);
    pthread_attr_destroy(&attr);
    if(rc != 0) {
        delete holder;
        if(is_thread) tg->live_threads.fetch_sub(1);
        v->r(0) = -rc;
        return true;
    }
    {
        std::lock_guard<std::mutex> lock(child_sys->tg->mtx);
        child_sys->tg->threads.push_back(child);
    }
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        pid_map[child_sys->pid] = child;
    }
    v->r(0) = child_sys->pid;
    return true;
}

bool PosixSyscall::do_getpid(vm* v) {
    v->r(0) = tg->tgid;
    return true;
}

bool PosixSyscall::do_getppid(vm* v) {
    v->r(0) = ppid.load();
    return true;
}

// 在 pid_map 中按 pid 查找 task，返回 vm shared_ptr（持锁内取出，调用方持有期间 vm 不会析构）。
std::shared_ptr<vm> PosixSyscall::find_task(uint64_t target_pid) {
    std::lock_guard<std::mutex> lock(pid_map_mutex);
    auto it = pid_map.find(target_pid);
    if(it == pid_map.end()) {
        return nullptr;
    }
    return it->second;
}

bool PosixSyscall::do_setpgid(vm* v) {
    pid_t pid_arg = arg_s32(v->r(1));
    pid_t pgrp_arg = arg_s32(v->r(2));
    if(pgrp_arg < 0) {
        v->r(0) = -EINVAL;
        return true;
    }

    // 解析目标 task：pid_arg==0 → 自身；否则必须是自身或子进程。
    std::shared_ptr<vm> target_vm;
    PosixSyscall* target = nullptr;
    if(pid_arg == 0) {
        target = this;
    } else {
        target_vm = find_task(static_cast<uint64_t>(pid_arg));
        if(!target_vm) {
            v->r(0) = -ESRCH;
            return true;
        }
        target = sys(target_vm.get()).get();
        if(!target) {
            v->r(0) = -ESRCH;
            return true;
        }
        // 仅允许改自身或子进程（ppid 记的是父 tg->tgid，故用 tg->tgid 匹配）
        if(static_cast<uint64_t>(pid_arg) != tg->tgid && target->ppid.load() != tg->tgid) {
            v->r(0) = -ESRCH;
            return true;
        }
    }

    // 跨 session 禁止
    if(target->session.get() != session.get()) {
        v->r(0) = -EPERM;
        return true;
    }
    // session leader 不可改 pgrp
    if(target->session->sid == target->pid) {
        v->r(0) = -EPERM;
        return true;
    }
    // 已是目标组成员且 pgid 一致：no-op
    if(target->pgrp->pgid == static_cast<uint64_t>(pgrp_arg) && pgrp_arg != 0) {
        v->r(0) = 0;
        return true;
    }

    // 解析新 pgid：pgrp_arg==0 → 目标自身 pid（新建组）
    uint64_t new_pgid = (pgrp_arg == 0) ? target->pid : static_cast<uint64_t>(pgrp_arg);

    // 若 new_pgid != 目标 pid，必须存在同 session 的进程以该 pid 为 pgid leader
    //（即某进程 pid == new_pgid 且同 session）。
    if(new_pgid != target->pid) {
        std::shared_ptr<vm> leader_vm = find_task(new_pgid);
        if(!leader_vm) {
            v->r(0) = -EPERM;
            return true;
        }
        auto leader = sys(leader_vm.get());
        if(!leader || leader->session.get() != session.get()) {
            v->r(0) = -EPERM;
            return true;
        }
    }

    target->pgrp = std::make_shared<ProcessGroup>(new_pgid, target->session);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_getpgid(vm* v) {
    pid_t pid_arg = arg_s32(v->r(1));
    if(pid_arg == 0) {
        v->r(0) = pgrp->pgid;
        return true;
    }
    auto target_vm = find_task(static_cast<uint64_t>(pid_arg));
    if(!target_vm) {
        v->r(0) = -ESRCH;
        return true;
    }
    auto target = sys(target_vm.get());
    if(!target) {
        v->r(0) = -ESRCH;
        return true;
    }
    v->r(0) = target->pgrp->pgid;
    return true;
}

bool PosixSyscall::do_getpgrp(vm* v) {
    v->r(0) = pgrp->pgid;
    return true;
}

bool PosixSyscall::do_setsid(vm* v) {
    // 已是进程组 leader → EPERM
    if(pgrp->pgid == pid) {
        v->r(0) = -EPERM;
        return true;
    }
    auto new_session = std::make_shared<Session>(pid);
    pgrp = std::make_shared<ProcessGroup>(pid, new_session);
    session = new_session;
    v->r(0) = pid;
    return true;
}

bool PosixSyscall::do_getsid(vm* v) {
    pid_t pid_arg = arg_s32(v->r(1));
    if(pid_arg == 0) {
        v->r(0) = session->sid;
        return true;
    }
    auto target_vm = find_task(static_cast<uint64_t>(pid_arg));
    if(!target_vm) {
        v->r(0) = -ESRCH;
        return true;
    }
    auto target = sys(target_vm.get());
    if(!target) {
        v->r(0) = -ESRCH;
        return true;
    }
    v->r(0) = target->session->sid;
    return true;
}

bool PosixSyscall::do_waitpid(vm* v) {
    int64_t target_pid = static_cast<int64_t>(arg_s32(v->r(1)));
    uint64_t status_addr = v->r(2);
    int32_t options = arg_s32(v->r(3));

    if((options & ~WNOHANG) != 0) {
        v->r(0) = -EINVAL;
        return true;
    }

    // waitpid(self) 无意义
    if(target_pid == (int64_t)pid) {
        v->r(0) = -EINVAL;
        return true;
    }

    int* status_ptr = nullptr;
    if(status_addr != 0) {
        status_ptr = static_cast<int*>(v->mmu_w(status_addr, sizeof(*status_ptr)));
        if(status_ptr == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
    }

    // 收集候选子进程。Linux 语义：
    //   pid > 0  → 指定 task（必须是自身子进程的线程组 leader）
    //   pid == 0 → 调用者进程组里任意子进程
    //   pid == -1→ 任意子进程
    //   pid < -1 → 进程组 -pid 里任意子进程
    // 只有 leader（pid == tg->tgid）可被 waitpid；非 leader 线程退出不产生可 wait 状态。
    auto match_child = [&](const std::shared_ptr<vm>& task_vm) -> bool {
        auto s = sys(task_vm.get());
        if(!s || s->ppid.load() != tg->tgid) return false;
        if(s->pid != s->tg->tgid) return false;  // 仅 leader 可 wait
        if(target_pid == -1) return true;
        if(target_pid == 0) return s->pgrp->pgid == pgrp->pgid;
        if(target_pid < -1) return s->pgrp->pgid == static_cast<uint64_t>(-target_pid);
        return false;
    };

    auto child_exited = [](const std::shared_ptr<vm>& task_vm) -> bool {
        auto s = sys(task_vm.get());
        return s && s->tg->exited.load(std::memory_order_acquire);
    };

    std::vector<std::shared_ptr<vm>> children;
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        if(target_pid > 0) {
            auto it = pid_map.find(static_cast<uint64_t>(target_pid));
            if(it == pid_map.end()) {
                v->r(0) = -ECHILD;
                return true;
            }
            auto child_sys = sys(it->second.get());
            if(child_sys == nullptr || child_sys->ppid.load() != tg->tgid) {
                v->r(0) = -ECHILD;
                return true;
            }
            children.push_back(it->second);
        } else {
            for(const auto& entry : pid_map) {
                if(!match_child(entry.second)) continue;
                if(child_exited(entry.second)) {
                    children.clear();
                    children.push_back(entry.second);
                    break;
                }
                children.push_back(entry.second);
            }
        }
    }

    if(children.empty()) {
        v->r(0) = -ECHILD;
        return true;
    }

    std::shared_ptr<vm> child;
    if(children.size() == 1 && child_exited(children[0])) {
        child = children[0];
    } else {
        if(options & WNOHANG) {
            v->r(0) = 0;
            return true;
        }

        do {
            for(const auto& candidate : children) {
                auto cs = sys(candidate.get());
                if(!cs) continue;
                {
                    std::unique_lock<std::mutex> lk(cs->tg->mtx);
                    cs->tg->cv.wait_for(lk, std::chrono::milliseconds(100), [&]{
                        return cs->tg->exited.load(std::memory_order_acquire);
                    });
                }
                if(cs->tg->exited.load(std::memory_order_acquire)) {
                    child = candidate;
                    break;
                }
                // VM_KILLED：被 exit_group / 致命信号命中，应立即返回 EINTR 让线程回 safepoint 退出。
                // 不查 VM_EXITED：它在 run() 末尾才置，线程卡在 waitpid 内部时恒为假。
                if(!pending_signals.empty() || (flags(v).load(std::memory_order_acquire) & vm::VM_KILLED)) {
                    v->r(0) = -EINTR;
                    return true;
                }
            }
        } while(child == nullptr);
    }

    //wait不能加锁，否则会死锁
    auto cs = sys(child.get());
    uint64_t exit_code = static_cast<uint64_t>(cs->tg->exit_code.load(std::memory_order_acquire));
    if(status_ptr != nullptr) {
        int status = (static_cast<int>(exit_code) & 0xff) << 8;
        *status_ptr = status;
    }

    uint64_t child_pid = cs->pid;  // leader 的 pid（== tg->tgid）
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        pid_map.erase(child_pid);
    }
    v->r(0) = child_pid;
    return true;
}

bool PosixSyscall::do_dup(vm* v) {
    int old_fd = arg_s32(v->r(1));
    if(old_fd < 0) {
        v->r(0) = -EBADF;
        return true;
    }

    auto it = ps->fds.find(old_fd);
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }

    int new_host_fd = dup(it->second->fd);
    if(new_host_fd < 0) {
        v->r(0) = -errno;
        return true;
    }

    int new_fd = allocate_fd();
    ps->fds[new_fd] = std::make_shared<fd_handle>(new_host_fd, it->second->path);
    v->r(0) = new_fd;
    return true;
}

bool PosixSyscall::do_dup3(vm* v) {
    int old_fd = arg_s32(v->r(1));
    int new_fd = arg_s32(v->r(2));
    int flags = arg_s32(v->r(3));
    if(old_fd < 0 || new_fd < 0) {
        v->r(0) = -EBADF;
        return true;
    }
    if(old_fd == new_fd) {
        v->r(0) = -EINVAL;
        return true;
    }
    if(flags & ~O_CLOEXEC) {
        v->r(0) = -EINVAL;
        return true;
    }

    auto it = ps->fds.find(old_fd);
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }

    int new_host_fd = dup(it->second->fd);
    if(new_host_fd < 0) {
        v->r(0) = -errno;
        return true;
    }

    auto handle = std::make_shared<fd_handle>(new_host_fd, it->second->path);
    if(flags & O_CLOEXEC) {
        handle->cloexec = true;
    }
    ps->fds[new_fd] = handle;
    v->r(0) = new_fd;
    return true;
}

bool PosixSyscall::do_pipe2(vm* v) {
    int* pipefd = static_cast<int*>(v->mmu_w(v->r(1), 2 * sizeof(int)));
    if(pipefd == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }

    int flags = arg_s32(v->r(2));
    int host_fds[2] = {-1, -1};

    int rc = pipe2(host_fds, flags);
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
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
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_fchdir(vm* v) {
    int fd = arg_s32(v->r(1));
    auto it = ps->fds.find(fd);
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    struct stat st = {};
    if(fstat(it->second->fd, &st) == -1) {
        v->r(0) = -errno;
        return true;
    }
    if(!S_ISDIR(st.st_mode)) {
        v->r(0) = -ENOTDIR;
        return true;
    }
    if(it->second->path.empty()) {
        v->r(0) = -ENOENT;
        return true;
    }
    ps->cwd = it->second->path;
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_getcwd(vm* v) {
    uint64_t buf_addr = v->r(1);
    size_t size = arg_size(v->r(2));
    if(size == 0) {
        v->r(0) = -ERANGE;
        return true;
    }
    char* buf = static_cast<char*>(v->mmu_w(buf_addr, size));
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    std::string path = ps->cwd.empty() ? "/" : ps->cwd;
    if(size <= path.size()) {
        v->r(0) = -ERANGE;
        return true;
    }
    memcpy(buf, path.c_str(), path.size() + 1);
    v->r(0) = path.size() + 1;
    return true;
}

bool PosixSyscall::do_statx(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int flags = arg_s32(v->r(3));
    unsigned int mask = arg_u32(v->r(4));
    auto out = static_cast<bpf::statx*>(v->mmu_w(v->r(5), sizeof(bpf::statx)));
    if(out == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    /* host struct statx 与 bpf::statx 均源自 Linux UAPI stat.h，布局二进制兼容
     *（同 256 字节、同偏移），故 host statx() 直写后 memcpy 即可，无需逐字段转换。 */
    static_assert(sizeof(bpf::statx) == sizeof(struct statx));
    struct statx stx = {};
    int rc = -1;
    if(dirfd == AT_FDCWD) {
#if defined(__ANDROID__)
        rc = (int)::syscall(SYS_statx, AT_FDCWD, resolve_path(path).c_str(),
                            flags, mask, &stx);
#else
        rc = statx(AT_FDCWD, resolve_path(path).c_str(), flags, mask, &stx);
#endif
    } else {
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
#if defined(__ANDROID__)
        rc = (int)::syscall(SYS_statx, it->second->fd, path.c_str(), flags, mask, &stx);
#else
        rc = statx(it->second->fd, path.c_str(), flags, mask, &stx);
#endif
    }
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    std::memcpy(out, &stx, sizeof(bpf::statx));
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_fchmodat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    mode_t mode = (mode_t)arg_u32(v->r(3));
    int flags = arg_s32(v->r(4));
    int rc = -1;
    if(dirfd == AT_FDCWD) {
        rc = fchmodat(AT_FDCWD, resolve_path(path).c_str(), mode, flags);
    } else {
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        rc = fchmodat(it->second->fd, path.c_str(), mode, flags);
    }
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_utimensat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    bool has_path = (v->r(2) != 0);

    if (has_path) {
        if(!read_c_string(v, v->r(2), path, 4096)) {
            v->r(0) = -EFAULT;
            return true;
        }
    }

    uint64_t times_addr = v->r(3);
    int flags = arg_s32(v->r(4));

    struct timespec pts[2];
    struct timespec* times_ptr = nullptr;

    if (times_addr != 0) {
        int64_t* raw = (int64_t*)v->mmu(times_addr);
        if (raw == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        pts[0].tv_sec = raw[0];
        pts[0].tv_nsec = raw[1];
        pts[1].tv_sec = raw[2];
        pts[1].tv_nsec = raw[3];
        times_ptr = pts;
    }

    int rc = -1;
    if (dirfd == AT_FDCWD) {
        if (!has_path) {
            v->r(0) = -EFAULT;
            return true;
        }
        rc = utimensat(AT_FDCWD, resolve_path(path).c_str(), times_ptr, flags);
    } else {
        auto it = ps->fds.find(dirfd);
        if (it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        // utimensat(2) 允许 path=NULL（配合 AT_EMPTY_PATH 作用于 fd 自身），
        // 但 glibc 头声明为 nonnull，编译器误报，这里局部抑制。
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull"
        rc = utimensat(it->second->fd, has_path ? path.c_str() : nullptr, times_ptr, flags);
#pragma GCC diagnostic pop
    }

    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_faccessat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int mode = arg_s32(v->r(3));
    int flags = arg_s32(v->r(4));

    int rc = -1;
    if (dirfd == AT_FDCWD) {
        rc = faccessat(AT_FDCWD, resolve_path(path).c_str(), mode, flags);
    } else {
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        rc = faccessat(it->second->fd, path.c_str(), mode, flags);
    }

    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_kill(vm* v) {
    int target_pid = arg_s32(v->r(1));
    int sig = arg_s32(v->r(2));
    if(sig < 0 || sig >= NSIG) {
        v->r(0) = -EINVAL;
        return true;
    }

    // 收集目标 task 列表。Linux 语义：
    //   pid > 0  → 指定 task
    //   pid == 0 → 调用者进程组所有 task（含自身）
    //   pid == -1→ 除 pid 1 外所有 task（含自身）
    //   pid < -1 → 进程组 -pid 所有 task
    std::vector<std::shared_ptr<vm>> targets;
    auto pick = [&](const std::shared_ptr<vm>& task_vm) {
        targets.push_back(task_vm);
    };

    if(target_pid > 0) {
        auto t = find_task(static_cast<uint64_t>(target_pid));
        if(t) pick(t);
    } else if(target_pid == 0) {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        for(const auto& entry : pid_map) {
            auto s = sys(entry.second.get());
            if(s && s->pgrp->pgid == pgrp->pgid) {
                pick(entry.second);
            }
        }
    } else if(target_pid == -1) {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        for(const auto& entry : pid_map) {
            auto s = sys(entry.second.get());
            // 跳过 pid 1（init）和调用者自身（Linux kill(-1) 不发给这二者）
            if(s && s->pid != 1 && s->pid != pid) {
                pick(entry.second);
            }
        }
    } else {
        // target_pid < -1：进程组 -pid
        uint64_t target_pgid = static_cast<uint64_t>(-target_pid);
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        for(const auto& entry : pid_map) {
            auto s = sys(entry.second.get());
            if(s && s->pgrp->pgid == target_pgid) {
                pick(entry.second);
            }
        }
    }

    if(targets.empty()) {
        v->r(0) = -ESRCH;
        return true;
    }

    // sig == 0：仅存在性检查，不发信号。
    if(sig == 0) {
        v->r(0) = 0;
        return true;
    }

    for(auto& t : targets) {
        options(t.get()).sys->queue_signal(t.get(), sig);
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_sigaction(vm* v) {
    int signo = arg_s32(v->r(1));
    uint64_t act_addr = v->r(2);
    uint64_t oldact_addr = v->r(3);

    if(signo <= 0 || signo >= NSIG || signo == SIGKILL || signo == SIGSTOP) {
        v->r(0) = -EINVAL;
        return true;
    }

    if(oldact_addr != 0) {
        auto oldact = static_cast<struct bpf::sigaction*>(v->mmu_w(oldact_addr, sizeof(struct bpf::sigaction)));
        if(oldact == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        const auto& current = ps->signal_actions[static_cast<size_t>(signo)];
        oldact->sa_handler = reinterpret_cast<void (*)(int)>(static_cast<uintptr_t>(current.handler));
        oldact->sa_mask = static_cast<bpf::sigset_t>(current.mask);
        oldact->sa_flags = current.flags;
    }

    if(act_addr != 0) {
        auto action = static_cast<const struct bpf::sigaction*>(v->mmu(act_addr));
        if(action == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        if(reinterpret_cast<uintptr_t>(action->sa_handler) == reinterpret_cast<uintptr_t>(SIG_ERR)) {
            v->r(0) = -EINVAL;
            return true;
        }
        auto& current = ps->signal_actions[static_cast<size_t>(signo)];
        current.handler = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(action->sa_handler));
        current.mask = static_cast<uint64_t>(action->sa_mask);
        current.flags = action->sa_flags;
    }

    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_fcntl(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    int cmd = arg_s32(v->r(2));
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        int min_fd = arg_s32(v->r(3));
        if (min_fd < 0) {
            v->r(0) = -EINVAL;
            return true;
        }

        int new_fd = allocate_fd(min_fd);

        int new_host_fd = dup(it->second->fd);
        if(new_host_fd < 0) {
            v->r(0) = -errno;
            return true;
        }

        auto new_handle = std::make_shared<fd_handle>(new_host_fd, it->second->path);
        if (cmd == F_DUPFD_CLOEXEC) {
            new_handle->cloexec = true;
        }
        ps->fds[new_fd] = new_handle;
        v->r(0) = new_fd;
        return true;
    }
    if (cmd == F_GETFD) {
        v->r(0) = it->second->cloexec ? FD_CLOEXEC : 0;
        return true;
    }
    if (cmd == F_SETFD) {
        it->second->cloexec = (v->r(3) & FD_CLOEXEC) != 0;
        v->r(0) = 0;
        return true;
    }

    uint64_t arg = v->r(3);
    int rc = -1;
    if (cmd == F_GETLK) {
            void* guest_arg = v->mmu_w(arg, sizeof(struct flock));
            if(guest_arg == nullptr) {
                v->r(0) = -EFAULT;
                return true;
            }
            rc = fcntl(it->second->fd, cmd, guest_arg);
    } else if (cmd == F_SETLK || cmd == F_SETLKW) {
            void* guest_arg = v->mmu(arg, sizeof(struct flock));
            if(guest_arg == nullptr) {
                v->r(0) = -EFAULT;
                return true;
            }
            rc = fcntl(it->second->fd, cmd, guest_arg);
    } else {
            rc = fcntl(it->second->fd, cmd, arg);
    }

    if(rc == -1) {
        v->r(0) = -errno;
    } else {
        v->r(0) = rc;
    }
    return true;
}

bool PosixSyscall::do_ioctl(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    unsigned long request = v->r(2);
    int rc;

    if (request == TCGETS) {
        struct termios host_t = {};
        rc = ioctl(it->second->fd, TCGETS, &host_t);
        if (rc == 0) {
            auto guest_t = (bpf::termios*)v->mmu_w(v->r(3), sizeof(bpf::termios));
            if (guest_t) {
                guest_t->c_lflag = host_t.c_lflag;
            } else {
                v->r(0) = -EFAULT;
                return true;
            }
        }
    } else if (request == TIOCGWINSZ) {
        void* arg = v->mmu_w(v->r(3), sizeof(struct winsize));
        if(arg == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        rc = ioctl(it->second->fd, TIOCGWINSZ, arg);
    } else {
        // Check if the command has a size field > 0, indicating a pointer argument.
        // Linux ioctl encoding: size is bits 16-29 (14 bits).
        size_t ioctl_size = (request >> 16) & 0x3FFF;
        if (ioctl_size) {
            int dir = _IOC_DIR(request);
            void* arg = (dir & _IOC_READ) ? v->mmu_w(v->r(3), ioctl_size) : v->mmu(v->r(3), ioctl_size);
            if(arg == nullptr) {
                v->r(0) = -EFAULT;
                return true;
            }
            rc = ioctl(it->second->fd, request, arg);
        } else {
            rc = ioctl(it->second->fd, request, (void*)v->r(3));
        }
    }

    if(rc == -1) {
        v->r(0) = -errno;
    } else {
        v->r(0) = rc;
    }
    return true;
}

bool PosixSyscall::do_umask(vm* v) {
    uint32_t new_mask = arg_u32(v->r(1));
    v->r(0) = umask_val;
    umask_val = new_mask & 0777;
    return true;
}

bool PosixSyscall::do_setjmp(vm* v) {
    uint64_t env_addr = v->r(1);
    uint64_t* env = (uint64_t*)v->mmu_w(env_addr, 7 * sizeof(uint64_t));
    if (!env) {
        v->r(0) = -EFAULT;
        return true;
    }
    env[0] = v->r(6);
    env[1] = v->r(7);
    env[2] = v->r(8);
    env[3] = v->r(9);
    env[4] = v->r(10);
    env[5] = pc(v);
    env[6] = signal_depth(v);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_longjmp(vm* v) {
    uint64_t env_addr = v->r(1);
    int32_t val = arg_s32(v->r(2));
    uint64_t* env = (uint64_t*)v->mmu(env_addr);
    if (!env) {
        v->r(0) = -EFAULT;
        return true;
    }
    v->r(6) = env[0];
    v->r(7) = env[1];
    v->r(8) = env[2];
    v->r(9) = env[3];
    v->r(10) = env[4];
    uint64_t saved_pc = env[5];
    signal_depth(v) = static_cast<size_t>(env[6]);
    pc(v) = saved_pc;
    // pc points to syscall instruction.
    // loop increments pc.
    // next instruction is executed.

    v->r(0) = (val == 0) ? 1 : val;
    return true;
}

bool PosixSyscall::do_mprotect(vm* v) {
    uint64_t addr = v->r(1);
    size_t len = arg_size(v->r(2));
    int prot = arg_s32(v->r(3));

    constexpr uint32_t kProtMask = PF_R | PF_W | PF_X;
    uint32_t new_flags = 0;
    if(prot & PROT_READ)  new_flags |= PF_R;
    if(prot & PROT_WRITE) new_flags |= PF_W;
    if(prot & PROT_EXEC)  new_flags |= PF_X;

    auto& ml = maps(v);
    std::lock_guard<std::mutex> lock(*maps_mutex(v));
    for(auto it = ml.begin(); it != ml.end(); ++it) {
        memmap& m = *it;
        // 查找一个完整覆盖 [addr, addr+len) 的映射；跨映射返回 ENOMEM，
        // 与 Linux 语义保持一致（mprotect 不跨 VMA）。
        if(m.paddr > addr || (addr + len) > m.paddr + m.size) {
            continue;
        }
        // 代码段不允许改权限：避免去 PF_X 后绕过宿主保护、加 W 后打宿主只读页。
        if(m.flags & PF_X) {
            v->r(0) = -EACCES;
            return true;
        }
        // 权限与现有 flags 完全相同：no-op。跳过切分与宿主 mprotect，避免把映射
        // 凭空切成三段并建立 cow_data（典型：pthread 栈已是 RW 时再 mprotect RW）。
        // flags/map/host 均未变化，TLB 条目依然有效，无需 flush。
        if(new_flags == (m.flags & kProtMask)) {
            v->r(0) = 0;
            return true;
        }

        // 只对 VM 自有（host mmap 分配）的内存调用宿主 mprotect，让堆保护生效；
        // 借用区（static_map / fork 子 VM / ELF 共享段）的 host_base 不保证按页
        // 对齐也不归本进程拥有，直接动宿主页保护可能误伤邻近内存或返回 EINVAL。
        // guest 视角的权限校验由 mmu/mmu_w 走 m.flags 实现，更新 flags 即足够。
        const bool own_host = m.data.get_deleter().owned;

        // 若 mprotect 的子区间 [addr, addr+len) 严格小于整张映射，必须把映射按
        // [m.paddr, addr) / [addr, addr+len) / [addr+len, end) 切成至多三段——否则
        // 整张 map.flags 会被改成 new_flags，但宿主只 mprotect 了子区间，余下段
        // （典型：pthread 栈的 PROT_NONE guard 页）host 保护未变。fork 后子 VM 对
        // 这张 map 做 CoW 深拷贝时 memcpy 会读到 guard 的 PROT_NONE 页 → 段错误。
        // 切分后 guard 段成为独立 map（flags 不含 PF_W，不触发 CoW），可写段 host
        // 已 mprotect 为可读，CoW 安全。各段共享同一 cow_data 管理宿主生命周期。
        const uint64_t mid_lo = addr;
        const uint64_t mid_hi = addr + len;
        const bool need_split = (m.paddr < mid_lo) || (mid_hi < m.paddr + m.size);

        if(need_split) {
            // 切分前先把整段宿主纳入 cow_data（同 do_clone 做法），让三段非拥有子映射
            // 共享同一控制块；否则切出的子段无人持有宿主所有权会泄漏。
            if(!m.cow_data && own_host) {
                m.cow_data = std::shared_ptr<unsigned char>(
                    m.data.get(), DataDeleter{m.data.get_deleter().size, true});
                m.data.get_deleter().owned = false;
            }
            unsigned char* base = m.data.get();
            std::shared_ptr<unsigned char> cb = m.cow_data;

            memmap left, mid, right;
            if(m.paddr < mid_lo) {
                left.paddr = m.paddr;
                left.size = mid_lo - m.paddr;
                left.flags = m.flags;
                left.set_data(base, left.size, false);
                left.cow_data = cb;
            }
            mid.paddr = mid_lo;
            mid.size = mid_hi - mid_lo;
            mid.flags = (m.flags & ~kProtMask) | new_flags;
            mid.set_data(base + (mid_lo - m.paddr), mid.size, false);
            mid.cow_data = cb;
            if(mid_hi < m.paddr + m.size) {
                right.paddr = mid_hi;
                right.size = (m.paddr + m.size) - mid_hi;
                right.flags = m.flags;
                right.set_data(base + (mid_hi - m.paddr), right.size, false);
                right.cow_data = cb;
            }

            // 宿主 mprotect：仅对 mid 段，与原行为一致（自有内存才动宿主保护）。
            if(own_host) {
                unsigned char* host_base = base + (mid_lo - m.paddr);
                if(mprotect(host_base, mid.size, prot) == -1) {
                    v->r(0) = -errno;
                    return true;
                }
            }

            it = ml.erase(it);
            if(right.size) it = ml.insert(it, std::move(right));
            it = ml.insert(it, std::move(mid));
            if(left.size) it = ml.insert(it, std::move(left));
        } else {
            if(own_host) {
                unsigned char* host_base = m.data.get() + (addr - m.paddr);
                if(mprotect(host_base, len, prot) == -1) {
                    v->r(0) = -errno;
                    return true;
                }
            }
            m.flags = (m.flags & ~kProtMask) | new_flags;
        }
        v->flush_tlb();
        v->r(0) = 0;
        return true;
    }
    v->r(0) = -ENOMEM;
    return true;
}

bool PosixSyscall::do_readv(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    int iovcnt = arg_s32(v->r(3));
    if(iovcnt <= 0) {
        v->r(0) = (iovcnt == 0) ? 0 : -EINVAL;
        return true;
    }
    auto guest_vec = static_cast<bpf::iovec*>(v->mmu(v->r(2), sizeof(bpf::iovec) * iovcnt));
    if(guest_vec == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    // 把 guest 的 iov 翻译成宿主 iovec：iov_base 走 mmu_w 转成 host 指针。
    // 这样宿主 readv 一次性按 iov 顺序填充，跨 iov 的短读/EOF 语义与内核一致。
    std::vector<iovec> host_vec;
    host_vec.reserve(iovcnt);
    for(int i = 0; i < iovcnt; ++i) {
        size_t len = (size_t)guest_vec[i].iov_len;
        if(len == 0) continue;
        void* buf = v->mmu_w((uint64_t)guest_vec[i].iov_base, len);
        if(buf == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        host_vec.push_back({buf, len});
    }
    if(host_vec.empty()) {
        v->r(0) = 0;
        return true;
    }
    ssize_t rc = readv(it->second->fd, host_vec.data(), (int)host_vec.size());
    if(rc < 0) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = (uint64_t)rc;
    return true;
}

bool PosixSyscall::do_writev(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    int iovcnt = arg_s32(v->r(3));
    if(iovcnt <= 0) {
        v->r(0) = (iovcnt == 0) ? 0 : -EINVAL;
        return true;
    }
    auto guest_vec = static_cast<bpf::iovec*>(v->mmu(v->r(2), sizeof(bpf::iovec) * iovcnt));
    if(guest_vec == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    // 把 guest 的 iov 翻译成宿主 iovec：iov_base 走 mmu 转成 host 指针（只读即可）。
    // 这样宿主 writev 一次性按 iov 顺序输出，短写语义与内核一致。
    std::vector<iovec> host_vec;
    host_vec.reserve(iovcnt);
    for(int i = 0; i < iovcnt; ++i) {
        size_t len = (size_t)guest_vec[i].iov_len;
        if(len == 0) continue;
        void* buf = v->mmu((uint64_t)guest_vec[i].iov_base, len);
        if(buf == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        host_vec.push_back({buf, len});
    }
    if(host_vec.empty()) {
        v->r(0) = 0;
        return true;
    }
    ssize_t rc = writev(it->second->fd, host_vec.data(), (int)host_vec.size());
    if(rc < 0) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = (uint64_t)rc;
    return true;
}

bool PosixSyscall::do_pread(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu_w(v->r(2), count);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    off_t off = (off_t)v->r(4);
    ssize_t rc = pread(it->second->fd, buf, count, off);
    if(rc < 0) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = (uint64_t)rc;
    return true;
}

bool PosixSyscall::do_pwrite(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu(v->r(2), count);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    off_t off = (off_t)v->r(4);
    ssize_t rc = pwrite(it->second->fd, buf, count, off);
    if(rc < 0) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = (uint64_t)rc;
    return true;
}

bool PosixSyscall::do_getrandom(vm* v) {
    size_t buflen = arg_size(v->r(2));
    if(buflen == 0) {
        v->r(0) = 0;
        return true;
    }
    void* buf = v->mmu_w(v->r(1), buflen);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    unsigned int flags = (unsigned int)arg_u32(v->r(3));
    // 用 syscall(SYS_getrandom) 而非 libc wrapper：bionic 的 getrandom() 是
    // __INTRODUCED_IN(28)，在 target API < 28（如 Termux 默认）时声明被隐藏。
    ssize_t rc = ::syscall(SYS_getrandom, buf, buflen, flags);
    if(rc < 0) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = (uint64_t)rc;
    return true;
}

bool PosixSyscall::do_getdents64(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    size_t count = arg_size(v->r(3));
    if(count == 0) {
        v->r(0) = -EINVAL;
        return true;
    }
    void* buf = v->mmu_w(v->r(2), count);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    int rc = (int)::syscall(SYS_getdents64, it->second->fd, buf, (int)count);
    if(rc < 0) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = (uint64_t)rc;
    return true;
}

bool PosixSyscall::do_set_tid_address(vm* v) {
    tid_address_ = v->r(1);
    // 这里返回 PID，让 musl __init_libc 认为 tid_address 已注册即可。
    v->r(0) = pid;
    return true;
}


bool PosixSyscall::do_madvise(vm* v) {
    // 主要用于 malloc MADV_DONTNEED；缺省语义可忽略。
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_sched_yield(vm* v) {
    sched_yield();
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_gettid(vm* v) {
    // 单线程进程语义下 gettid == getpid；fork 出去的子 VM 也是各自独立单线程，
    // 同样满足 gettid==getpid。
    v->r(0) = pid;
    return true;
}

bool PosixSyscall::do_set_tls(vm* v) {
    // 设置 thread pointer（musl __init_tp → __set_thread_area 在启动时调用）。
    // BPF 无 TLS 寄存器，用一个 VM 字段 tp_ 模拟；guest 侧 __get_tp() 经
    // BPF_SYS_GET_TLS 读回同一值。
    // 必须返回 0（成功），否则 musl __init_tls.c:149 会 a_crash()。
    tp(v) = v->r(1);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_get_tls(vm* v) {
    // 读取 thread pointer（guest 侧 __get_tp 用）。单线程下调用稀疏
    // （stdio getc/putc 热路径因 f->lock==0 短路，不触发 __pthread_self）。
    v->r(0) = tp(v);
    return true;
}

// 唤醒 addr 上最多 val 个等待者。返回实际唤醒数。
int PosixSyscall::futex_wake(ThreadGroup* tg, uint64_t addr, int val) {
    if(val <= 0) {
        return 0;
    }
    std::lock_guard<std::mutex> lock(g_futex_mutex);
    auto it = g_futex_table.find({tg, addr});
    if(it == g_futex_table.end() || it->second.waiters.empty()) {
        return 0;
    }
    int woken = std::min((int)it->second.waiters.size(), val);
    for(int i = 0; i < woken; i++) {
        vm* w = it->second.waiters.back();
        it->second.waiters.pop_back();
        w->unblock();
    }
    if(it->second.waiters.empty()) g_futex_table.erase(it);
    return woken;
}

// 在 addr 上等待：*addr == val 则阻塞，否则 -EAGAIN。被 futex 唤醒返回 0；被 kill/信号
// 打断返回 -EINTR；超时返回 -ETIMEDOUT。
int PosixSyscall::futex_wait(vm* v, ThreadGroup* tg, uint64_t addr, uint32_t val,
                             const struct timespec* timeout) {
    auto* p = static_cast<uint32_t*>(v->mmu(addr, sizeof(uint32_t)));
    if(!p) return -EFAULT;

    {
        // 注册 + *p 检查原子（持 g_futex_mutex），经典 futex 正确性论证成立：要么 *p 已变
        // （musl 在 wake 前改值）→ EAGAIN；要么注册后 wake 必命中本等待者（waker 在同一把
        // 锁下遍历 waiters 列表）。置 VM_BLOCKED 与注册同在锁内，外部 waker 才看得到。
        std::lock_guard<std::mutex> flk(g_futex_mutex);
        if(*p != val) return -EAGAIN;
        auto it = g_futex_table.try_emplace(std::make_pair(tg, addr)).first;
        it->second.waiters.push_back(v);
        flags(v).fetch_or(vm::VM_BLOCKED, std::memory_order_release);
    }

    // 阻塞在 vm 自身 exit_cv 上
    int rc = v->wait_for(timeout);

    // 退出清理：摘自己（被 wake 路径 waker 已摘；kill/超时/信号路径这里摘）+ 清 VM_BLOCKED
    // （被 wake 路径外部已清，此处幂等）。仅取 g_futex_mutex，无嵌套锁。
    {
        std::lock_guard<std::mutex> flk(g_futex_mutex);
        futex_detach(tg, addr, v);
        flags(v).fetch_and(~vm::VM_BLOCKED, std::memory_order_release);
    }
    return rc;
}

bool PosixSyscall::do_futex(vm* v) {
    uint64_t uaddr = v->r(1);
    int op = arg_s32(v->r(2));
    uint32_t val = (uint32_t)v->r(3);
    uint64_t timeout_ptr = v->r(4);
    uint64_t uaddr2 = v->r(5);
    uint64_t val3 = v->r(0);  // 第 6 参走 r0（BpfWideArgs syscall 6 参路径）

    if((uaddr & 0x3) != 0) {
        v->r(0) = -EINVAL;
        return true;
    }

    int op_base = op & ~FUTEX2_PRIVATE;
    const struct timespec* timeout = nullptr;
    struct timespec ts_buf;
    if(timeout_ptr != 0 && (op_base == FUTEX_WAIT)) {
        const struct timespec* gts = static_cast<const struct timespec*>(
            v->mmu(timeout_ptr, sizeof(struct timespec)));
        if(!gts) {
            v->r(0) = -EFAULT;
            return true;
        }
        ts_buf = *gts;
        timeout = &ts_buf;
    }

    switch(op_base) {
    case FUTEX_WAIT: {
        int rc = futex_wait(v, tg.get(), uaddr, val, timeout);
        v->r(0) = (uint64_t)(int64_t)rc;
        return true;
    }
    case FUTEX_WAKE: {
        int woken = futex_wake(tg.get(), uaddr, (int)val);
        v->r(0) = (uint64_t)woken;
        return true;
    }
    case FUTEX_REQUEUE: {
        // 简化：唤醒 addr 上所有等待者（忽略 requeue 到 uaddr2）。
        // musl condvar 用 FUTEX_REQUEUE 避免 thundering herd；全唤醒正确但效率低。
        (void)uaddr2; (void)val3;
        int woken = futex_wake(tg.get(), uaddr, 0x10000);
        v->r(0) = (uint64_t)woken;
        return true;
    }
    default:
        // PI 系列（LOCK_PI/UNLOCK_PI 等）及 WAKE_OP 暂不支持，返回 -ENOSYS 让 musl 降级。
        v->r(0) = -ENOSYS;
        return true;
    }
}

bool PosixSyscall::do_tkill(vm* v) {
    int tid = arg_s32(v->r(1));
    int sig = arg_s32(v->r(2));
    if(sig < 0 || sig >= NSIG || tid <= 0) {
        v->r(0) = -EINVAL;
        return true;
    }
    auto target_vm = find_task(static_cast<uint64_t>(tid));
    if(!target_vm) {
        v->r(0) = -ESRCH;
        return true;
    }
    if(sig == 0) {
        v->r(0) = 0;
        return true;
    }
    options(target_vm.get()).sys->queue_signal(target_vm.get(), sig);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_tgkill(vm* v) {
    int tgid_arg = arg_s32(v->r(1));
    int tid = arg_s32(v->r(2));
    int sig = arg_s32(v->r(3));
    if(sig < 0 || sig >= NSIG || tid <= 0 || tgid_arg <= 0) {
        v->r(0) = -EINVAL;
        return true;
    }
    auto target_vm = find_task(static_cast<uint64_t>(tid));
    if(!target_vm) {
        v->r(0) = -ESRCH;
        return true;
    }
    auto target = sys(target_vm.get());
    if(!target || target->tg->tgid != static_cast<uint64_t>(tgid_arg)) {
        v->r(0) = -ESRCH;
        return true;
    }
    if(sig == 0) {
        v->r(0) = 0;
        return true;
    }
    options(target_vm.get()).sys->queue_signal(target_vm.get(), sig);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::syscall(vm* v, uint32_t call) {
    uint32_t sys_id = call;
    if(call >= BPF_CALL_BASE) {
        sys_id = BPF_CALL_TO_ID(call);
    }
    switch (sys_id) {
    case BPF_SYS_MMAP:          return do_mmap(v);
    case BPF_SYS_MUNMAP:        return do_munmap(v);
    case BPF_SYS_EXIT:          return do_exit(v);
    case BPF_SYS_EXIT_GROUP:    return do_exit_group(v);
    case BPF_SYS_NANOSLEEP:     return do_nanosleep(v);
    case BPF_SYS_OPENAT:        return do_openat(v);
    case BPF_SYS_READ:          return do_read(v);
    case BPF_SYS_WRITE:         return do_write(v);
    case BPF_SYS_LSEEK:         return do_lseek(v);
    case BPF_SYS_TRUNCATE:      return do_truncate(v);
    case BPF_SYS_FTRUNCATE:     return do_ftruncate(v);
    case BPF_SYS_CLOSE:         return do_close(v);
    case BPF_SYS_UNLINKAT:      return do_unlinkat(v);
    case BPF_SYS_MKDIRAT:       return do_mkdirat(v);
    case BPF_SYS_SYMLINKAT:     return do_symlinkat(v);
    case BPF_SYS_LINKAT:        return do_linkat(v);
    case BPF_SYS_RENAMEAT2:     return do_renameat2(v);
    case BPF_SYS_READLINKAT:    return do_readlinkat(v);
    case BPF_SYS_EXECVE:        return do_execve(v);
    case BPF_SYS_CLONE:         return do_clone(v);
    case BPF_SYS_GETPID:        return do_getpid(v);
    case BPF_SYS_GETPPID:       return do_getppid(v);
    case BPF_SYS_WAITPID:       return do_waitpid(v);
    case BPF_SYS_DUP:           return do_dup(v);
    case BPF_SYS_DUP3:          return do_dup3(v);
    case BPF_SYS_PIPE2:         return do_pipe2(v);
    case BPF_SYS_FCHDIR:        return do_fchdir(v);
    case BPF_SYS_GETCWD:        return do_getcwd(v);
    case BPF_SYS_STATX:         return do_statx(v);
    case BPF_SYS_FCHMODAT:      return do_fchmodat(v);
    case BPF_SYS_UTIMENSAT:     return do_utimensat(v);
    case BPF_SYS_FACCESSAT:     return do_faccessat(v);
    case BPF_SYS_KILL:          return do_kill(v);
    case BPF_SYS_TKILL:         return do_tkill(v);
    case BPF_SYS_TGKILL:        return do_tgkill(v);
    case BPF_SYS_SIGACTION:     return do_sigaction(v);
    case BPF_SYS_SETPGID:       return do_setpgid(v);
    case BPF_SYS_GETPGID:       return do_getpgid(v);
    case BPF_SYS_GETPGRP:       return do_getpgrp(v);
    case BPF_SYS_SETSID:        return do_setsid(v);
    case BPF_SYS_GETSID:        return do_getsid(v);
    case BPF_SYS_FCNTL:         return do_fcntl(v);
    case BPF_SYS_IOCTL:         return do_ioctl(v);
    case BPF_SYS_UMASK:         return do_umask(v);
    case BPF_SYS_SETJMP:        return do_setjmp(v);
    case BPF_SYS_LONGJMP:       return do_longjmp(v);
    case BPF_SYS_CLOCK_GETTIME: return do_clock_gettime(v);
    // —— musl/libc 兼容性补充 ——
    case BPF_SYS_MPROTECT:       return do_mprotect(v);
    case BPF_SYS_READV:          return do_readv(v);
    case BPF_SYS_WRITEV:         return do_writev(v);
    case BPF_SYS_PREAD:          return do_pread(v);
    case BPF_SYS_PWRITE:         return do_pwrite(v);
    case BPF_SYS_GETRANDOM:      return do_getrandom(v);
    case BPF_SYS_GETDENTS64:     return do_getdents64(v);
    case BPF_SYS_SET_TID_ADDRESS:return do_set_tid_address(v);
    case BPF_SYS_MADVISE:        return do_madvise(v);
    case BPF_SYS_SCHED_YIELD:    return do_sched_yield(v);
    case BPF_SYS_GETTID:         return do_gettid(v);
    case BPF_SYS_SET_TLS:        return do_set_tls(v);
    case BPF_SYS_GET_TLS:        return do_get_tls(v);
    case BPF_SYS_FUTEX:          return do_futex(v);
    default:
        /* 未实现的 syscall（包括 musl 移植用 BPF_CALL_BASE 占位的 brk/mremap/futex
         * 等探测型调用）。统一返回 -ENOSYS，让 musl 走兜底/降级路径。仅在 BPF_DEBUG
         * 时打印，避免每次启动刷屏（这些调用大多 musl 会主动忽略返回值）。 */
        if (getenv("BPF_DEBUG"))
            fprintf(stderr, "unsupported func: 0x%x\n", call);
        v->r(0) = -ENOSYS;
        return true;
    }
}
