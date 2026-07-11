#include "posix_internal.h"

// futex 等待桶：每个 (地址空间, guest addr) 一个 bucket，持有等待者 vm* 列表。
// 地址空间用 ThreadGroup 裸指针标识（CLONE_VM 线程共享 tg；fork 后不同 tg 即不同地址空间）。
//
// 列表里的 vm* 必然存活：拥有它的线程正阻塞在 futex_wait 内，未跑 fini，vm 不会析构；
// 等待者返回前必先把自己摘掉（被 wakeup(true) 路径由 waker 摘，kill/超时/信号路径自己摘），故列表
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

// clear-child-tid 路径：持 g_futex_mutex 清零 *ctid（host 指针已由调用方 mmu_w 取得），
// 再从 tid_address 的等待桶摘一个等待者唤醒。
// 被封装在这里（而非 posix_syscall.cpp 的 fini 内联）是因为 g_futex_* 是本文件 static。
void futex_child_tid_clear(ThreadGroup* tg, int* ctid, uint64_t tid_address) {
    std::lock_guard<std::mutex> flock(g_futex_mutex);
    *ctid = 0;
    auto it = g_futex_table.find({tg, tid_address});
    if(it == g_futex_table.end() || it->second.waiters.empty()) {
        return;
    }
    vm* w = it->second.waiters.back();
    it->second.waiters.pop_back();
    if(it->second.waiters.empty()) g_futex_table.erase(it);
    w->wakeup(true);
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
        w->wakeup(true);
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

    int rc = v->wait_for(timeout);

    // 退出清理：摘自己（被 wake 路径 waker 已摘；kill/超时/信号路径这里摘）+ 清 VM_BLOCKED
    // （被 wake 路径外部已清，此处幂等）。仅取 g_futex_mutex，无嵌套锁。
    {
        std::lock_guard<std::mutex> flk(g_futex_mutex);
        futex_detach(tg, addr, v);
        flags(v).fetch_and(~vm::VM_BLOCKED, std::memory_order_release);
    }
    // 对齐 Linux 内核 FUTEX_WAIT 的 ERESTARTSYS 语义。超时（-ETIMEDOUT）/唤醒（0）原样返回。
    if(rc == -EINTR) {
        return SYSCALL_RESTART;
    }
    return rc;
}

int64_t PosixSyscall::do_futex(vm* v) {
    uint64_t uaddr = v->r(1);
    int op = arg_s32(v->r(2));
    uint32_t val = (uint32_t)v->r(3);
    uint64_t timeout_ptr = v->r(4);
    uint64_t uaddr2 = v->r(5);
    uint64_t val3 = v->r(0);  // 第 6 参走 r0（BpfWideArgs syscall 6 参路径）

    if((uaddr & 0x3) != 0) {
        return -EINVAL;
    }

    int op_base = op & ~FUTEX2_PRIVATE;
    const struct timespec* timeout = nullptr;
    struct timespec ts_buf;
    if(timeout_ptr != 0 && (op_base == FUTEX_WAIT)) {
        const struct timespec* gts = static_cast<const struct timespec*>(
            v->mmu(timeout_ptr, sizeof(struct timespec)));
        if(!gts) {
            return -EFAULT;
        }
        ts_buf = *gts;
        timeout = &ts_buf;
    }

    switch(op_base) {
    case FUTEX_WAIT: {
        return futex_wait(v, tg.get(), uaddr, val, timeout);
    }
    case FUTEX_WAKE: {
        return futex_wake(tg.get(), uaddr, (int)val);
    }
    case FUTEX_REQUEUE: {
        // 简化：唤醒 addr 上所有等待者（忽略 requeue 到 uaddr2）。
        // musl condvar 用 FUTEX_REQUEUE 避免 thundering herd；全唤醒正确但效率低。
        (void)uaddr2; (void)val3;
        return futex_wake(tg.get(), uaddr, 0x10000);
    }
    default:
        // PI 系列（LOCK_PI/UNLOCK_PI 等）及 WAKE_OP 暂不支持，返回 -ENOSYS 让 musl 降级。
        return -ENOSYS;
    }
}
