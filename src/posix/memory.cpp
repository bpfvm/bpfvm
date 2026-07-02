#include "posix_internal.h"

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

bool PosixSyscall::do_madvise(vm* v) {
    // 主要用于 malloc MADV_DONTNEED；缺省语义可忽略。
    v->r(0) = 0;
    return true;
}
