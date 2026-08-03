#include "posix_internal.h"
#include <iostream>
#include <algorithm>

// 在 maps（vector）里对 [base, end) 打洞：把所有与之重叠的 memmap 切成至多三段，
// 保留不重叠的左 [paddr,base) / 右 [end, paddr+size) 两段，删掉中间重叠段。
// host 内存经 cow_data 共享（同 do_mprotect 的切分模式），避免双重释放。
// 供 MAP_FIXED（do_mmap）按 Linux 语义打洞用。
static void punch_hole(std::vector<memmap>& ml, uint64_t base, uint64_t end) {
    std::vector<memmap> out;
    out.reserve(ml.size());
    for (auto& m : ml) {
        if (end <= m.paddr || base >= m.paddr + m.size) {  // 不重叠，原样保留
            out.push_back(std::move(m));
            continue;
        }
        const bool own_host = m.data.get_deleter().owned;
        if (!m.cow_data && own_host) {
            m.cow_data = std::shared_ptr<unsigned char>(
                m.data.get(), DataDeleter{m.data.get_deleter().size, true});
            m.data.get_deleter().owned = false;
        }
        unsigned char* hbase = m.data.get();
        std::shared_ptr<unsigned char> cb = m.cow_data;
        const uint32_t fl = m.flags;
        const uint64_t m_end = m.paddr + m.size;
        // 左段（保留不重叠的左侧）
        if (m.paddr < base) {
            memmap left;
            left.paddr = m.paddr;
            left.size = base - m.paddr;
            left.flags = fl;
            left.set_data(hbase, left.size, false);
            left.cow_data = cb;
            left.path = m.path;
            out.push_back(std::move(left));
        }
        // 右段（保留不重叠的右侧）
        if (end < m_end) {
            memmap right;
            right.paddr = end;
            right.size = m_end - end;
            right.flags = fl;
            right.set_data(hbase + (end - m.paddr), right.size, false);
            right.cow_data = cb;
            right.path = m.path;
            out.push_back(std::move(right));
        }
        // 重叠段丢弃（m 析构时若仍 own host 会 munmap；上面已把 owned 置 false）
    }
    ml = std::move(out);
}

int64_t PosixSyscall::do_mmap(vm* v) {
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
        return -EINVAL;
    }

    const bool fixed = flags & MAP_FIXED;
    if (fixed && (addr_hint % PAGE) != 0) {
        return -EINVAL;   // MAP_FIXED 要求 addr 页对齐
    }

    std::string path;
    int host_fd = -1;
    if (!(flags & MAP_ANONYMOUS)) {
        auto h = ps->find_fd(fd);
        if(!h) {
            return -EBADF;
        }
        host_fd = h->host_fd();
        path = h->path;
    }

    // host 内存始终独立分配（addr_hint 是 guest 空间地址，与 host 无关；host 端不
    // 用 MAP_FIXED，避免 guest 间接控制 host 地址布局）。
    void* addr = mmap(nullptr, len, prot, flags & ~MAP_FIXED, host_fd, offset);
    if(addr == MAP_FAILED) {
        return -errno;
    }

    // MAP_FIXED：按 Linux 语义先 unmap 与 [addr_hint, addr_hint+len) 重叠的旧 guest
    // 映射——对部分重叠的段要切分（打洞），保留不重叠的左/右两段，不能整段删掉。
    if (fixed) {
        const uint64_t base = addr_hint;
        const uint64_t end = addr_hint + len;
        auto& ml = maps(v);
        std::lock_guard<std::mutex> lock(*maps_mutex(v));
        punch_hole(ml, base, end);
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
    mem.path = path;
    int64_t result;
    if (fixed) {
        mem.paddr = addr_hint;   // guest 空间固定地址
        result = (int64_t)mem.paddr;
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
        result = (int64_t)mem.paddr;
        auto it = ml.begin();
        while(it != ml.end() && it->paddr < mem.paddr) {
            it++;
        }
        ml.insert(it, std::move(mem));
    }
    v->flush_tlb();
    return result;
}

int64_t PosixSyscall::do_munmap(vm* v) {
    if(!v->unmap(v->r(1))) {
        return -EINVAL;
    }
    return 0;
}

int64_t PosixSyscall::do_mprotect(vm* v) {
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
    const uint64_t range_lo = addr;
    const uint64_t range_hi = addr + len;
    bool any = false;
    // 遍历所有与 [addr, addr+len) 重叠的映射，逐一应用权限（Linux mprotect 可跨多个
    // VMA）。guest ldso 的 DT_TEXTREL 对整模块 mprotect(map, map_len, RWX)，此时模块
    // 已被 map_library 的 mmap_fixed 切成 text/rodata/data 多段，必须跨段处理。
    for (size_t i = 0; i < ml.size(); ) {
        memmap& m = ml[i];
        if (range_hi <= m.paddr || range_lo >= m.paddr + m.size) { ++i; continue; }  // 不重叠
        // 子区间 = 本 map 与请求范围的交集
        uint64_t sub_lo = std::max(range_lo, m.paddr);
        uint64_t sub_hi = std::min(range_hi, m.paddr + m.size);
        // 不允许去掉可执行（安全）：text 段不能改成非 X。但允许加 W（TEXTREL 需要
        // 给 text 加 W 写 lddw imm）；原「PF_X 段一律拒绝」过严，会挡掉 TEXTREL。
        if ((m.flags & PF_X) && !(new_flags & PF_X)) {
            return -EACCES;
        }
        any = true;
        const bool own_host = m.data.get_deleter().owned;
        const bool need_split = (m.paddr < sub_lo) || (sub_hi < m.paddr + m.size);
        if (need_split) {
            if (!m.cow_data && own_host) {
                m.cow_data = std::shared_ptr<unsigned char>(
                    m.data.get(), DataDeleter{m.data.get_deleter().size, true});
                m.data.get_deleter().owned = false;
            }
            unsigned char* base = m.data.get();
            std::shared_ptr<unsigned char> cb = m.cow_data;
            memmap left, mid, right;
            if (m.paddr < sub_lo) {
                left.paddr = m.paddr;
                left.size = sub_lo - m.paddr;
                left.flags = m.flags;
                left.set_data(base, left.size, false);
                left.cow_data = cb;
            }
            mid.paddr = sub_lo;
            mid.size = sub_hi - sub_lo;
            mid.flags = (m.flags & ~kProtMask) | new_flags;
            mid.set_data(base + (sub_lo - m.paddr), mid.size, false);
            mid.cow_data = cb;
            if (sub_hi < m.paddr + m.size) {
                right.paddr = sub_hi;
                right.size = (m.paddr + m.size) - sub_hi;
                right.flags = m.flags;
                right.set_data(base + (sub_hi - m.paddr), right.size, false);
                right.cow_data = cb;
            }
            if (own_host) {
                unsigned char* host_base = base + (sub_lo - m.paddr);
                if (mprotect(host_base, mid.size, prot) == -1) {
                    return -errno;
                }
            }
            // 用「构造新 vector」式替换，避免 vector insert/erase 的迭代器失效
            // 顺序：left（若有）→ mid → right（若有），保持 paddr 升序（尾部分配器
            // ml.back() 依赖有序，否则 mmap 地址碰撞）。
            std::vector<memmap> rebuilt;
            rebuilt.reserve(ml.size() + 2);
            for (size_t j = 0; j < ml.size(); ++j) {
                if (j == i) {
                    if (left.size)  rebuilt.push_back(std::move(left));
                    rebuilt.push_back(std::move(mid));
                    if (right.size) rebuilt.push_back(std::move(right));
                } else {
                    rebuilt.push_back(std::move(ml[j]));
                }
            }
            ml = std::move(rebuilt);
            i = 0;  // 重建后从头扫（N 通常 <100，开销可忽略）
        } else {
            // 整张 map 都在范围内
            if (new_flags == (m.flags & kProtMask)) { ++i; continue; }  // no-op
            if (own_host) {
                if (mprotect(m.data.get(), m.size, prot) == -1) {
                    return -errno;
                }
            }
            m.flags = (m.flags & ~kProtMask) | new_flags;
            ++i;
        }
    }
    v->flush_tlb();
    return any ? 0 : -ENOMEM;
}

int64_t PosixSyscall::do_madvise(vm*) {
    // 主要用于 malloc MADV_DONTNEED；缺省语义可忽略。
    return 0;
}
