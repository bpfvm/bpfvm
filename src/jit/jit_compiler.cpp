//
// jit_compiler.cpp — JitCompiler template implementation + helper functions.
//

#include "jit_compiler.h"
#include "insn.h"

#include <queue>
#include <chrono>
#include <cstdio>

#if defined(__x86_64__)
#include "x86_emitter.h"
#elif defined(__aarch64__)
#include "aarch64_emitter.h"
#endif

// ---------------------------------------------------------------------------
// JitCompiler implementation
// ---------------------------------------------------------------------------

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winvalid-offsetof"
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_reg_            = offsetof(vm, reg);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_pc_             = offsetof(vm, pc_);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_flags_          = offsetof(vm, flags);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_tlb_            = offsetof(vm, tlb);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_insn_count_     = offsetof(vm, insn_count);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_insn_limit_     = offsetof(vm, options) + offsetof(vmOptions, insn_limit);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_stack_limit_    = offsetof(vm, options) + offsetof(vmOptions, stack_limit);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_scratch_        = offsetof(vm, jit_scratch);
#pragma GCC diagnostic pop

template<typename EmitterT>
JitCompiler<EmitterT>::JitCompiler() {
    const char* env = getenv("JIT_ENABLE");
    enabled_ = (env == nullptr || strcmp(env, "0") != 0);
    if (const char* e = getenv("JIT_THRESHOLD")) threshold_ = (uint32_t)atoi(e);
    debug_enabled_ = getenv("BPF_DEBUG");
    jit_dump_enabled_ = getenv("BPF_JIT_DUMP") != nullptr;
    failed_sentinel_.kind = JitEntryKind::Failed;

    helpers_.safepoint        = (void*)&helper_safepoint;
    helpers_.push_frame       = (void*)&helper_push_frame;
    helpers_.pop_frame        = (void*)&helper_pop_frame;
    helpers_.do_syscall       = (void*)&helper_do_syscall;
    helpers_.do_softfp        = (void*)&helper_do_softfp;
    helpers_.call_indirect    = (void*)&helper_call_indirect;
    helpers_.call_indirect_ic = (void*)&helper_call_indirect_ic;
    helpers_.call_bpf         = (void*)&helper_call_bpf;
    helpers_.return_to_caller = (void*)&helper_return_to_caller;
    helpers_.resolve_and_cache = (void*)&helper_resolve_and_cache;
    helpers_.mmu              = (void*)&helper_mmu;
    helpers_.mmu_w            = (void*)&helper_mmu_w;
}

template<typename EmitterT>
JitCompiler<EmitterT>::~JitCompiler() {
    // code 都在 arena 内，逐条 munmap 会截断整块映射；这里整块释放。
    for (auto& a : arenas_) munmap(a.base, a.size);
    arenas_.clear();
}

// ---------------------------------------------------------------------------
// JIT control-flow helpers (called from JIT-generated code)
// ---------------------------------------------------------------------------

template<typename EmitterT>
int JitCompiler<EmitterT>::helper_safepoint(vm* v) {
    uint64_t saved_pc = v->pc_;
    if (!v->safepoint()) {
        return 1;
    }
    if (v->pc_ != saved_pc) {
        return 1;
    }
    return 0;
}

template<typename EmitterT>
bool JitCompiler<EmitterT>::helper_push_frame(vm* v, uint64_t ret_addr) {
    return v->push_frame(ret_addr);
}

template<typename EmitterT>
uint64_t JitCompiler<EmitterT>::helper_pop_frame(vm* v) {
    return v->pop_frame();
}

template<typename EmitterT>
bool JitCompiler<EmitterT>::helper_do_syscall(vm* v, uint32_t call_id) {
    uint64_t saved_pc = v->pc_;
    // do_syscall 内部已检测 VM_EXITED|VM_KILLED 并据此返回 false，无需在此补设 flag。
    if (!v->do_syscall(call_id)) {
        if (v->pc_ == saved_pc) v->pc_ += sizeof(bpf_insn);
        return false;
    }
    if (v->pc_ != saved_pc) {
        // pc 被改（如 longjmp）。置 VM_JIT_ABORT，让调用链各层 .cont 的 flag-check
        // 级联 vm_exit，最终由 step() 接管新 pc。safepoint() 清此位。
        v->flags.fetch_or(vm::VM_JIT_ABORT, std::memory_order_release);
        v->pc_ += sizeof(bpf_insn);
        return false;
    }
    // ERESTARTSYS：可重启 syscall 被信号打断。pc 保持 = saved_pc（syscall 指令）,不推进
    // 此判定必须在下面"推进 pc"的 flag 退出分支之前：重启场景下 VM_SIGNAL_PENDING
    // 必然同时置位（信号入队即设），若先命中则会错误推进 pc。
    if (v->restart_syscall_pc_ != 0) {
        return false;
    }
    // 其余 flag（退出/被杀/停止/待决信号）一律推进 pc 越过 syscall 指令并退出 JIT：
    uint32_t f = v->flags.load(std::memory_order_acquire);
    if (f & (vm::VM_EXITED | vm::VM_KILLED | vm::VM_STOPPED | vm::VM_SIGNAL_PENDING)) {
        v->pc_ += sizeof(bpf_insn);
        return false;
    }
    return true;
}

// FP 虚拟指令的 JIT 回退：do_softfp 只写 r0、不改 pc、不会导致 VM exit，
template<typename EmitterT>
bool JitCompiler<EmitterT>::helper_do_softfp(vm* v, uint32_t call_id) {
    v->do_softfp(call_id);
    return true;
}

template<typename EmitterT>
void JitCompiler<EmitterT>::helper_call_indirect(vm* v, uint64_t ret_gpa, uint64_t target) {
    if (!v->push_frame(ret_gpa, target)) {
        return;
    }
    if (!v->mmu(target, sizeof(bpf_insn))) {
        v->log_mem_violation("call", target);
        v->flags.fetch_or(vm::VM_KILLED, std::memory_order_release);
        return;
    }
    v->pc_ = target;
}

// 间接调用慢路径（带 IC 填槽）：语义同 helper_call_indirect；若目标已编译则把
// {tag, entry_fast, frame} 写入站点槽，后续同目标走 JIT 内快路径
template<typename EmitterT>
void JitCompiler<EmitterT>::helper_call_indirect_ic(vm* v, uint64_t ret_gpa, uint64_t target,
                                                    IndirectICSlot* slot) {
    helper_call_indirect(v, ret_gpa, target);
    if (v->flags.load(std::memory_order_acquire) & (vm::VM_KILLED | vm::VM_EXITED)) return;
    if (slot->tag != target) {
        void* e = v->jit->resolve_call(v, target);
        if (e) {
            slot->tag = target;
            slot->entry = e;
            slot->frame = v->frame_size_of(target);
        }
    }
}

template<typename EmitterT>
void JitCompiler<EmitterT>::helper_call_bpf(vm* v, uint64_t ret_gpa, uint64_t callee_gpa) {
    if (!v->push_frame(ret_gpa, callee_gpa)) {
        v->flags.fetch_or(vm::VM_EXITED, std::memory_order_release);
        return;
    }
    if (!v->mmu(callee_gpa, sizeof(bpf_insn))) {
        v->log_mem_violation("call", callee_gpa);
        v->flags.fetch_or(vm::VM_KILLED, std::memory_order_release);
        return;
    }
    v->pc_ = callee_gpa;
}

template<typename EmitterT>
int JitCompiler<EmitterT>::helper_return_to_caller(vm* v, uint64_t ret_gpa) {
    if (!v->mmu(ret_gpa, sizeof(bpf_insn))) {
        v->log_mem_violation("return", ret_gpa);
        v->flags.fetch_or(vm::VM_KILLED, std::memory_order_release);
        return -1;
    }
    v->pc_ = ret_gpa;
    return 0;
}

template<typename EmitterT>
void* JitCompiler<EmitterT>::helper_resolve_and_cache(vm* v, uint64_t callee_gpa, uint64_t* slot) {
    // inline cache miss 慢路径。push_frame 已由 JIT 内联完成，这里查 callee：命中填槽并
    //   返回 entry_fast 入口；未编译则 v->pc_=callee_gpa 返回 nullptr（回 step() 编译）。
    void* target = v->jit->resolve_call(v, callee_gpa);
    if (target) {
        *slot = (uint64_t)target;
        return target;
    }
    v->pc_ = callee_gpa;
    return nullptr;
}

template<typename EmitterT>
void* JitCompiler<EmitterT>::helper_mmu(vm* v, uint64_t addr, uint64_t size) {
    return v->mmu_slow(addr, (size_t)size);
}

template<typename EmitterT>
void* JitCompiler<EmitterT>::helper_mmu_w(vm* v, uint64_t addr, uint64_t size) {
    return v->mmu_w_slow(addr, (size_t)size);
}

// resolve_call — 由 helper_resolve_and_cache（cache miss 慢路径）调用，返回 callee 的
//   entry_fast 入口；未编译返回 nullptr。

template<typename EmitterT>
void* JitCompiler<EmitterT>::resolve_call(vm* /*v*/, uint64_t callee_gpa) {
    auto it = entries_.find(callee_gpa);
    if (it == entries_.end()) return nullptr;
    auto& f = it->second;
    if (f.kind != JitEntryKind::Compiled) return nullptr;
    return (char*)f.code + f.entry_fast_offset;
}

// ---------------------------------------------------------------------------
// discover_reachable: BFS to find all reachable BPF instructions
// ---------------------------------------------------------------------------

template<typename EmitterT>
void JitCompiler<EmitterT>::discover_reachable(
    const bpf_insn* start, int seg_limit,
    std::vector<bool>& reachable,
    std::vector<bool>& back_edge_targets,
    std::vector<uint32_t>& loop_body_sizes,
    int& func_size)
{
    func_size = 0;
    if (seg_limit <= 0) return;

    reachable.assign(seg_limit, false);
    back_edge_targets.assign(seg_limit, false);
    // 回边稀疏记录：(target, src)。绝大多数 pc 不是回边 target
    // 改为只在遇到回边时 push，遍历后聚合。
    std::vector<std::pair<int,int>> back_edges;
    int max_reached = -1;

    // 显式栈（vector）：可达集与队列遍历等价，免去 deque 的分块分配
    std::vector<int> q;
    auto enqueue = [&](int idx) {
        if (idx >= 0 && idx < seg_limit && !reachable[idx]) {
            reachable[idx] = true;
            if (idx > max_reached) max_reached = idx;
            q.push_back(idx);
        }
    };

    // 记录从 i 到 target 的跳转：标记回边并更新循环体大小估计
    auto jump = [&](int i, int target) {
        if (target >= 0 && target < seg_limit) {
            if (target <= i) {
                back_edge_targets[target] = true;
                back_edges.emplace_back(target, i);
            }
            enqueue(target);
        }
    };

    enqueue(0);

    while (!q.empty()) {
        int i = q.back();
        q.pop_back();
        const bpf_insn* insn = start + i;
        uint8_t cls = insn->code & 0x07;
        uint8_t op = insn->code & 0xf0;

        int next = i + 1;

        switch (cls) {
        case BPF_LD:
            if ((insn->code & 0xe0) == BPF_IMM && (insn->code & 0x18) == BPF_DW) {
                next = i + 2;
            }
            enqueue(next);
            break;

        case BPF_JMP:
            if (op == BPF_JA) {
                jump(i, i + 1 + insn->off);
            } else if (op == BPF_CALL) {
                enqueue(next);
            } else if (op == BPF_EXIT) {
            } else {
                jump(i, i + 1 + insn->off);
                enqueue(next);
            }
            break;

        case BPF_JMP32:
            if (op == BPF_JA) {
                jump(i, i + 1 + insn->imm);
            } else {
                jump(i, i + 1 + insn->off);
                enqueue(next);
            }
            break;

        default:
            enqueue(next);
            break;
        }
    }

    if (max_reached < 0) return;

    if (max_reached < seg_limit - 1) {
        const bpf_insn* insn = start + max_reached;
        if ((insn->code & 0x07) == BPF_LD &&
            (insn->code & 0xe0) == BPF_IMM &&
            (insn->code & 0x18) == BPF_DW) {
            max_reached++;
        }
    }

    func_size = max_reached + 1;

    reachable.resize(func_size);
    back_edge_targets.resize(func_size);

    // 计算每个回边目标的循环体大小：同一 target 取最远 src（max 语义）
    loop_body_sizes.assign(func_size, 1);
    for (auto [target, src] : back_edges) {
        int body = src - target + 1;
        if (body > (int)loop_body_sizes[target]) {
            loop_body_sizes[target] = body;
        }
    }

    for (int i = 0; i < func_size - 1; i++) {
        if (reachable[i]) {
            const bpf_insn* insn = start + i;
            if ((insn->code & 0x07) == BPF_LD &&
                (insn->code & 0xe0) == BPF_IMM &&
                (insn->code & 0x18) == BPF_DW) {
                reachable[i + 1] = false;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// emit_instruction: BPF-level dispatch
// ---------------------------------------------------------------------------

template<typename EmitterT>
bool JitCompiler<EmitterT>::emit_instruction(EmitterT& e, const bpf_insn* entry_pc, uint64_t entry_gpa, int i,
                                               int num_insns,
                                               std::vector<JumpPlaceholder>& placeholders,
                                               std::vector<AbortPatchInfo>& abort_patches,
                                               std::vector<size_t>& call_cache_offs,
                                               std::vector<size_t>& ic_cache_offs,
                                               int& compiled_count, vm* v) {
    const bpf_insn* insn = entry_pc + i;
    uint8_t cls = insn->code & 0x07;

    switch (cls) {
    case BPF_ALU64:
        if (insn->dst_reg >= 10) return false;
        if (!e.emit_alu(insn, true)) return false;
        compiled_count++;
        break;

    case BPF_ALU:
        if (insn->dst_reg >= 10) return false;
        if (!e.emit_alu(insn, false)) return false;
        compiled_count++;
        break;

    case BPF_LD:
        if (!e.emit_ld(insn)) return false;
        compiled_count += 2;
        break;

    case BPF_LDX:
        if (insn->dst_reg >= 10) return false;
        if (!e.emit_ldx(insn, abort_patches, i)) return false;
        compiled_count++;
        break;

    case BPF_ST:
        if (!e.emit_st(insn, abort_patches, i)) return false;
        compiled_count++;
        break;

    case BPF_STX:
        if (!e.emit_stx(insn, abort_patches, i)) return false;
        compiled_count++;
        break;

    case BPF_JMP: {
        uint8_t op = insn->code & 0xf0;
        bool is_x = (insn->code & 0x08) == BPF_X;

        if (op == BPF_JA) {
            int tgt = i + 1 + insn->off;
            bool deopt = tgt < 0 || tgt >= num_insns;
            if (deopt) {
                // 越界 ja(典型:回跳目标在编译入口之前) -> 写目标 pc 后跳 flush_and_exit,
                // 由 step() 在目标处继续(重新探测编译或解释执行)
                e.emit_set_pc_imm(entry_gpa + (uint64_t)(int64_t)tgt * sizeof(bpf_insn));
            }
            e.emit_ja(insn, i, placeholders);
            if (deopt) placeholders.back().deopt = true;
            compiled_count++;
        } else if (op == BPF_CALL) {
            if (is_x) {
                uint64_t ret_gpa = entry_gpa + (uint64_t)(i + 1) * sizeof(bpf_insn);
                e.emit_call_indirect(insn, ret_gpa, abort_patches, i, ic_cache_offs);
                compiled_count++;
            } else if (insn->src_reg == 0) {
                e.emit_call_syscall(insn, i, entry_gpa);
                compiled_count++;
            } else if (insn->src_reg == 1) {
                uint64_t ret_gpa    = entry_gpa + (uint64_t)(i + 1) * sizeof(bpf_insn);
                uint64_t callee_gpa = entry_gpa + (uint64_t)(i + 1 + insn->imm) * sizeof(bpf_insn);
                // 编译期读被调函数帧槽（frame_slot.h），运行期内联 push 直接嵌立即数；
                // 无槽回退 v->options.stack_limit（-S 启动后不变，嵌立即数安全）。
                e.emit_call_bpf(ret_gpa, callee_gpa, v->frame_size_of(callee_gpa),
                                abort_patches, i, call_cache_offs);
                compiled_count++;
            } else if (insn->src_reg == 2) {
                // 浮点专用通道：先 JIT 原生（emit_call_softfp），未命中（如 x86 的
                // uint fp<->int 转换）走 emit_call_softfp_slow 回退到 helper_do_softfp。
                if (e.emit_call_softfp(insn)) {
                    compiled_count++;
                } else {
                    e.emit_call_softfp_slow(insn, i, entry_gpa);
                    compiled_count++;
                }
            } else {
                return false;
            }
        } else if (op == BPF_EXIT) {
            e.emit_exit(abort_patches, i);
            compiled_count++;
        } else {
            int tgt = i + 1 + insn->off;
            bool oos = tgt < 0 || tgt >= num_insns;
            bool ok = oos
                ? e.emit_jmp_deopt(insn, true,
                      entry_gpa + (uint64_t)(int64_t)tgt * sizeof(bpf_insn), placeholders)
                : e.emit_jmp(insn, i, true, placeholders);
            if (!ok) return false;
            compiled_count++;
        }
        break;
    }

    case BPF_JMP32: {
        uint8_t op = insn->code & 0xf0;
        if (op == BPF_JA) {
            int tgt = i + 1 + insn->imm;
            bool deopt = tgt < 0 || tgt >= num_insns;
            if (deopt) {
                e.emit_set_pc_imm(entry_gpa + (uint64_t)(int64_t)tgt * sizeof(bpf_insn));
            }
            e.emit_ja32(insn, i, placeholders);
            if (deopt) placeholders.back().deopt = true;
            compiled_count++;
        } else {
            int tgt = i + 1 + insn->off;
            bool oos = tgt < 0 || tgt >= num_insns;
            bool ok = oos
                ? e.emit_jmp_deopt(insn, false,
                      entry_gpa + (uint64_t)(int64_t)tgt * sizeof(bpf_insn), placeholders)
                : e.emit_jmp(insn, i, false, placeholders);
            if (!ok) return false;
            compiled_count++;
        }
        break;
    }

    default:
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// finalize_code
// ---------------------------------------------------------------------------

template<typename EmitterT>
void* JitCompiler<EmitterT>::finalize_code(EmitterT& e) {
    size_t code_size = e.size();
    size_t aligned = (code_size + 4095) & ~(size_t)4095;

    // 找有空间的 arena；没有则新开一块（RW，碎片按需触碰缺页）
    CodeArena* arena = nullptr;
    for (auto& a : arenas_) {
        if (a.used + aligned <= a.size) { arena = &a; break; }
    }
    if (!arena) {
        size_t asize = aligned > kCodeArenaSize ? aligned : kCodeArenaSize;
        uint8_t* base = (uint8_t*)mmap(nullptr, asize, PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) return nullptr;
        arenas_.push_back({base, asize, 0});
        arena = &arenas_.back();
    }

    uint8_t* code_mem = arena->base + arena->used;
    memcpy(code_mem, e.data(), code_size);

    // Flush instruction cache before removing write permission.
    // On AArch64, dc cvau (data cache clean) may require write access on
    // some security-hardened kernels, so do this while pages are still RW.
    __builtin___clear_cache((char*)code_mem, (char*)code_mem + code_size);

    if (mprotect(code_mem, aligned, PROT_READ | PROT_EXEC) != 0) {
        return nullptr;
    }
    arena->used += aligned;
    return code_mem;
}

// ---------------------------------------------------------------------------
// compile: build a complete JIT function from all reachable instructions
// ---------------------------------------------------------------------------

template<typename EmitterT>
JitEntry* JitCompiler<EmitterT>::compile(vm* v, uint64_t gpa) {
    if (!enabled_) return nullptr;
    // GDB attach 期间（VM_DEBUG_ATTACHED）：跳过 JIT，强制走解释器——解释器每步检查断点/单步，
    if (v->get_flags() & vm::VM_DEBUG_ATTACHED) return nullptr;

    // 影子缓存快路径：Compiled/Failed 直接返回（step() 的每指令探测是本函数调用的
    // 绝对大头）。Counting 不缓存——计数语义留在 map（挤掉重查一次哈希即可，比重数
    // 阈值便宜；实测计数入缓存在算力负载无收益、启动回退 4.7x）。
    auto& hot = pc_cache_[(gpa >> 3) & (kPcCacheSlots - 1)];
    if (hot.gpa == gpa) {
        return hot.e == &failed_sentinel_ ? nullptr : hot.e;
    }

    struct Timer {
        bool enable;
        uint64_t& acc;
        std::chrono::high_resolution_clock::time_point start;
        explicit Timer(bool enable_, uint64_t& a) : enable(enable_), acc(a) {
            if (enable) start = std::chrono::high_resolution_clock::now();
        }
        ~Timer() {
            if(!enable) return;
            acc += (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::high_resolution_clock::now() - start).count();
        }
    };

    stats.map_path_calls++;
    Timer t_map(debug_enabled_, stats.map_path_ns);

    // 已编译/已失败直接返回（entries_ 只登记过阈值的 pc，规模 ~编译片段数；
    // Counting 是 emplace 后的本函数内瞬态，此处不可能命中）。
    auto it = entries_.find(gpa);
    if (it != entries_.end()) {
        if (it->second.kind == JitEntryKind::Compiled) {
            hot = {gpa, &it->second};
            return &it->second;
        }
        hot = {gpa, &failed_sentinel_};
        return nullptr;
    }

    // 热点检测：未达阈值的 pc 走解释器（返回 nullptr）。计数在 hot_counters_ 递增
    // ——step() 单步与 JIT helper_call_bpf 都经过这里，所以循环回边目标会被反复
    // 计数，达到阈值即在循环头编译（OSR：prologue 从 vm->reg[] 加载解释器当前
    // 状态，JIT 接管剩余循环）。冷 pc 永不达阈值，始终走解释器。
    if (threshold_ > 0) {
        size_t base = (gpa >> 3) & (kHotCounterSlots - 1);
        HotCounter* slot = nullptr;
        uint32_t min_count = UINT32_MAX;
        for (unsigned k = 0; k < kHotCounterProbe; k++) {
            HotCounter& s = hot_counters_[(base + k) & (kHotCounterSlots - 1)];
            if (s.gpa == gpa || s.gpa == 0) { slot = &s; break; }
            if (s.count < min_count) { min_count = s.count; slot = &s; }
        }
        if (slot->gpa != gpa) { slot->gpa = gpa; slot->count = 0; }
        if (slot->count != UINT32_MAX) slot->count++;
        if (slot->count < threshold_) return nullptr;
        slot->gpa = 0;   // 提升进 entries_，清槽防陈旧计数
        slot->count = 0;
    }
    it = entries_.emplace(gpa, JitEntry{}).first;
    // 过阈值进入真实编译（BFS/emit/patch/finalize）
    Timer t_real(debug_enabled_, stats.real_compile_ns);
    auto t_real0 = std::chrono::high_resolution_clock::now();
    auto ns_since = [](std::chrono::high_resolution_clock::time_point t0) {
        return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::high_resolution_clock::now() - t0).count();
    };

    // gpa 是 guest 入口地址；编译期需要 host 指针遍历指令，mmu 取一次（编译期无 CoW）
    auto t_seg0 = std::chrono::high_resolution_clock::now();
    const bpf_insn* entry_pc = (const bpf_insn*)v->mmu(gpa, sizeof(bpf_insn));
    if (!entry_pc) return nullptr;
    uint64_t entry_gpa = gpa;

    const bpf_insn* seg_end = nullptr;
    for (auto& m : *v->maps) {
        if (entry_gpa >= m.paddr && entry_gpa < m.paddr + m.size) {
            size_t bytes_remaining = m.size - (size_t)(entry_gpa - m.paddr);
            seg_end = entry_pc + bytes_remaining / sizeof(bpf_insn);
            break;
        }
    }
    if (!seg_end) return nullptr;

    int seg_limit = (int)(seg_end - entry_pc);
    if (debug_enabled_) stats.seg_ns += ns_since(t_seg0);

    // 记录失败：把当前 entry 标记为 Failed（下次直接命中返回 nullptr，不再重试/计数）。
    // poison_idx：触发失败的指令相对入口的下标（未知传 -1）。同一函数内更靠后的
    // 热点 pc 再次尝试编译会命中同一条毒指令，逐 pc 重跑 BFS+emit 是纯浪费——
    // 故把入口到毒指令的前缀跨度一并毒化进影子缓存（保守：未编译的入口不再重试，
    // 已 Compiled 的豁免——见循环内说明）。
    auto mark_failed = [&](int poison_idx, const char* why) {
        it->second.kind = JitEntryKind::Failed;
        if (debug_enabled_) {
            double ms = std::chrono::duration<double, std::milli>(
                std::chrono::high_resolution_clock::now() - t_real0).count();
            fprintf(stderr, "[jit-fail] %s gpa=0x%lx %.3fms", why, (unsigned long)gpa, ms);
            if (poison_idx >= 0 && entry_pc) {
                const bpf_insn* bad = entry_pc + poison_idx;
                fprintf(stderr, " poison@+%d code=0x%02x dst=%d src=%d off=%d imm=0x%x",
                        poison_idx, bad->code, bad->dst_reg, bad->src_reg, bad->off, bad->imm);
            }
            fprintf(stderr, "\n");
        }
        int upto = (poison_idx >= 0 && entry_pc) ? poison_idx : 0;
        for (int k = 0; k <= upto; k++) {
            uint64_t p = gpa + (uint64_t)k * sizeof(bpf_insn);
            // 已 Compiled 的入口不毒化：被毒跨度覆盖的已编译入口（与毒指令分处不同
            // 可达分支的循环头）一旦覆写成 Failed，影子命中永远返回 nullptr 且无自愈
            // 路径（直至槽被别名挤出或 VM 销毁），该片段永久失去 OSR 入口
            auto e = entries_.find(p);
            if (e != entries_.end() && e->second.kind == JitEntryKind::Compiled) continue;
            pc_cache_[(p >> 3) & (kPcCacheSlots - 1)] = {p, &failed_sentinel_};
        }
    };

    // Discover reachable instructions via BFS
    auto t_bfs0 = std::chrono::high_resolution_clock::now();
    int num_insns = 0;
    std::vector<bool> reachable;
    std::vector<bool> back_edge_targets;
    std::vector<uint32_t> loop_body_sizes;
    discover_reachable(entry_pc, seg_limit, reachable, back_edge_targets, loop_body_sizes, num_insns);
    if (debug_enabled_) stats.bfs_ns += ns_since(t_bfs0);
    // reachable 空/num_insns<=0 <=> seg_limit<=0（gpa 距段尾不足一条指令）。
    // gpa 相对段的位置不变、段大小不变，属结构性失败——缓存失败避免每次 step 重跑 BFS。
    if (num_insns <= 0) {
        mark_failed(-1, "empty-span");
        return nullptr;
    }

    // Set up emitter（成员复用，容量跨编译保留）
    EmitterT& e = work_emitter_;
    e.reset();
    e.set_vm_offsets(off_reg_, off_pc_, off_flags_, off_tlb_, off_stack_limit_, off_scratch_);
    if(debug_enabled_ || v->options.insn_limit != 0) {
        e.set_budget(off_insn_count_, off_insn_limit_, v->options.insn_limit != 0);
    }
    e.set_helpers(helpers_);

    // Emit code
    std::vector<JumpPlaceholder> placeholders;
    std::vector<AbortPatchInfo> abort_patches;
    std::vector<size_t> call_cache_offs;   // inline cache 槽地址占位（imm64）的 buffer 偏移
    std::vector<size_t> ic_cache_offs;     // 间接调用 IC 槽地址占位
    std::vector<uint32_t> pc_offsets(num_insns, UINT32_MAX);

    auto t_emit0 = std::chrono::high_resolution_clock::now();
    size_t flush_and_exit_offset = e.emit_prologue();

    int compiled_count = 0;
    for (int i = 0; i < num_insns; i++) {
        if (!reachable[i]) continue;
        pc_offsets[i] = (uint32_t)e.size();

        if (entry_pc[i].dst_reg > 10 || entry_pc[i].src_reg > 10) {
            mark_failed(i, "reg-num");
            return nullptr;
        }

        // Safepoint at back-edge targets (loop headers)
        if (back_edge_targets[i]) {
            // 本 safepoint 所在 BPF 指令（循环头）的 guest pc：信号处理返回后应
            // 恢复到此处执行，故把该地址传给 emit_safepoint 写入 vm->pc。
            uint64_t insn_gpa = entry_gpa + (uint64_t)i * sizeof(bpf_insn);
            e.emit_safepoint(loop_body_sizes[i], insn_gpa);
        }

        if (!emit_instruction(e, entry_pc, entry_gpa, i, num_insns,
                              placeholders, abort_patches, call_cache_offs, ic_cache_offs,
                              compiled_count, v)) {
            mark_failed(i, "emit-insn");
            return nullptr;
        }
    }
    if (debug_enabled_) stats.emit_ns += ns_since(t_emit0);

    if (compiled_count == 0) {
        mark_failed(-1, "nothing-emitted");
        return nullptr;
    }

    auto t_patch0 = std::chrono::high_resolution_clock::now();

    // Patch jump placeholders
    for (auto& ph : placeholders) {
        if (ph.target_bpf_index < 0 || ph.target_bpf_index >= num_insns ||
            pc_offsets[ph.target_bpf_index] == UINT32_MAX) {
            if (ph.deopt) {
                e.patch_branch_uncond(ph.patch_offset, flush_and_exit_offset);
                continue;
            }
            if (debug_enabled_) {
                fprintf(stderr, "[jit-patch-fail] target_idx=%d num_insns=%d\n",
                        ph.target_bpf_index, num_insns);
            }
            mark_failed(num_insns - 1, "patch-target");
            return nullptr;
        }
        size_t target = pc_offsets[ph.target_bpf_index];
        switch (ph.kind) {
        case PlaceholderKind::Conditional:  e.patch_branch_cond(ph.patch_offset, target); break;
        case PlaceholderKind::Unconditional:  e.patch_branch_uncond(ph.patch_offset, target); break;
        }
    }

    // Patch abort jumps to .flush_and_exit
    for (auto& ap : abort_patches) {
        e.patch_branch_abort(ap.jump_offset, flush_and_exit_offset);
    }

    // 复用当前 entry（编译开始前已 emplace，迭代器稳定），承载编译产物；call_cache
    // 落地后取稳定槽地址 patch 进 JIT 代码。
    auto& func = it->second;
    func.gpa = gpa;

    // 槽地址占位：每站点恰 1 个（快路径字面量，慢路径经 mov_rip_literal/ldr_literal_at
    // 重取同一份），占位 i <-> 槽 i 恒等映射。在 e.data()（RW）上 patch，随 finalize_code
    // memcpy 进 RX 页——无运行时代码 patch，W^X 保持。
    func.call_cache.assign(call_cache_offs.size(), 0);
    for (size_t i = 0; i < call_cache_offs.size(); i++) {
        uint64_t slot_addr = (uint64_t)(uintptr_t)&func.call_cache[i];
        memcpy(e.data() + call_cache_offs[i], &slot_addr, sizeof(slot_addr));
    }

    // 间接调用 IC 同构：占位 i <-> ic_slots[i]
    func.ic_slots.assign(ic_cache_offs.size(), IndirectICSlot{});
    for (size_t i = 0; i < ic_cache_offs.size(); i++) {
        uint64_t slot_addr = (uint64_t)(uintptr_t)&func.ic_slots[i];
        memcpy(e.data() + ic_cache_offs[i], &slot_addr, sizeof(slot_addr));
    }
    if (debug_enabled_) stats.patch_ns += ns_since(t_patch0);

    // Finalize
    auto t_fin0 = std::chrono::high_resolution_clock::now();
    void* code_mem = finalize_code(e);
    if (!code_mem) {
        mark_failed(-1, "finalize");
        return nullptr;
    }
    if (debug_enabled_) stats.finalize_ns += ns_since(t_fin0);

    stats.jit_compiles++;
    stats.jit_compiled_insns += compiled_count;
    func.code = code_mem;
    func.insn_count = compiled_count;
    func.pc_offsets = std::move(pc_offsets);
    func.entry_fast_offset = e.get_entry_fast_offset();  // 由 emit_prologue 生成
    func.kind = JitEntryKind::Compiled;
    hot = {gpa, &func};
    // 逐条编译日志挂 BPF_JIT_DUMP（与 hex dump 配套定位 gpa）；BPF_DEBUG 只保留
    // 退出统计与罕见的 [jit-fail]，避免大程序编译数百函数时刷屏
    if (jit_dump_enabled_) {
        double ms = std::chrono::duration<double, std::milli>(
            std::chrono::high_resolution_clock::now() - t_real0).count();
        fprintf(stderr, "[jit-compile] gpa=0x%lx span=%d emitted=%d %.3fms\n",
                (unsigned long)gpa, num_insns, compiled_count, ms);
        fprintf(stderr, "[jit-dump] gpa=0x%lx size=%zu host=%p\n", (unsigned long)gpa, e.size(), code_mem);
        const uint32_t* w = (const uint32_t*)e.data();
        for (size_t k = 0; k < e.size() / 4; k++) {
            fprintf(stderr, "%08x%s", w[k], (k % 8 == 7 || k + 1 == e.size() / 4) ? "\n" : " ");
        }
    }
    return &func;
}

// ---------------------------------------------------------------------------
// Explicit template instantiation
// ---------------------------------------------------------------------------

#if defined(__x86_64__)
template class JitCompiler<X86Emitter>;
#elif defined(__aarch64__)
template class JitCompiler<AArch64Emitter>;
#endif
