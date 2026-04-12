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
// Arithmetic helpers for DIV/MOD (called from JIT-generated code)
// ---------------------------------------------------------------------------

uint64_t jit_div64(uint64_t dst, uint64_t src, int16_t off) {
    if (off == 0) {
        return src ? dst / src : 0;
    }
    if (!src) return 0;
    auto sd = (int64_t)src;
    return (sd == -1 && (int64_t)dst == INT64_MIN)
        ? (uint64_t)INT64_MIN : (uint64_t)((int64_t)dst / sd);
}

uint64_t jit_mod64(uint64_t dst, uint64_t src, int16_t off) {
    if (off == 0) {
        return src ? dst % src : dst;
    }
    if (!src) return dst;
    auto sd = (int64_t)src;
    return (sd == -1 && (int64_t)dst == INT64_MIN)
        ? 0 : (uint64_t)((int64_t)dst % sd);
}

uint32_t jit_div32(uint32_t dst, uint32_t src, int16_t off) {
    if (off == 0) {
        return src ? dst / src : 0;
    }
    if (!src) return 0;
    auto sd = (int32_t)src;
    return (sd == -1 && (int32_t)dst == INT32_MIN)
        ? (uint32_t)INT32_MIN : (uint32_t)((int32_t)dst / sd);
}

uint32_t jit_mod32(uint32_t dst, uint32_t src, int16_t off) {
    if (off == 0) {
        return src ? dst % src : dst;
    }
    if (!src) return dst;
    auto sd = (int32_t)src;
    return (sd == -1 && (int32_t)dst == INT32_MIN)
        ? 0 : (uint32_t)((int32_t)dst % sd);
}

// ---------------------------------------------------------------------------
// JitCompiler implementation
// ---------------------------------------------------------------------------

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winvalid-offsetof"
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_reg_            = offsetof(vm, reg);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_pc_             = offsetof(vm, pc);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_flags_          = offsetof(vm, flags);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_tlb_            = offsetof(vm, tlb);
#pragma GCC diagnostic pop

template<typename EmitterT>
JitCompiler<EmitterT>::JitCompiler() {
    const char* env = getenv("JIT_ENABLE");
    enabled_ = (env == nullptr || strcmp(env, "0") != 0);
}

template<typename EmitterT>
JitCompiler<EmitterT>::~JitCompiler() {
    for (auto& [pc, f] : functions_) {
        if (f.code) munmap(f.code, f.code_size);
    }
}

// ---------------------------------------------------------------------------
// JIT control-flow helpers (called from JIT-generated code)
// ---------------------------------------------------------------------------

template<typename EmitterT>
int JitCompiler<EmitterT>::helper_safepoint(vm* v) {
    const bpf_insn* saved_pc = v->pc;
    if (!v->safepoint()) {
        return 1;
    }
    if (v->pc != saved_pc) {
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
    const bpf_insn* saved_pc = v->pc;
    bool ok = v->do_syscall(call_id);
    if (!ok) {
        v->flags.fetch_or(vm::VM_EXITED, std::memory_order_release);
        if (v->pc == saved_pc) v->pc++;
        return false;
    }
    if (v->pc != saved_pc) {
        v->pc++;
        return false;
    }
    uint32_t f = v->flags.load(std::memory_order_acquire);
    if (f & (vm::VM_EXITED | vm::VM_KILLED | vm::VM_STOPPED)) {
        v->pc++;
        return false;
    }
    return true;
}

template<typename EmitterT>
bool JitCompiler<EmitterT>::helper_call_indirect(vm* v, uint64_t ret_gpa, uint64_t target) {
    if (!v->push_frame(ret_gpa)) {
        return false;
    }
    void* host = v->mmu(target);
    if (!host) {
        v->flags.fetch_or(vm::VM_KILLED, std::memory_order_release);
        return false;
    }
    v->pc = (const bpf_insn*)host;
    return false;
}

template<typename EmitterT>
int JitCompiler<EmitterT>::helper_return_to_caller(vm* v, uint64_t ret_gpa) {
    void* host = v->mmu(ret_gpa);
    if (!host) {
        v->flags.fetch_or(vm::VM_KILLED, std::memory_order_release);
        return -1;
    }
    v->pc = (const bpf_insn*)host;
    return 0;
}

template<typename EmitterT>
void* JitCompiler<EmitterT>::helper_mmu(vm* v, uint64_t addr, uint64_t size) {
    return v->mmu_slow(addr, (size_t)size);
}

template<typename EmitterT>
void* JitCompiler<EmitterT>::helper_mmu_w(vm* v, uint64_t addr, uint64_t size) {
    return v->mmu_w_slow(addr, (size_t)size);
}

// ---------------------------------------------------------------------------
// Helper table construction
// ---------------------------------------------------------------------------

template<typename EmitterT>
HelperTable JitCompiler<EmitterT>::make_helper_table() const {
    HelperTable h;
    h.safepoint = (void*)&helper_safepoint;
    h.push_frame = (void*)&helper_push_frame;
    h.pop_frame = (void*)&helper_pop_frame;
    h.do_syscall = (void*)&helper_do_syscall;
    h.call_indirect = (void*)&helper_call_indirect;
    h.return_to_caller = (void*)&helper_return_to_caller;
    h.mmu = (void*)&helper_mmu;
    h.mmu_w = (void*)&helper_mmu_w;
    h.div64 = (void*)jit_div64;
    h.div32 = (void*)jit_div32;
    h.mod64 = (void*)jit_mod64;
    h.mod32 = (void*)jit_mod32;
    return h;
}

// ---------------------------------------------------------------------------
// discover_reachable: BFS to find all reachable BPF instructions
// ---------------------------------------------------------------------------

template<typename EmitterT>
std::vector<bool> JitCompiler<EmitterT>::discover_reachable(
    const bpf_insn* start, int seg_limit,
    std::vector<bool>& back_edge_targets, int& func_size)
{
    func_size = 0;
    if (seg_limit <= 0) return {};

    std::vector<bool> reachable(seg_limit, false);
    back_edge_targets.assign(seg_limit, false);
    int max_reached = -1;

    std::queue<int> q;
    auto enqueue = [&](int idx) {
        if (idx >= 0 && idx < seg_limit && !reachable[idx]) {
            reachable[idx] = true;
            if (idx > max_reached) max_reached = idx;
            q.push(idx);
        }
    };

    enqueue(0);

    while (!q.empty()) {
        int i = q.front();
        q.pop();
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
                int target = i + 1 + insn->off;
                if (target >= 0 && target < seg_limit) {
                    if (target <= i) back_edge_targets[target] = true;
                    enqueue(target);
                }
            } else if (op == BPF_CALL) {
                enqueue(next);
            } else if (op == BPF_EXIT) {
            } else {
                int target = i + 1 + insn->off;
                if (target >= 0 && target < seg_limit) {
                    if (target <= i) back_edge_targets[target] = true;
                    enqueue(target);
                }
                enqueue(next);
            }
            break;

        case BPF_JMP32:
            if (op == BPF_JA) {
                int target = i + 1 + insn->imm;
                if (target >= 0 && target < seg_limit) {
                    if (target <= i) back_edge_targets[target] = true;
                    enqueue(target);
                }
            } else {
                int target = i + 1 + insn->off;
                if (target >= 0 && target < seg_limit) {
                    if (target <= i) back_edge_targets[target] = true;
                    enqueue(target);
                }
                enqueue(next);
            }
            break;

        default:
            enqueue(next);
            break;
        }
    }

    if (max_reached < 0) return {};

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

    return reachable;
}

// ---------------------------------------------------------------------------
// emit_instruction: BPF-level dispatch
// ---------------------------------------------------------------------------

template<typename EmitterT>
bool JitCompiler<EmitterT>::emit_instruction(EmitterT& e, vm* v, const bpf_insn* entry_pc, int i,
                                               std::vector<JumpPlaceholder>& placeholders,
                                               std::vector<AbortPatchInfo>& abort_patches,
                                               int& compiled_count) {
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
            e.emit_ja(insn, i, placeholders);
            compiled_count++;
        } else if (op == BPF_CALL) {
            if (is_x) {
                uint64_t ret_gpa = v->unmmu(entry_pc + i + 1);
                e.emit_call_indirect(insn, ret_gpa);
                compiled_count++;
            } else if (insn->src_reg == 0) {
                e.emit_call_syscall(insn, i, entry_pc);
                compiled_count++;
            } else if (insn->src_reg == 1) {
                uint64_t ret_gpa = v->unmmu(entry_pc + i + 1);
                e.emit_call_bpf(insn, i, ret_gpa, entry_pc);
                compiled_count++;
            } else {
                return false;
            }
        } else if (op == BPF_EXIT) {
            e.emit_exit();
            compiled_count++;
        } else {
            if (!e.emit_jmp(insn, i, true, placeholders)) return false;
            compiled_count++;
        }
        break;
    }

    case BPF_JMP32: {
        uint8_t op = insn->code & 0xf0;
        if (op == BPF_JA) {
            e.emit_ja32(insn, i, placeholders);
            compiled_count++;
        } else {
            if (!e.emit_jmp(insn, i, false, placeholders)) return false;
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
    size_t alloc_size = (code_size + 4095) & ~(size_t)4095;
    void* code_mem = mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code_mem == MAP_FAILED) return nullptr;

    memcpy(code_mem, e.data(), code_size);
    if (mprotect(code_mem, alloc_size, PROT_READ | PROT_EXEC) != 0) {
        munmap(code_mem, alloc_size);
        return nullptr;
    }

    // Flush instruction cache (required on AArch64 where icache != dcache)
    __builtin___clear_cache((char*)code_mem, (char*)code_mem + code_size);
    return code_mem;
}

// ---------------------------------------------------------------------------
// compile: build a complete JIT function from all reachable instructions
// ---------------------------------------------------------------------------

template<typename EmitterT>
JitFunction* JitCompiler<EmitterT>::compile(vm* v, const bpf_insn* entry_pc) {
    if (!enabled_) return nullptr;
    auto it = functions_.find(entry_pc);
    if (it != functions_.end()) return &it->second;
    if (failed_.count(entry_pc)) {
        return nullptr;
    }

    auto compile_start = std::chrono::high_resolution_clock::now();
    auto record_compile_time = [&] {
        stats.compile_ns += (uint64_t)std::chrono::duration_cast<
            std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - compile_start).count();
    };

    // Find code segment end
    uint64_t entry_gpa = v->unmmu(entry_pc);
    if (!entry_gpa) return nullptr;

    const bpf_insn* seg_end = nullptr;
    for (auto& m : v->maps) {
        if (entry_gpa >= m.paddr && entry_gpa < m.paddr + m.size) {
            size_t bytes_remaining = m.size - (size_t)(entry_gpa - m.paddr);
            seg_end = entry_pc + bytes_remaining / sizeof(bpf_insn);
            break;
        }
    }
    if (!seg_end) return nullptr;

    int seg_limit = (int)(seg_end - entry_pc);

    // Discover reachable instructions via BFS
    std::vector<bool> back_edge_targets;
    int num_insns = 0;
    auto reachable = discover_reachable(entry_pc, seg_limit, back_edge_targets, num_insns);
    if (reachable.empty() || num_insns <= 0) { record_compile_time(); return nullptr; }

    // Set up emitter
    EmitterT e;
    e.set_vm_offsets(off_reg_, off_pc_, off_flags_, off_tlb_);
    e.set_helpers(make_helper_table());

    // Emit code
    std::vector<JumpPlaceholder> placeholders;
    std::vector<AbortPatchInfo> abort_patches;
    std::vector<uint32_t> pc_offsets(num_insns, UINT32_MAX);

    size_t flush_and_exit_offset = e.emit_prologue();

    int compiled_count = 0;
    for (int i = 0; i < num_insns; i++) {
        if (!reachable[i]) continue;
        pc_offsets[i] = (uint32_t)e.size();

        // Safepoint at back-edge targets (loop headers)
        if (back_edge_targets[i]) {
            e.emit_safepoint();
        }

        if (!emit_instruction(e, v, entry_pc, i,
                              placeholders, abort_patches, compiled_count)) {
            failed_.insert(entry_pc);
            record_compile_time();
            return nullptr;
        }
    }

    if (compiled_count == 0) { failed_.insert(entry_pc); record_compile_time(); return nullptr; }

    // Patch jump placeholders
    for (auto& ph : placeholders) {
        if (ph.target_bpf_index < 0 || ph.target_bpf_index >= num_insns ||
            pc_offsets[ph.target_bpf_index] == UINT32_MAX) {
            failed_.insert(entry_pc);
            record_compile_time();
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
        e.patch_branch_cond(ap.jump_offset, flush_and_exit_offset);
    }

    // Finalize
    void* code_mem = finalize_code(e);
    if (!code_mem) { record_compile_time(); return nullptr; }

    stats.jit_compiles++;
    stats.jit_compiled_insns += compiled_count;
    auto& func = functions_[entry_pc];
    func.code = code_mem;
    func.insn_count = compiled_count;
    func.code_size = (e.size() + 4095) & ~(size_t)4095;
    func.entry_pc = entry_pc;
    func.pc_offsets = std::move(pc_offsets);
    record_compile_time();
    return &func;
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

template<typename EmitterT>
void JitCompiler<EmitterT>::dump_stats(const JitStats& s) {
    if (!getenv("JIT_DEBUG")) return;
    double pct = s.total_insns ? (100.0 * s.jit_insns / s.total_insns) : 0.0;
    fprintf(stderr, "[JIT] 总指令条数: %lu\n", s.total_insns);
    fprintf(stderr, "[JIT] JIT执行条数: %lu (%.1f%%)\n", s.jit_insns, pct);
    fprintf(stderr, "[JIT] JIT编译函数数: %lu\n", s.jit_compiles);
    fprintf(stderr, "[JIT] JIT执行函数次数: %lu\n", s.jit_func_runs);
    if (s.jit_compiles) {
        fprintf(stderr, "[JIT] 编译时平均函数大小: %.1f条\n",
                (double)s.jit_compiled_insns / s.jit_compiles);
    }
    if (s.jit_func_runs) {
        fprintf(stderr, "[JIT] 运行时平均每次执行: %.1f条\n",
                (double)s.jit_insns / s.jit_func_runs);
    }
    fprintf(stderr, "[JIT] 编译耗时: %.1fms\n", s.compile_ns / 1e6);
}

// ---------------------------------------------------------------------------
// Explicit template instantiation
// ---------------------------------------------------------------------------

#if defined(__x86_64__)
template class JitCompiler<X86Emitter>;
#elif defined(__aarch64__)
template class JitCompiler<AArch64Emitter>;
#endif
