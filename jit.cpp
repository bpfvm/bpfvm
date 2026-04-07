//
// Created by chouryzhou on 26-3-31.
//

#include "jit.h"

#include <cstdlib>
#include <cstdio>
#include <climits>
#include <cstring>
#include <queue>
#include <chrono>

#if defined(__x86_64__)

#include "insn.h"

// ---------------------------------------------------------------------------
// Arithmetic helpers for DIV/MOD (called from JIT-generated code)
//
// Called via System V AMD64 ABI: arg1=RDI, arg2=RSI, arg3=RDX; return in RAX.
// RBX is callee-saved per ABI, so vm* survives every helper call.
//
// Why helpers for DIV/MOD?
//   - BPF divide-by-zero → result = 0 (not #DE fault).
//   - BPF INT64_MIN / -1 → INT64_MIN (not #DE fault).
//   - BPF insn->off selects unsigned (off==0) vs. signed (off!=0) division.
// ---------------------------------------------------------------------------

static uint64_t jit_div64(uint64_t dst, uint64_t src, int16_t off) {
    if (off == 0) {
        return src ? dst / src : 0;
    }
    if (!src) return 0;
    auto sd = (int64_t)src;
    return (sd == -1 && (int64_t)dst == INT64_MIN)
        ? (uint64_t)INT64_MIN : (uint64_t)((int64_t)dst / sd);
}

static uint64_t jit_mod64(uint64_t dst, uint64_t src, int16_t off) {
    if (off == 0) {
        return src ? dst % src : dst;
    }
    if (!src) return dst;
    auto sd = (int64_t)src;
    return (sd == -1 && (int64_t)dst == INT64_MIN)
        ? 0 : (uint64_t)((int64_t)dst % sd);
}

static uint32_t jit_div32(uint32_t dst, uint32_t src, int16_t off) {
    if (off == 0) {
        return src ? dst / src : 0;
    }
    if (!src) return 0;
    auto sd = (int32_t)src;
    return (sd == -1 && (int32_t)dst == INT32_MIN)
        ? (uint32_t)INT32_MIN : (uint32_t)((int32_t)dst / sd);
}

static uint32_t jit_mod32(uint32_t dst, uint32_t src, int16_t off) {
    if (off == 0) {
        return src ? dst % src : dst;
    }
    if (!src) return dst;
    auto sd = (int32_t)src;
    return (sd == -1 && (int32_t)dst == INT32_MIN)
        ? 0 : (uint32_t)((int32_t)dst % sd);
}

// ---------------------------------------------------------------------------
// MMU slow-path helpers for JIT (TLB miss)
// ---------------------------------------------------------------------------

void* JitCompiler::helper_mmu(vm* v, uint64_t addr, uint64_t size) {
    return v->mmu_slow(addr, (size_t)size);
}

void* JitCompiler::helper_mmu_w(vm* v, uint64_t addr, uint64_t size) {
    return v->mmu_w_slow(addr, (size_t)size);
}

// ---------------------------------------------------------------------------
// JIT control-flow helpers (called from JIT-generated code)
// ---------------------------------------------------------------------------

// Safepoint: check exit/stop flags and pending signals.
// Returns 0 = all clear (JIT continues), 1 = abort JIT.
int JitCompiler::helper_safepoint(vm* v) {
    const bpf_insn* saved_pc = v->pc;
    if (!v->safepoint()) {
        return 1;  // VM killed/exited/stopped
    }
    // If safepoint (via handle_signals) changed pc (e.g. pushed a signal
    // handler frame), abort JIT so the loop re-enters from the new pc.
    if (v->pc != saved_pc) {
        return 1;
    }
    return 0;
}

// BPF-to-BPF CALL: push a frame with the given guest return address.
bool JitCompiler::helper_push_frame(vm* v, uint64_t ret_addr) {
    return v->push_frame(ret_addr);
}

// EXIT: pop a frame.  Returns the guest return address (0 = stack bottom).
uint64_t JitCompiler::helper_pop_frame(vm* v) {
    return v->pop_frame();
}

// Syscall CALL (src_reg==0): invoke do_syscall().
// Returns true = VM continues, false = VM should stop.
bool JitCompiler::helper_do_syscall(vm* v, uint32_t call_id) {
    const bpf_insn* saved_pc = v->pc;
    bool ok = v->do_syscall(call_id);
    if (!ok) {
        v->flags.fetch_or(vm::VM_EXITED, std::memory_order_release);
        return false;
    }
    // If the syscall handler changed pc (e.g. longjmp), return false to abort JIT.
    // step() will detect the pc change and return to run(), which re-enters JIT
    // at the new pc. No need to permanently disable JIT — cached functions remain
    // valid since they are stateless (all VM state lives in the vm struct).
    if (v->pc != saved_pc) {
        return false;
    }
    // A syscall may have set flags (e.g. kill(SIGSTOP) sets VM_STOPPED) or
    // queued a signal (e.g. kill() to self).  For flags, abort JIT immediately.
    // For pending signals, do NOT abort here — let the JIT continue executing
    // the next BPF instructions (which will save r0 to a callee-saved register)
    // and deliver the signal at the next safepoint (back-edge or function boundary).
    // Aborting here would cause the prologue safepoint of the continuation function
    // to clobber r0 (caller-saved) before the BPF code can save it.
    uint32_t f = v->flags.load(std::memory_order_acquire);
    if (f & (vm::VM_EXITED | vm::VM_KILLED | vm::VM_STOPPED)) {
        return false;
    }
    return true;
}

// Indirect call (BPF_CALL | BPF_X): push frame, resolve target, update pc.
// Always returns false to abort JIT — the target is dynamic.
bool JitCompiler::helper_call_indirect(vm* v, uint64_t ret_gpa, uint64_t target) {
    if (!v->push_frame(ret_gpa)) {
        return false;  // stack overflow
    }
    void* host = v->mmu(target);
    if (!host) {
        v->flags.fetch_or(vm::VM_KILLED, std::memory_order_release);
        return false;
    }
    v->pc = (const bpf_insn*)host;
    return false;  // always abort: pc changed to dynamic target
}

// Top-level return: convert guest return address to host pointer and update vm::pc.
int JitCompiler::helper_return_to_caller(vm* v, uint64_t ret_gpa) {
    void* host = v->mmu(ret_gpa);
    if (!host) {
        v->flags.fetch_or(vm::VM_KILLED, std::memory_order_release);
        return -1;
    }
    v->pc = (const bpf_insn*)host;
    return 0;
}

// ---------------------------------------------------------------------------
// Inline TLB fast-path helper
// ---------------------------------------------------------------------------
// Emits the inline TLB lookup for a memory instruction.  On TLB hit, RAX ends
// up holding the host pointer.  On miss, falls through to the slow-path label.
//
// Input:  RAX = guest address
// Output: RAX = host pointer (fast path)  or  RAX unchanged (slow path)
// Clobbers: RCX, RDX
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// JitCompiler implementation
// ---------------------------------------------------------------------------

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winvalid-offsetof"
const size_t JitCompiler::off_reg_            = offsetof(vm, reg);
const size_t JitCompiler::off_flags_          = offsetof(vm, flags);
const size_t JitCompiler::off_signal_pending_ = offsetof(vm, signal_pending);
const size_t JitCompiler::off_signal_depth_   = offsetof(vm, signal_depth);
const size_t JitCompiler::off_tlb_            = offsetof(vm, tlb);
const size_t JitCompiler::off_pc_             = offsetof(vm, pc);
#pragma GCC diagnostic pop

JitCompiler::JitCompiler() {
    const char* env = getenv("JIT_ENABLE");
    enabled_ = (env == nullptr || strcmp(env, "0") != 0);
}

JitCompiler::~JitCompiler() {
    for (auto& [pc, f] : functions_) {
        if (f.code) munmap(f.code, f.code_size);
    }
}

// ---------------------------------------------------------------------------
// discover_reachable: BFS to find all reachable BPF instructions
// ---------------------------------------------------------------------------
// Returns a vector<bool> indexed by BPF instruction offset from entry_pc.
// seg_limit is the number of instructions from entry_pc to segment end
// (used only as an upper bound for jump targets).
// Also fills back_edge_targets: indices that are targets of backward jumps.
// func_size is set to the function extent: one past the highest reachable index
// (so the caller can size data structures to func_size instead of seg_limit).
// ---------------------------------------------------------------------------
std::vector<bool> JitCompiler::discover_reachable(
    const bpf_insn* start, int seg_limit,
    std::vector<bool>& back_edge_targets, int& func_size)
{
    func_size = 0;
    if (seg_limit <= 0) return {};

    // BFS uses the full segment limit as bounds for jump targets,
    // but we track the actual extent of reachable instructions.
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

    enqueue(0); // BFS from entry_pc (index 0 of the local range)

    while (!q.empty()) {
        int i = q.front();
        q.pop();
        const bpf_insn* insn = start + i;
        uint8_t cls = insn->code & 0x07;
        uint8_t op = insn->code & 0xf0;
        bool is_x = (insn->code & 0x08) == BPF_X;

        // Default: sequential flow to next instruction
        int next = i + 1;

        switch (cls) {
        case BPF_LD:
            // LD DW: consumes 2 instruction slots
            if ((insn->code & 0xe0) == BPF_IMM && (insn->code & 0x18) == BPF_DW) {
                next = i + 2;
            }
            enqueue(next);
            break;

        case BPF_JMP:
            if (op == BPF_JA) {
                // Unconditional jump: target = i + 1 + off
                int target = i + 1 + insn->off;
                if (target >= 0 && target < seg_limit) {
                    if (target <= i) back_edge_targets[target] = true;
                    enqueue(target);
                }
            } else if (op == BPF_CALL) {
                if (is_x) {
                    // Indirect call: can't determine target statically.
                    // Mark as reachable but don't follow.
                    enqueue(next);
                } else if (insn->src_reg == 0) {
                    // Syscall: no control flow change
                    enqueue(next);
                } else if (insn->src_reg == 1) {
                    // BPF-to-BPF: callee compiled independently,
                    // only follow return address (next instruction).
                    enqueue(next);
                } else {
                    enqueue(next);
                }
            } else if (op == BPF_EXIT) {
                // EXIT: terminates current function — do not enqueue next.
                // Code after EXIT is only reachable if explicitly jumped to.
            } else {
                // Conditional jump: both fall-through and target
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
                // JA32: target = i + 1 + imm
                int target = i + 1 + insn->imm;
                if (target >= 0 && target < seg_limit) {
                    if (target <= i) back_edge_targets[target] = true;
                    enqueue(target);
                }
            } else {
                // Conditional jump (32-bit): both paths
                int target = i + 1 + insn->off;
                if (target >= 0 && target < seg_limit) {
                    if (target <= i) back_edge_targets[target] = true;
                    enqueue(target);
                }
                enqueue(next);
            }
            break;

        default:
            // ALU, LD (non-DW), LDX, ST, STX: sequential
            enqueue(next);
            break;
        }
    }

    if (max_reached < 0) return {};

    // LD DW consumes 2 slots; if the last reachable insn is LD DW, extend by 1
    if (max_reached < seg_limit - 1) {
        const bpf_insn* insn = start + max_reached;
        if ((insn->code & 0x07) == BPF_LD &&
            (insn->code & 0xe0) == BPF_IMM &&
            (insn->code & 0x18) == BPF_DW) {
            max_reached++;
        }
    }

    func_size = max_reached + 1;

    // Truncate vectors to function extent
    reachable.resize(func_size);
    back_edge_targets.resize(func_size);

    // Post-process: mark second halves of LD DW as consumed (not real instructions)
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
// Helper call (div/mod/etc.)
// ---------------------------------------------------------------------------

void JitCompiler::emit_helper_call(Emitter& e, void* helper, int32_t dst_disp) {
    e.emit8(0x48); e.emit8(0x89); e.emit8(0xC7);  // mov rdi, rax
    e.emit8(0x48); e.emit8(0x89); e.emit8(0xCE);  // mov rsi, rcx
    e.call_helper(helper);
    e.store_r64(dst_disp, X86::RAX);
}

// ---------------------------------------------------------------------------
// TLB memory access helpers
// ---------------------------------------------------------------------------

MemAccessContext JitCompiler::begin_mem_access(Emitter& e, int32_t base_disp,
                                               int16_t offset, int access_size, bool is_write) {
    MemAccessContext ctx{};
    int32_t tlb_off = (int32_t)off_tlb_;

    // Load guest address into RAX and apply BPF offset
    e.load_r64(X86::RAX, base_disp);
    if (offset != 0) {
        e.emit8(0x48); e.emit8(0x05); e.emit32((uint32_t)(int32_t)offset); // add rax, offset
    }

    // --- Inline TLB lookup (fast path) ---

    // Compute TLB index: ((addr >> 20) & 0xF) * 32 = (addr >> 15) & 0x1F0
    e.emit8(0x48); e.emit8(0x89); e.emit8(0xC1);                   // mov rcx, rax
    e.emit8(0x48); e.emit8(0xC1); e.emit8(0xE9); e.emit8(15);     // shr rcx, 15
    e.emit8(0x81); e.emit8(0xE1); e.emit32(0x1F0);                 // and ecx, 0x1F0

    // Bounds check 1: addr >= entry.guest_base
    e.sib_op_rax(0x3B, tlb_off);                                    // cmp rax, [rbx+rcx+tlb_off]
    ctx.miss_jumps.push_back(e.size());
    e.emit8(0x0F); e.emit8(0x82); e.emit32(0);                     // JB .slow

    // Bounds check 2: addr + size <= entry.guest_end
    // lea rdx, [rax + size]
    e.emit8(0x48); e.emit8(0x8D); e.emit8(0x90);                   // lea rdx, [rax + disp32]
    e.emit32((uint32_t)access_size);
    e.sib_op_rdx(0x3B, tlb_off + 8);                                // cmp rdx, [rbx+rcx+tlb_off+8]
    ctx.miss_jumps.push_back(e.size());
    e.emit8(0x0F); e.emit8(0x87); e.emit32(0);                     // JA .slow

    if (is_write) {
        // Write permission: flags & PF_W (0x2)
        e.sib_test_dword(tlb_off + 24, 0x2);
        ctx.miss_jumps.push_back(e.size());
        e.emit8(0x0F); e.emit8(0x84); e.emit32(0);                 // JZ .slow

        // No CoW: !cow (byte at offset 28)
        e.sib_cmp_byte(tlb_off + 28, 0);
        ctx.miss_jumps.push_back(e.size());
        e.emit8(0x0F); e.emit8(0x85); e.emit32(0);                 // JNE .slow
    }

    // TLB hit: host_ptr = host_base + (addr - guest_base)
    e.sib_op_rax(0x2B, tlb_off);                                    // sub rax, [rbx+rcx+tlb_off]
    e.sib_op_rax(0x03, tlb_off + 16);                               // add rax, [rbx+rcx+tlb_off+16]

    // JMP .done (rel32 placeholder — patched by finish_mem_access)
    ctx.done_jmp = e.size();
    e.emit8(0xE9); e.emit32(0);

    // --- Slow path: TLB miss — call C helper ---
    ctx.slow_start = e.size();
    e.mov_rdi_rbx();                                                 // mov rdi, rbx (vm*)
    e.mov_rsi_rax();                                                 // mov rsi, rax (guest addr)
    e.emit8(0xBA); e.emit32((uint32_t)access_size);                 // mov edx, size
    e.call_helper(is_write ? (void*)&JitCompiler::helper_mmu_w
                           : (void*)&JitCompiler::helper_mmu);

    // Test for null (memory violation)
    e.test_rax_rax();
    ctx.abort_jumps.push_back(e.size());
    e.emit8(0x0F); e.emit8(0x84); e.emit32(0);                     // JZ .vm_exit

    // .done: RAX = host pointer
    ctx.done_offset = e.size();
    return ctx;
}

void JitCompiler::finish_mem_access(Emitter& e, MemAccessContext& ctx,
                                     std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    // Patch miss jumps → .slow
    for (size_t off : ctx.miss_jumps) {
        uint32_t rel = (uint32_t)(ctx.slow_start - (off + 6));
        memcpy(e.data() + off + 2, &rel, 4);
    }
    // Patch fast-path JMP → .done
    {
        uint32_t rel = (uint32_t)(ctx.done_offset - (ctx.done_jmp + 5));
        memcpy(e.data() + ctx.done_jmp + 1, &rel, 4);
    }
    // Record abort jumps for later patching to .vm_exit
    for (size_t off : ctx.abort_jumps) {
        abort_patches.push_back({off, bpf_index});
    }
}

// ---------------------------------------------------------------------------
// ALU (unified template for ALU64 and ALU32)
// ---------------------------------------------------------------------------

template<bool Is64>
bool JitCompiler::emit_alu(Emitter& e, const bpf_insn* insn) {
    bool is_x = (insn->code & 0x08) == BPF_X;
    uint8_t op = insn->code & 0xf0;
    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    int32_t src_disp = off_reg_ + insn->src_reg * 8;

    // Helper lambdas to select 64/32 bit variants
    auto load_dst = [&]() {
        if constexpr (Is64) e.load_r64(X86::RAX, dst_disp);
        else                e.load_r32(X86::RAX, dst_disp);
    };
    auto load_src = [&]() {
        if constexpr (Is64) e.load_r64(X86::RCX, src_disp);
        else                e.load_r32(X86::RCX, src_disp);
    };

    // ── MOV (off == 0) ──
    if (op == BPF_MOV && insn->off == 0) {
        // ALU64: self-move is a no-op.
        // ALU32: NOT a no-op — 32-bit write clears the upper 32 bits.
        if constexpr (Is64) {
            if (is_x && insn->dst_reg == insn->src_reg) return true;
        }
        if (is_x) {
            load_src();
            e.store_r64(dst_disp, X86::RCX);
        } else {
            if constexpr (Is64) e.store_imm64(dst_disp, insn->imm);
            else                e.store_imm32_zext(dst_disp, insn->imm);
        }
        return true;
    }

    // ── NEG ──
    if (op == BPF_NEG) {
        load_dst();
        if constexpr (Is64) e.neg64(); else e.neg32();
        e.store_r64(dst_disp, X86::RAX);
        return true;
    }

    // ── MOV with sign-extension (off != 0) ──
    if (op == BPF_MOV) {
        if (is_x) {
            e.load_r64(X86::RAX, src_disp);
        } else {
            e.emit8(0x48); e.emit8(0xB8); e.emit64((uint64_t)(int64_t)insn->imm); // movabs rax, imm64
        }
        if constexpr (Is64) {
            switch (insn->off) {
            case 8:  e.emit8(0x48); e.emit8(0x0F); e.emit8(0xBE); e.emit8(0xC0); break; // movsx rax, al
            case 16: e.emit8(0x48); e.emit8(0x0F); e.emit8(0xBF); e.emit8(0xC0); break; // movsx rax, ax
            case 32: e.emit8(0x48); e.emit8(0x63); e.emit8(0xC0); break;                 // movsxd rax, eax
            default: return false;
            }
        } else {
            switch (insn->off) {
            case 8:  e.emit8(0x0F); e.emit8(0xBE); e.emit8(0xC0); break; // movsx eax, al
            case 16: e.emit8(0x0F); e.emit8(0xBF); e.emit8(0xC0); break; // movsx eax, ax
            default: return false;
            }
        }
        e.store_r64(dst_disp, X86::RAX);
        return true;
    }

    // ── END (byte-swap / zero-extend) ──
    if (op == BPF_END) {
        // BPF_K le64 is a no-op on native little-endian
        if (!is_x && insn->imm == 64)
            return true;

        if (is_x) {
            // BPF_X = big-endian byte swap
            if constexpr (Is64) {
                e.load_r64(X86::RAX, dst_disp);
            } else {
                e.load_r32(X86::RAX, dst_disp);
            }
            switch (insn->imm) {
            case 16:
                e.emit8(0x66); e.emit8(0xC1); e.emit8(0xC0); e.emit8(0x08); // rol ax, 8
                e.emit8(0x0F); e.emit8(0xB7); e.emit8(0xC0);                // movzx eax, ax
                break;
            case 32:
                e.emit8(0x0F); e.emit8(0xC8);                               // bswap eax
                break;
            case 64:
                if constexpr (!Is64) return false;                            // ALU32 has no 64-bit bswap
                e.emit8(0x48); e.emit8(0x0F); e.emit8(0xC8);               // bswap rax
                break;
            default: return false;
            }
        } else {
            // BPF_K = little-endian zero-extend / truncate
            switch (insn->imm) {
            case 16:
                e.load_r32(X86::RAX, dst_disp);
                e.emit8(0x25); e.emit32(0xFFFF);                             // and eax, 0xFFFF
                break;
            case 32:
                e.load_r32(X86::RAX, dst_disp);                            // zero-extends to 64
                break;
            default: return false;
            }
        }
        e.store_r64(dst_disp, X86::RAX);
        return true;
    }

    // ── Peephole: no-op operations ──
    if (!is_x) {
        if (insn->imm == 0 && (op == BPF_ADD || op == BPF_SUB || op == BPF_OR ||
            op == BPF_XOR || op == BPF_LSH || op == BPF_RSH || op == BPF_ARSH)) {
            return true;
        }
        if (insn->imm == 1 && (op == BPF_MUL || op == BPF_DIV)) {
            return true;
        }
    }

    // ── Arithmetic / logic / shift ──
    constexpr uint8_t shift_mask = Is64 ? 0x3F : 0x1F;

    load_dst();
    if (is_x) load_src();

    switch (op) {
    case BPF_ADD:  is_x ? (Is64 ? e.add64() : e.add32()) : (Is64 ? e.add64_imm(insn->imm) : e.add32_imm(insn->imm)); break;
    case BPF_SUB:  is_x ? (Is64 ? e.sub64() : e.sub32()) : (Is64 ? e.sub64_imm(insn->imm) : e.sub32_imm(insn->imm)); break;
    case BPF_OR:   is_x ? (Is64 ? e.or64()  : e.or32())  : (Is64 ? e.or64_imm(insn->imm)  : e.or32_imm(insn->imm));  break;
    case BPF_AND:  is_x ? (Is64 ? e.and64() : e.and32()) : (Is64 ? e.and64_imm(insn->imm) : e.and32_imm(insn->imm)); break;
    case BPF_XOR:  is_x ? (Is64 ? e.xor64() : e.xor32()) : (Is64 ? e.xor64_imm(insn->imm) : e.xor32_imm(insn->imm)); break;
    case BPF_LSH:
        if (is_x) { if constexpr (Is64) e.shl64_cl(); else e.shl32_cl(); }
        else { if constexpr (Is64) e.shl64_imm(insn->imm & shift_mask); else e.shl32_imm(insn->imm & shift_mask); }
        break;
    case BPF_RSH:
        if (is_x) { if constexpr (Is64) e.shr64_cl(); else e.shr32_cl(); }
        else { if constexpr (Is64) e.shr64_imm(insn->imm & shift_mask); else e.shr32_imm(insn->imm & shift_mask); }
        break;
    case BPF_ARSH:
        if (is_x) { if constexpr (Is64) e.sar64_cl(); else e.sar32_cl(); }
        else { if constexpr (Is64) e.sar64_imm(insn->imm & shift_mask); else e.sar32_imm(insn->imm & shift_mask); }
        break;
    case BPF_MUL:  is_x ? (Is64 ? e.mul64() : e.mul32()) : (Is64 ? e.mul64_imm(insn->imm) : e.mul32_imm(insn->imm)); break;
    case BPF_DIV: {
        if (!is_x) {
            e.emit8(0x48); e.emit8(0xC7); e.emit8(0xC1); e.emit32(insn->imm); // mov rcx, imm32 (sign-ext)
        }
        e.emit8(0xBA); e.emit32((uint32_t)(int32_t)insn->off); // mov edx, off
        emit_helper_call(e, Is64 ? (void*)jit_div64 : (void*)jit_div32, dst_disp);
        return true;
    }
    case BPF_MOD: {
        if (!is_x) {
            e.emit8(0x48); e.emit8(0xC7); e.emit8(0xC1); e.emit32(insn->imm); // mov rcx, imm32 (sign-ext)
        }
        e.emit8(0xBA); e.emit32((uint32_t)(int32_t)insn->off); // mov edx, off
        emit_helper_call(e, Is64 ? (void*)jit_mod64 : (void*)jit_mod32, dst_disp);
        return true;
    }
    default: return false;
    }

    e.store_r64(dst_disp, X86::RAX);
    return true;
}

// Explicit template instantiations
template bool JitCompiler::emit_alu<true>(Emitter& e, const bpf_insn* insn);
template bool JitCompiler::emit_alu<false>(Emitter& e, const bpf_insn* insn);

// ---------------------------------------------------------------------------
// LD: load 64-bit immediate (no memory access)
// ---------------------------------------------------------------------------

bool JitCompiler::emit_ld(Emitter& e, const bpf_insn* insn) {
    uint8_t mode = insn->code & 0xe0;
    uint8_t size = insn->code & 0x18;
    if (mode != BPF_IMM || size != BPF_DW) return false;
    if (insn->dst_reg >= 10) return false;

    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    uint64_t imm64 = (uint64_t)(uint32_t)(insn + 1)->imm << 32 | (uint32_t)insn->imm;

    e.emit8(0x48); e.emit8(0xB8); e.emit64(imm64);
    e.store_r64(dst_disp, X86::RAX);
    return true;
}

// ---------------------------------------------------------------------------
// LDX: load from memory with inline TLB
// ---------------------------------------------------------------------------

bool JitCompiler::emit_ldx(Emitter& e, const bpf_insn* insn,
                            std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    uint8_t mode = insn->code & 0xe0;
    uint8_t size_field = insn->code & 0x18;
    if (mode != BPF_MEM && mode != BPF_MEMSX) return false;
    if (mode == BPF_MEMSX && size_field == BPF_DW) return false;
    if (insn->dst_reg >= 10) return false;

    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    int32_t src_disp = off_reg_ + insn->src_reg * 8;
    int access_size;
    switch (size_field) {
    case BPF_DW: access_size = 8; break;
    case BPF_W:  access_size = 4; break;
    case BPF_H:  access_size = 2; break;
    case BPF_B:  access_size = 1; break;
    default: return false;
    }

    auto ctx = begin_mem_access(e, src_disp, insn->off, access_size, /*is_write=*/false);

    if (mode == BPF_MEM) {
        switch (size_field) {
        case BPF_DW: e.emit8(0x48); e.emit8(0x8B); e.emit8(0x00); break;
        case BPF_W:  e.emit8(0x8B); e.emit8(0x00); break;
        case BPF_H:  e.emit8(0x0F); e.emit8(0xB7); e.emit8(0x00); break;
        case BPF_B:  e.emit8(0x0F); e.emit8(0xB6); e.emit8(0x00); break;
        }
    } else {
        switch (size_field) {
        case BPF_W:  e.emit8(0x48); e.emit8(0x63); e.emit8(0x00); break;
        case BPF_H:  e.emit8(0x48); e.emit8(0x0F); e.emit8(0xBF); e.emit8(0x00); break;
        case BPF_B:  e.emit8(0x48); e.emit8(0x0F); e.emit8(0xBE); e.emit8(0x00); break;
        default: return false;
        }
    }

    e.store_r64(dst_disp, X86::RAX);
    finish_mem_access(e, ctx, abort_patches, bpf_index);
    return true;
}

// ---------------------------------------------------------------------------
// ST: store immediate to memory with inline TLB
// ---------------------------------------------------------------------------

bool JitCompiler::emit_st(Emitter& e, const bpf_insn* insn,
                           std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    uint8_t mode = insn->code & 0xe0;
    uint8_t size_field = insn->code & 0x18;
    if (mode != BPF_MEM) return false;

    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    int access_size;
    switch (size_field) {
    case BPF_DW: access_size = 8; break;
    case BPF_W:  access_size = 4; break;
    case BPF_H:  access_size = 2; break;
    case BPF_B:  access_size = 1; break;
    default: return false;
    }

    auto ctx = begin_mem_access(e, dst_disp, insn->off, access_size, /*is_write=*/true);

    switch (size_field) {
    case BPF_DW: e.emit8(0x48); e.emit8(0xC7); e.emit8(0x00); e.emit32(insn->imm); break;
    case BPF_W:  e.emit8(0xC7); e.emit8(0x00); e.emit32(insn->imm); break;
    case BPF_H:  e.emit8(0x66); e.emit8(0xC7); e.emit8(0x00); e.emit16((uint16_t)insn->imm); break;
    case BPF_B:  e.emit8(0xC6); e.emit8(0x00); e.emit8((uint8_t)insn->imm); break;
    }

    finish_mem_access(e, ctx, abort_patches, bpf_index);
    return true;
}

// ---------------------------------------------------------------------------
// STX: store register to memory with inline TLB
// ---------------------------------------------------------------------------

bool JitCompiler::emit_stx(Emitter& e, const bpf_insn* insn,
                            std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    uint8_t mode = insn->code & 0xe0;
    uint8_t size_field = insn->code & 0x18;
    if (mode == BPF_ATOMIC) return emit_stx_atomic(e, insn, abort_patches, bpf_index);
    if (mode != BPF_MEM) return false;

    int32_t src_disp = off_reg_ + insn->src_reg * 8;
    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    int access_size;
    switch (size_field) {
    case BPF_DW: access_size = 8; break;
    case BPF_W:  access_size = 4; break;
    case BPF_H:  access_size = 2; break;
    case BPF_B:  access_size = 1; break;
    default: return false;
    }

    auto ctx = begin_mem_access(e, dst_disp, insn->off, access_size, /*is_write=*/true);

    e.load_r64(X86::RCX, src_disp);

    switch (size_field) {
    case BPF_DW: e.emit8(0x48); e.emit8(0x89); e.emit8(0x08); break;
    case BPF_W:  e.emit8(0x89); e.emit8(0x08); break;
    case BPF_H:  e.emit8(0x66); e.emit8(0x89); e.emit8(0x08); break;
    case BPF_B:  e.emit8(0x88); e.emit8(0x08); break;
    }

    finish_mem_access(e, ctx, abort_patches, bpf_index);
    return true;
}

// ---------------------------------------------------------------------------
// STX atomic: locked read-modify-write with inline TLB
// ---------------------------------------------------------------------------

bool JitCompiler::emit_stx_atomic(Emitter& e, const bpf_insn* insn,
                                    std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    uint8_t size_field = insn->code & 0x18;
    if (size_field != BPF_DW && size_field != BPF_W) return false;

    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    int32_t src_disp = off_reg_ + insn->src_reg * 8;
    int32_t r0_disp  = off_reg_;
    bool is_dw = (size_field == BPF_DW);
    int access_size = is_dw ? 8 : 4;

    auto ctx = begin_mem_access(e, dst_disp, insn->off, access_size, /*is_write=*/true);

    e.mov_rdx_rax();
    e.load_r64(X86::RCX, src_disp);

    int32_t op = insn->imm;

    if (op == (BPF_OR  | BPF_FETCH) ||
        op == (BPF_AND | BPF_FETCH) ||
        op == (BPF_XOR | BPF_FETCH)) {
        uint8_t alu_opcode = ((op & ~BPF_FETCH) == BPF_OR)  ? 0x09
                            : ((op & ~BPF_FETCH) == BPF_AND) ? 0x21
                            : 0x31;

        e.load_r64(X86::RDI, r0_disp);  // save r(0)

        size_t loop_start = e.size();

        if (is_dw) {
            e.emit8(0x48); e.emit8(0x8B); e.emit8(0x02);
        } else {
            e.emit8(0x8B); e.emit8(0x02);
        }

        if (is_dw) e.emit8(0x48);
        e.emit8(0x89); e.emit8(0xC7);
        if (is_dw) e.emit8(0x48);
        e.emit8(alu_opcode); e.emit8(0xCF);

        e.emit8(0xF0);
        if (is_dw) e.emit8(0x48);
        e.emit8(0x0F); e.emit8(0xB1); e.emit8(0x3A);

        e.emit8(0x75);
        e.emit8(0);  // rel8 placeholder
        auto loop_end = e.size();
        int8_t rel = (int8_t)(loop_start - loop_end);
        e.data()[loop_end - 1] = (uint8_t)rel;

        e.store_r64(r0_disp, X86::RDI);  // restore r(0) first
        e.store_r64(src_disp, X86::RCX);  // then write FETCH result (may overlap r0)

        finish_mem_access(e, ctx, abort_patches, bpf_index);
        return true;
    }

    switch (op) {
    case BPF_ADD | BPF_FETCH:
        e.emit8(0xF0);
        if (is_dw) e.emit8(0x48);
        e.emit8(0x0F); e.emit8(0xC1); e.emit8(0x0A);  // LOCK XADD [RDX], RCX
        e.store_r64(src_disp, X86::RCX);
        break;
    case BPF_ADD:
        e.emit8(0xF0);
        if (is_dw) e.emit8(0x48);
        e.emit8(0x01); e.emit8(0x0A);  // LOCK ADD [RDX], RCX
        break;

    case BPF_OR:
    case BPF_AND:
    case BPF_XOR: {
        uint8_t opcode = (op == BPF_OR) ? 0x09
                       : (op == BPF_AND) ? 0x21
                       : 0x31;
        e.emit8(0xF0);
        if (is_dw) e.emit8(0x48);
        e.emit8(opcode); e.emit8(0x0A);
        break;
    }

    case BPF_XCHG:
        if (is_dw) e.emit8(0x48);
        e.emit8(0x87); e.emit8(0x0A);
        e.store_r64(src_disp, X86::RCX);
        break;

    case BPF_CMPXCHG:
        e.load_r64(X86::RAX, r0_disp);
        e.emit8(0xF0);
        if (is_dw) e.emit8(0x48);
        e.emit8(0x0F); e.emit8(0xB1); e.emit8(0x0A);
        e.store_r64(r0_disp, X86::RAX);
        break;

    default:
        finish_mem_access(e, ctx, abort_patches, bpf_index);
        return false;
    }

    finish_mem_access(e, ctx, abort_patches, bpf_index);
    return true;
}

// ---------------------------------------------------------------------------
// Conditional jumps (unified template for JMP64 and JMP32)
// ---------------------------------------------------------------------------

template<bool Is64>
bool JitCompiler::emit_jmp(Emitter& e, const bpf_insn* insn, int current_index,
                            std::vector<JumpPlaceholder>& placeholders) {
    uint8_t op = insn->code & 0xf0;
    bool is_x = (insn->code & 0x08) == BPF_X;
    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    int32_t src_disp = off_reg_ + insn->src_reg * 8;

    if constexpr (Is64) {
        if (op == BPF_JA || op == BPF_CALL || op == BPF_EXIT) return false;
    } else {
        if (op == BPF_JA) return false;
    }

    uint8_t x86_cc = 0;
    bool is_test = false;

    switch (op) {
    case BPF_JEQ:  x86_cc = 0x84; break;
    case BPF_JNE:  x86_cc = 0x85; break;
    case BPF_JGT:  x86_cc = 0x87; break;
    case BPF_JGE:  x86_cc = 0x83; break;
    case BPF_JLT:  x86_cc = 0x82; break;
    case BPF_JLE:  x86_cc = 0x86; break;
    case BPF_JSGT: x86_cc = 0x8F; break;
    case BPF_JSGE: x86_cc = 0x8D; break;
    case BPF_JSLT: x86_cc = 0x8C; break;
    case BPF_JSLE: x86_cc = 0x8E; break;
    case BPF_JSET: x86_cc = 0x85; is_test = true; break;
    default: return false;
    }

    auto load_dst = [&]() {
        if constexpr (Is64) e.load_r64(X86::RAX, dst_disp);
        else                e.load_r32(X86::RAX, dst_disp);
    };
    auto load_src = [&]() {
        if constexpr (Is64) e.load_r64(X86::RCX, src_disp);
        else                e.load_r32(X86::RCX, src_disp);
    };

    load_dst();

    if (is_test) {
        if (is_x) {
            load_src();
            if constexpr (Is64) e.test64(); else e.test32();
        } else {
            if constexpr (Is64) e.test64_imm(insn->imm); else e.test32_imm(insn->imm);
        }
    } else {
        if (is_x) {
            load_src();
            if constexpr (Is64) e.cmp64(); else e.cmp32();
        } else {
            if constexpr (Is64) e.cmp64_imm(insn->imm); else e.cmp32_imm(insn->imm);
        }
    }

    size_t jcc_off = e.size();
    e.jcc_rel32(x86_cc);

    int target = current_index + 1 + insn->off;
    placeholders.push_back({jcc_off, target, PlaceholderKind::Jcc});
    return true;
}

// Explicit template instantiations
template bool JitCompiler::emit_jmp<true>(Emitter& e, const bpf_insn* insn, int current_index,
                                           std::vector<JumpPlaceholder>& placeholders);
template bool JitCompiler::emit_jmp<false>(Emitter& e, const bpf_insn* insn, int current_index,
                                            std::vector<JumpPlaceholder>& placeholders);

// ---------------------------------------------------------------------------
// Unconditional jump (JA) — JMP64
// ---------------------------------------------------------------------------

void JitCompiler::emit_ja(Emitter& e, const bpf_insn* insn, int current_index,
                           std::vector<JumpPlaceholder>& placeholders) {
    size_t jmp_off = e.size();
    e.jmp_rel32();
    int target = current_index + 1 + insn->off;
    placeholders.push_back({jmp_off, target, PlaceholderKind::Jmp});
}

// ---------------------------------------------------------------------------
// Unconditional jump (JA) — JMP32 (uses imm instead of off)
// ---------------------------------------------------------------------------

void JitCompiler::emit_ja32(Emitter& e, const bpf_insn* insn, int current_index,
                              std::vector<JumpPlaceholder>& placeholders) {
    size_t jmp_off = e.size();
    e.jmp_rel32();
    int target = current_index + 1 + insn->imm;
    placeholders.push_back({jmp_off, target, PlaceholderKind::Jmp});
}

// ---------------------------------------------------------------------------
// CALL syscall (src_reg==0)
// ---------------------------------------------------------------------------

void JitCompiler::emit_call_syscall(Emitter& e, const bpf_insn* insn, int current_index,
                                      const bpf_insn* entry_pc,
                                      std::vector<AbortPatchInfo>& abort_patches) {
    // Update vm::pc to the current BPF instruction's host address.
    // This ensures syscall handlers (e.g. setjmp) see the correct pc.
    // movabs rax, instruction_host_addr
    const bpf_insn* insn_host = entry_pc + current_index;
    e.mov_rax_imm64((uint64_t)(uintptr_t)insn_host);
    // mov [rbx + off_pc_], rax
    e.emit8(0x48); e.emit8(0x89); e.emit8(0x83); e.emit32((uint32_t)off_pc_);
    // mov rdi, rbx  (vm*)
    e.mov_rdi_rbx();
    // mov esi, imm32 (call_id)
    e.emit8(0xBE); e.emit32((uint32_t)insn->imm);
    // call jit_do_syscall
    e.call_helper((void*)&JitCompiler::helper_do_syscall);
    // test al, al
    e.test_al_al();
    // jz .vm_exit
    abort_patches.push_back({e.size(), current_index});
    e.emit8(0x0F); e.emit8(0x84); e.emit32(0);
}

// ---------------------------------------------------------------------------
// CALL BPF-to-BPF (src_reg==1)
// ---------------------------------------------------------------------------

void JitCompiler::emit_call_bpf(Emitter& e, const bpf_insn* insn, int current_index,
                                  uint64_t ret_gpa,
                                  const bpf_insn* entry_pc,
                                  size_t vm_exit_offset,
                                  std::vector<AbortPatchInfo>& abort_patches) {
    // push_frame(ret_gpa)
    // mov rdi, rbx
    e.mov_rdi_rbx();
    // movabs rsi, ret_gpa
    e.emit8(0x48); e.emit8(0xBE); e.emit64(ret_gpa);
    // call jit_push_frame
    e.call_helper((void*)&JitCompiler::helper_push_frame);
    // test al, al
    e.test_al_al();
    // jz .vm_exit
    abort_patches.push_back({e.size(), current_index});
    e.emit8(0x0F); e.emit8(0x84); e.emit32(0);

    // Set vm::pc to callee entry.
    const bpf_insn* callee_pc = entry_pc + current_index + 1 + insn->imm;
    e.mov_rax_imm64((uint64_t)(uintptr_t)callee_pc);
    // mov [rbx + off_pc_], rax
    e.emit8(0x48); e.emit8(0x89); e.emit8(0x83); e.emit32((uint32_t)off_pc_);

    // Exit JIT — step() will re-enter JIT for the callee.
    size_t jmp_off = e.size();
    e.emit8(0xE9); e.emit32(0);
    uint32_t rel = (uint32_t)(vm_exit_offset - (jmp_off + 5));
    memcpy(e.data() + jmp_off + 1, &rel, 4);
}

// ---------------------------------------------------------------------------
// CALL indirect (BPF_CALL | BPF_X): target address from register
// ---------------------------------------------------------------------------

void JitCompiler::emit_call_indirect(Emitter& e, const bpf_insn* insn, int current_index,
                                      uint64_t ret_gpa,
                                      std::vector<AbortPatchInfo>& abort_patches) {
    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    // mov rdi, rbx           (1st arg: vm*)
    e.mov_rdi_rbx();
    // movabs rsi, ret_gpa    (2nd arg: guest return address)
    e.emit8(0x48); e.emit8(0xBE); e.emit64(ret_gpa);
    // mov rdx, [rbx + dst_disp]  (3rd arg: target = r(dst_reg))
    e.load_r64(X86::RDX, dst_disp);
    // call jit_call_indirect
    e.call_helper((void*)&JitCompiler::helper_call_indirect);
    // Helper always returns false (0) — unconditionally abort JIT.
    // test al, al
    e.test_al_al();
    // jz .vm_exit  (always taken since al==0)
    abort_patches.push_back({e.size(), current_index});
    e.emit8(0x0F); e.emit8(0x84); e.emit32(0);
}

// ---------------------------------------------------------------------------
// EXIT
// ---------------------------------------------------------------------------

void JitCompiler::emit_exit(Emitter& e, size_t vm_exit_offset) {
    // call jit_pop_frame(vm*) — returns guest return address in RAX
    // mov rdi, rbx
    e.mov_rdi_rbx();
    // call jit_pop_frame
    e.call_helper((void*)&JitCompiler::helper_pop_frame);
    e.test_rax_rax();
    // jnz .has_ret_addr (non-zero: has return address)
    size_t has_ret_jcc = e.size();
    e.emit8(0x0F); e.emit8(0x85); e.emit32(0);  // JNZ rel32

    // Stack bottom (rax == 0): set VM_EXITED flag so step() returns false.
    // lock or dword [rbx + off_flags_], 1
    e.emit8(0xF0); e.emit8(0x83); e.emit8(0x8B);
    e.emit32((uint32_t)off_flags_);
    e.emit8(0x01);
    // jmp .vm_exit
    size_t stack_bottom_jmp = e.size();
    e.emit8(0xE9); e.emit32(0);
    uint32_t rel = (uint32_t)(vm_exit_offset - (stack_bottom_jmp + 5));
    memcpy(e.data() + stack_bottom_jmp + 1, &rel, 4);

    // .has_ret_addr: update vm::pc via helper, then exit JIT
    size_t has_ret_target = e.size();
    rel = (uint32_t)(has_ret_target - (has_ret_jcc + 6));
    memcpy(e.data() + has_ret_jcc + 2, &rel, 4);

    // mov rdi, rbx (vm*)
    e.mov_rdi_rbx();
    e.mov_rsi_rax();
    // call jit_return_to_caller — sets vm::pc
    e.call_helper((void*)&JitCompiler::helper_return_to_caller);
    // jmp .vm_exit — step() will re-enter JIT for the caller
    size_t exit_jmp = e.size();
    e.emit8(0xE9); e.emit32(0);
    rel = (uint32_t)(vm_exit_offset - (exit_jmp + 5));
    memcpy(e.data() + exit_jmp + 1, &rel, 4);
}

// ---------------------------------------------------------------------------
// compile() sub-methods
// ---------------------------------------------------------------------------

// Emit prologue, .vm_exit block, .entry label, and entry safepoint.
// Returns the offset of .vm_exit for use by abort patches.
size_t JitCompiler::emit_prologue(Emitter& e, std::vector<AbortPatchInfo>& abort_patches) {
    // push rbx              (53)
    e.push_rbx();
    // After step()'s CALL: RSP ≡ 8 mod 16.  push rbx → RSP ≡ 0 mod 16.
    // This is 16-byte aligned, correct for System V ABI before CALL instructions.
    // mov rbx, rdi          (48 89 FB)
    e.mov_rbx_rdi();
    // jmp .entry            (E9 rel32)
    e.jmp_rel32();
    size_t entry_jmp_offset = e.size() - 5;

    // .vm_exit: simple epilogue (no RBP, no nested CALL depth to unwind)
    size_t vm_exit_offset = e.size();
    // pop rbx               (5B)
    e.emit8(0x5B);
    // mov eax, -1           (B8 FF FF FF FF) — return -1 (abort)
    e.emit8(0xB8); e.emit32(-1);
    // ret                   (C3)
    e.emit8(0xC3);

    // .entry
    size_t entry_offset = e.size();
    e.patch_jmp_rel32(entry_jmp_offset, entry_offset);

    // Safepoint at entry
    e.mov_rdi_rbx();
    e.call_helper((void*)&JitCompiler::helper_safepoint);
    e.test_eax_eax();
    // jnz .vm_exit
    abort_patches.push_back({e.size(), -1});
    e.emit8(0x0F); e.emit8(0x85); e.emit32(0);  // JNE rel32

    return vm_exit_offset;
}

// Emit a single BPF instruction. Returns false if the instruction cannot be compiled.
bool JitCompiler::emit_instruction(Emitter& e, vm* v, const bpf_insn* entry_pc, int i,
                                    size_t vm_exit_offset,
                                    std::vector<JumpPlaceholder>& placeholders,
                                    std::vector<AbortPatchInfo>& abort_patches,
                                    int& compiled_count) {
    const bpf_insn* insn = entry_pc + i;
    uint8_t cls = insn->code & 0x07;

    switch (cls) {
    case BPF_ALU64:
        if (insn->dst_reg >= 10) return false;
        if (!emit_alu64(e, insn)) return false;
        compiled_count++;
        break;

    case BPF_ALU:
        if (insn->dst_reg >= 10) return false;
        if (!emit_alu32(e, insn)) return false;
        compiled_count++;
        break;

    case BPF_LD:
        if (!emit_ld(e, insn)) return false;
        compiled_count += 2;  // LD DW consumes 2 insns
        break;

    case BPF_LDX:
        if (insn->dst_reg >= 10) return false;
        if (!emit_ldx(e, insn, abort_patches, i)) return false;
        compiled_count++;
        break;

    case BPF_ST:
        if (!emit_st(e, insn, abort_patches, i)) return false;
        compiled_count++;
        break;

    case BPF_STX:
        if (!emit_stx(e, insn, abort_patches, i)) return false;
        compiled_count++;
        break;

    case BPF_JMP: {
        uint8_t op = insn->code & 0xf0;
        bool is_x = (insn->code & 0x08) == BPF_X;

        if (op == BPF_JA) {
            emit_ja(e, insn, i, placeholders);
            compiled_count++;
        } else if (op == BPF_CALL) {
            if (is_x) {
                uint64_t ret_gpa = v->unmmu(entry_pc + i + 1);
                emit_call_indirect(e, insn, i, ret_gpa, abort_patches);
                compiled_count++;
            } else if (insn->src_reg == 0) {
                emit_call_syscall(e, insn, i, entry_pc, abort_patches);
                compiled_count++;
            } else if (insn->src_reg == 1) {
                uint64_t ret_gpa = v->unmmu(entry_pc + i + 1);
                emit_call_bpf(e, insn, i, ret_gpa, entry_pc, vm_exit_offset, abort_patches);
                compiled_count++;
            } else {
                return false;
            }
        } else if (op == BPF_EXIT) {
            emit_exit(e, vm_exit_offset);
            compiled_count++;
        } else {
            if (!emit_jmp64(e, insn, i, placeholders)) return false;
            compiled_count++;
        }
        break;
    }

    case BPF_JMP32: {
        uint8_t op = insn->code & 0xf0;
        if (op == BPF_JA) {
            emit_ja32(e, insn, i, placeholders);
            compiled_count++;
        } else {
            if (!emit_jmp32(e, insn, i, placeholders)) return false;
            compiled_count++;
        }
        break;
    }

    default:
        return false;
    }
    return true;
}

// Allocate executable memory (W^X), patch helper calls, and finalize.
// Returns executable pointer, or nullptr on failure.
void* JitCompiler::finalize_code(Emitter& e) {
    size_t code_size = e.size();
    size_t alloc_size = (code_size + 4095) & ~(size_t)4095;
    void* code_mem = mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code_mem == MAP_FAILED) return nullptr;

    // Patch CALL rel32 sites now that we know the final code address.
    if (!e.patch_calls(code_mem)) {
        munmap(code_mem, alloc_size);
        return nullptr;  // helper beyond ±2GB — reject JIT
    }

    memcpy(code_mem, e.data(), code_size);
    if (mprotect(code_mem, alloc_size, PROT_READ | PROT_EXEC) != 0) {
        munmap(code_mem, alloc_size);
        return nullptr;
    }
    return code_mem;
}

// ---------------------------------------------------------------------------
// compile: build a complete JIT function from all reachable instructions
// ---------------------------------------------------------------------------

JitFunction* JitCompiler::compile(vm* v, const bpf_insn* entry_pc) {
    if (!enabled_) return nullptr;
    auto it = functions_.find(entry_pc);
    if (it != functions_.end()) return &it->second;
    if (failed_.count(entry_pc)) return nullptr;

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

    // Discover reachable instructions via BFS (bounded by segment, but only
    // explores the current function — EXIT terminates, CALL doesn't follow).
    std::vector<bool> back_edge_targets;
    int num_insns = 0;
    auto reachable = discover_reachable(entry_pc, seg_limit, back_edge_targets, num_insns);
    if (reachable.empty() || num_insns <= 0) { record_compile_time(); return nullptr; }

    // Emit code
    Emitter e;
    std::vector<JumpPlaceholder> placeholders;
    std::vector<AbortPatchInfo> abort_patches;
    std::vector<uint32_t> pc_offsets(num_insns, UINT32_MAX);

    size_t vm_exit_offset = emit_prologue(e, abort_patches);

    // Emit all reachable instructions
    int compiled_count = 0;
    for (int i = 0; i < num_insns; i++) {
        if (!reachable[i]) continue;
        pc_offsets[i] = (uint32_t)e.size();

        // Safepoint at back-edge targets (loop headers)
        if (back_edge_targets[i]) {
            e.mov_rdi_rbx();
            e.call_helper((void*)&JitCompiler::helper_safepoint);
            e.test_eax_eax();
            abort_patches.push_back({e.size(), i});
            e.emit8(0x0F); e.emit8(0x85); e.emit32(0);  // JNE rel32
        }

        if (!emit_instruction(e, v, entry_pc, i, vm_exit_offset,
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
        case PlaceholderKind::Jcc:  e.patch_rel32(ph.patch_offset, target); break;
        case PlaceholderKind::Jmp:  e.patch_jmp_rel32(ph.patch_offset, target); break;
        }
    }

    // Patch abort jumps to .vm_exit
    for (auto& ap : abort_patches) {
        e.patch_rel32(ap.jump_offset, vm_exit_offset);
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

#endif // __x86_64__

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

void JitCompiler::dump_stats(const JitStats& s) {
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
