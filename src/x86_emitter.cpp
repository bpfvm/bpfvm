//
// x86_emitter.cpp — x86_64-specific JIT code emission implementation.
//

#include "x86_emitter.h"

#include <cstdint>
#include <cstring>

#if defined(__x86_64__)

#include "insn.h"

// ---------------------------------------------------------------------------
// VM state setup
// ---------------------------------------------------------------------------

void X86Emitter::set_vm_offsets(size_t off_reg, size_t off_pc, size_t off_flags, size_t off_tlb) {
    off_reg_ = off_reg;
    off_pc_ = off_pc;
    off_flags_ = off_flags;
    off_tlb_ = off_tlb;
}

void X86Emitter::set_helpers(const HelperTable& h) {
    helpers_ = h;
}

// ---------------------------------------------------------------------------
// Low-level x86_64 emission: memory access
// ---------------------------------------------------------------------------

void X86Emitter::load_r64(uint8_t dst, int32_t disp) {
    uint8_t rex = 0x48;
    if (dst >= 8) rex |= 0x04;
    emit8(rex);
    emit8(0x8B);
    emit8(modrm(2, dst & 7, X86::RBP));
    emit32(disp);
}

void X86Emitter::store_r64(int32_t disp, uint8_t src) {
    uint8_t rex = 0x48;
    if (src >= 8) rex |= 0x04;
    emit8(rex);
    emit8(0x89);
    emit8(modrm(2, src & 7, X86::RBP));
    emit32(disp);
}

// ---------------------------------------------------------------------------
// SIB-addressed operations: [RBP + RDI + disp32]
// ---------------------------------------------------------------------------

void X86Emitter::sib_op_rax(uint8_t opcode, int32_t disp) {
    emit8(0x48); emit8(opcode); emit8(0x84); emit8(0x3D); emit32(disp);
}

void X86Emitter::sib_op_rdx(uint8_t opcode, int32_t disp) {
    emit8(0x48); emit8(opcode); emit8(0x94); emit8(0x3D); emit32(disp);
}

void X86Emitter::sib_test_dword(int32_t disp, uint32_t imm) {
    emit8(0xF7); emit8(0x84); emit8(0x3D); emit32(disp); emit32(imm);
}

void X86Emitter::sib_cmp_byte(int32_t disp, uint8_t imm) {
    emit8(0x80); emit8(0xBC); emit8(0x3D); emit32(disp); emit8(imm);
}

// ---------------------------------------------------------------------------
// BPF register access
// ---------------------------------------------------------------------------

void X86Emitter::load_bpf(uint8_t bpf_reg, uint8_t x86_dst) {
    if (bpf_reg >= 6 && bpf_reg <= 9) {
        uint8_t host = BPF_CALLEE_REG[bpf_reg - 6];
        if (host != x86_dst) {
            mov_r64(x86_dst, host);
        }
    } else {
        load_r64(x86_dst, (int32_t)(off_reg_ + bpf_reg * 8));
    }
}

void X86Emitter::store_bpf_wt(uint8_t bpf_reg, uint8_t x86_src) {
    store_r64((int32_t)(off_reg_ + bpf_reg * 8), x86_src);
}

void X86Emitter::store_bpf_wt32(uint8_t bpf_reg, uint8_t x86_src) {
    // Zero-extend 32-bit value in register, then do 64-bit store.
    // Cannot use 32-bit MOV to memory because that only writes 32 bits,
    // leaving the upper 32 bits of the 64-bit slot with stale data.
    // mov r32, r32 (zero-extends to 64 bits) + store_r64
    if (x86_src >= 8) emit8(0x45);  // REX.RB: 32-bit self-move for extended reg
    emit8(0x89);
    emit8(modrm(3, x86_src & 7, x86_src & 7));
    store_r64((int32_t)(off_reg_ + bpf_reg * 8), x86_src);
}

void X86Emitter::store_bpf_lazy(uint8_t bpf_reg, uint8_t x86_src) {
    uint8_t host = BPF_CALLEE_REG[bpf_reg - 6];
    if (host != x86_src) {
        mov_r64(host, x86_src);
    }
}

void X86Emitter::flush_r6_r9() {
    for (int i = 0; i < 4; i++) {
        store_r64((int32_t)(off_reg_ + (i + 6) * 8), BPF_CALLEE_REG[i]);
    }
}

// ---------------------------------------------------------------------------
// Register-to-register MOV
// ---------------------------------------------------------------------------

void X86Emitter::mov_r64(uint8_t dst, uint8_t src) {
    uint8_t rex = 0x48;
    if (src >= 8) rex |= 0x04;
    if (dst >= 8) rex |= 0x01;
    emit8(rex);
    emit8(0x89);
    emit8(modrm(3, src & 7, dst & 7));
}

// --- ALU64 reg,reg ---

void X86Emitter::add64()  { emit8(0x48); emit8(0x01); emit8(0xC8); }
void X86Emitter::sub64()  { emit8(0x48); emit8(0x29); emit8(0xC8); }
void X86Emitter::or64()   { emit8(0x48); emit8(0x09); emit8(0xC8); }
void X86Emitter::and64()  { emit8(0x48); emit8(0x21); emit8(0xC8); }
void X86Emitter::xor64()  { emit8(0x48); emit8(0x31); emit8(0xC8); }
void X86Emitter::mul64()  { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xC1); }
void X86Emitter::neg64()  { emit8(0x48); emit8(0xF7); emit8(0xD8); }

void X86Emitter::shl64_cl() { emit8(0x48); emit8(0xD3); emit8(0xE0); }
void X86Emitter::shr64_cl() { emit8(0x48); emit8(0xD3); emit8(0xE8); }
void X86Emitter::sar64_cl() { emit8(0x48); emit8(0xD3); emit8(0xF8); }

// --- ALU64 reg,imm32 ---

void X86Emitter::add64_imm(int32_t imm)  { emit8(0x48); emit8(0x05); emit32(imm); }
void X86Emitter::sub64_imm(int32_t imm)  { emit8(0x48); emit8(0x2D); emit32(imm); }
void X86Emitter::or64_imm(int32_t imm)   { emit8(0x48); emit8(0x0D); emit32(imm); }
void X86Emitter::and64_imm(int32_t imm)  { emit8(0x48); emit8(0x25); emit32(imm); }
void X86Emitter::xor64_imm(int32_t imm)  { emit8(0x48); emit8(0x35); emit32(imm); }

void X86Emitter::shl64_imm(uint8_t c) { emit8(0x48); emit8(0xC1); emit8(0xE0); emit8(c); }
void X86Emitter::shr64_imm(uint8_t c) { emit8(0x48); emit8(0xC1); emit8(0xE8); emit8(c); }
void X86Emitter::sar64_imm(uint8_t c) { emit8(0x48); emit8(0xC1); emit8(0xF8); emit8(c); }

void X86Emitter::mul64_imm(int32_t imm) { emit8(0x48); emit8(0x69); emit8(0xC0); emit32(imm); }

// --- ALU32 reg,reg ---

void X86Emitter::add32()  { emit8(0x01); emit8(0xC8); }
void X86Emitter::sub32()  { emit8(0x29); emit8(0xC8); }
void X86Emitter::or32()   { emit8(0x09); emit8(0xC8); }
void X86Emitter::and32()  { emit8(0x21); emit8(0xC8); }
void X86Emitter::xor32()  { emit8(0x31); emit8(0xC8); }
void X86Emitter::mul32()  { emit8(0x0F); emit8(0xAF); emit8(0xC1); }
void X86Emitter::neg32()  { emit8(0xF7); emit8(0xD8); }

void X86Emitter::shl32_cl() { emit8(0xD3); emit8(0xE0); }
void X86Emitter::shr32_cl() { emit8(0xD3); emit8(0xE8); }
void X86Emitter::sar32_cl() { emit8(0xD3); emit8(0xF8); }

// --- ALU32 reg,imm32 ---

void X86Emitter::add32_imm(int32_t imm)  { emit8(0x05); emit32(imm); }
void X86Emitter::sub32_imm(int32_t imm)  { emit8(0x2D); emit32(imm); }
void X86Emitter::or32_imm(int32_t imm)   { emit8(0x0D); emit32(imm); }
void X86Emitter::and32_imm(int32_t imm)  { emit8(0x25); emit32(imm); }
void X86Emitter::xor32_imm(int32_t imm)  { emit8(0x35); emit32(imm); }

void X86Emitter::shl32_imm(uint8_t c) { emit8(0xC1); emit8(0xE0); emit8(c); }
void X86Emitter::shr32_imm(uint8_t c) { emit8(0xC1); emit8(0xE8); emit8(c); }
void X86Emitter::sar32_imm(uint8_t c) { emit8(0xC1); emit8(0xF8); emit8(c); }

void X86Emitter::mul32_imm(int32_t imm) { emit8(0x69); emit8(0xC0); emit32(imm); }

// --- CMP / TEST ---

void X86Emitter::cmp64()          { emit8(0x48); emit8(0x39); emit8(0xC8); }
void X86Emitter::cmp64_imm(int32_t imm) { emit8(0x48); emit8(0x3D); emit32(imm); }
void X86Emitter::cmp32()          { emit8(0x39); emit8(0xC8); }
void X86Emitter::cmp32_imm(int32_t imm) { emit8(0x3D); emit32(imm); }
void X86Emitter::test64()         { emit8(0x48); emit8(0x85); emit8(0xC8); }
void X86Emitter::test64_imm(int32_t imm) { emit8(0x48); emit8(0xA9); emit32(imm); }
void X86Emitter::test32()         { emit8(0x85); emit8(0xC8); }
void X86Emitter::test32_imm(int32_t imm) { emit8(0xA9); emit32(imm); }

// --- Control flow ---

void X86Emitter::jcc_rel32(uint8_t cc) { emit8(0x0F); emit8(cc); emit32(0); }
void X86Emitter::jmp_rel32() { emit8(0xE9); emit32(0); }

// --- Immediate / common patterns ---

void X86Emitter::mov_rax_imm64(uint64_t val) {
    emit8(0x48); emit8(0xB8); emit64(val);
}

void X86Emitter::store_imm64(int32_t disp, int32_t imm) {
    emit8(0x48); emit8(0xC7); emit8(modrm(2, 0, X86::RBP));
    emit32(disp); emit32(imm);
}

void X86Emitter::store_imm32_zext(int32_t disp, int32_t imm) {
    if (imm >= 0) {
        store_imm64(disp, imm);
    } else {
        emit8(0xB8); emit32(imm);
        store_r64(disp, X86::RAX);
    }
}

void X86Emitter::call_helper(void* addr) {
    emit8(0x49); emit8(0xBA); emit64((uint64_t)(uintptr_t)addr);
    emit8(0x41); emit8(0xFF); emit8(0xD2);
}

void X86Emitter::mov_rdi_rbp()  { emit8(0x48); emit8(0x89); emit8(0xEF); }
void X86Emitter::mov_rsi_rax()  { emit8(0x48); emit8(0x89); emit8(0xC6); }
void X86Emitter::mov_rdx_rax()  { emit8(0x48); emit8(0x89); emit8(0xC2); }

void X86Emitter::test_rax_rax() { emit8(0x48); emit8(0x85); emit8(0xC0); }
void X86Emitter::test_eax_eax() { emit8(0x85); emit8(0xC0); }
void X86Emitter::test_al_al()   { emit8(0x84); emit8(0xC0); }

// --- Prologue/epilogue helpers ---

void X86Emitter::push_rbp() { emit8(0x55); }
void X86Emitter::pop_rbp()  { emit8(0x5D); }
void X86Emitter::mov_rbp_rdi() { emit8(0x48); emit8(0x89); emit8(0xFD); }

// ---------------------------------------------------------------------------
// Helper call (div/mod/etc.)
// ---------------------------------------------------------------------------

void X86Emitter::emit_helper_call(void* helper) {
    emit8(0x48); emit8(0x89); emit8(0xC7);  // mov rdi, rax
    emit8(0x48); emit8(0x89); emit8(0xCE);  // mov rsi, rcx
    call_helper(helper);
}

// ---------------------------------------------------------------------------
// Inline TLB fast path + slow path
// ---------------------------------------------------------------------------

MemAccessContext X86Emitter::begin_mem_access(int32_t base_disp,
                                               int16_t offset, int access_size, bool is_write) {
    MemAccessContext ctx{};
    int32_t tlb_off = (int32_t)off_tlb_;

    // Load guest address into RAX and apply BPF offset
    load_r64(X86::RAX, base_disp);
    if (offset != 0) {
        emit8(0x48); emit8(0x05); emit32((uint32_t)(int32_t)offset); // add rax, offset
    }

    // Compute TLB index: ((addr >> 20) & (TLB_SIZE-1)) * sizeof(TlbEntry)
    emit8(0x48); emit8(0x89); emit8(0xC7);                   // mov rdi, rax
    emit8(0x48); emit8(0xC1); emit8(0xEF); emit8(20);        // shr rdi, 20
    emit8(0x81); emit8(0xE7); emit32(TLB_SIZE - 1);          // and edi, (TLB_SIZE-1)
    if constexpr ((sizeof(TlbEntry) & (sizeof(TlbEntry) - 1)) == 0) {
        constexpr int shift = __builtin_ctz(sizeof(TlbEntry));
        emit8(0xC1); emit8(modrm(3, 4, X86::RDI)); emit8(shift); // shl edi, shift
    } else {
        emit8(0x69); emit8(0xFF); emit32(sizeof(TlbEntry));   // imul edi, edi, sizeof(TlbEntry)
    }

    constexpr int32_t off_guest_base = (int32_t)offsetof(TlbEntry, guest_base);
    constexpr int32_t off_guest_end  = (int32_t)offsetof(TlbEntry, guest_end);
    constexpr int32_t off_host_base  = (int32_t)offsetof(TlbEntry, host_base);
    constexpr int32_t off_flags      = (int32_t)offsetof(TlbEntry, flags);
    constexpr int32_t off_cow        = (int32_t)offsetof(TlbEntry, cow);

    // Bounds check 1: addr >= entry.guest_base
    sib_op_rax(0x3B, tlb_off + off_guest_base);              // cmp rax, guest_base
    ctx.miss_jumps.push_back(size());
    emit8(0x0F); emit8(0x82); emit32(0);                     // JB .slow

    // Bounds check 2: addr + size <= entry.guest_end
    emit8(0x48); emit8(0x8D); emit8(0x90);                   // lea rdx, [rax + disp32]
    emit32((uint32_t)access_size);
    sib_op_rdx(0x3B, tlb_off + off_guest_end);               // cmp rdx, guest_end
    ctx.miss_jumps.push_back(size());
    emit8(0x0F); emit8(0x87); emit32(0);                     // JA .slow

    if (is_write) {
        // Write permission: flags & PF_W (0x2)
        sib_test_dword(tlb_off + off_flags, 0x2);
        ctx.miss_jumps.push_back(size());
        emit8(0x0F); emit8(0x84); emit32(0);                 // JZ .slow

        // No CoW: !cow
        sib_cmp_byte(tlb_off + off_cow, 0);
        ctx.miss_jumps.push_back(size());
        emit8(0x0F); emit8(0x85); emit32(0);                 // JNE .slow
    }

    // TLB hit: host_ptr = host_base + (addr - guest_base)
    sib_op_rax(0x2B, tlb_off + off_guest_base);              // sub rax, guest_base
    sib_op_rax(0x03, tlb_off + off_host_base);               // add rax, host_base

    // JMP .done (rel32 placeholder)
    ctx.done_jmp = size();
    emit8(0xE9); emit32(0);

    // --- Slow path: TLB miss ---
    ctx.slow_start = size();
    mov_rdi_rbp();                                                 // mov rdi, rbp (vm*)
    mov_rsi_rax();                                                 // mov rsi, rax (guest addr)
    emit8(0xBA); emit32((uint32_t)access_size);                 // mov edx, size
    call_helper(is_write ? helpers_.mmu_w : helpers_.mmu);

    // Test for null (memory violation)
    test_rax_rax();
    ctx.abort_jumps.push_back(size());
    emit8(0x0F); emit8(0x84); emit32(0);                     // JZ .vm_exit

    // .done: RAX = host pointer
    ctx.done_offset = size();
    return ctx;
}

void X86Emitter::finish_mem_access(MemAccessContext& ctx,
                                     std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    // Patch miss jumps → .slow
    for (size_t off : ctx.miss_jumps) {
        uint32_t rel = (uint32_t)(ctx.slow_start - (off + 6));
        memcpy(data() + off + 2, &rel, 4);
    }
    // Patch fast-path JMP → .done
    {
        uint32_t rel = (uint32_t)(ctx.done_offset - (ctx.done_jmp + 5));
        memcpy(data() + ctx.done_jmp + 1, &rel, 4);
    }
    // Record abort jumps for later patching to .vm_exit
    for (size_t off : ctx.abort_jumps) {
        abort_patches.push_back({off, bpf_index});
    }
}

// ---------------------------------------------------------------------------
// ALU (unified for ALU64 and ALU32)
// ---------------------------------------------------------------------------

bool X86Emitter::emit_alu(const bpf_insn* insn, bool is_64) {
    bool is_x = (insn->code & 0x08) == BPF_X;
    uint8_t op = insn->code & 0xf0;
    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;

    auto load_dst = [&]() {
        load_bpf(insn->dst_reg, X86::RAX);
    };
    auto load_src = [&]() {
        load_bpf(insn->src_reg, X86::RCX);
    };
    auto store_dst = [&]() {
        if (insn->dst_reg < 6) {
            if (is_64) store_bpf_wt(insn->dst_reg, X86::RAX);
            else       store_bpf_wt32(insn->dst_reg, X86::RAX);
        } else {
            if (!is_64) {
                emit8(0x89); emit8(0xC0);  // mov eax, eax
            }
            store_bpf_lazy(insn->dst_reg, X86::RAX);
        }
    };

    // ── MOV (off == 0) ──
    if (op == BPF_MOV && insn->off == 0) {
        if (is_64) {
            if (is_x && insn->dst_reg == insn->src_reg) return true;
        }
        if (is_x) {
            load_bpf(insn->src_reg, X86::RCX);
            if (insn->dst_reg < 6) {
                if (is_64) store_bpf_wt(insn->dst_reg, X86::RCX);
                else       store_bpf_wt32(insn->dst_reg, X86::RCX);
            } else {
                if (!is_64) {
                    emit8(0x89); emit8(0xC9);  // mov ecx, ecx
                }
                store_bpf_lazy(insn->dst_reg, X86::RCX);
            }
        } else {
            if (is_64) store_imm64(dst_disp, insn->imm);
            else       store_imm32_zext(dst_disp, insn->imm);
            if (insn->dst_reg >= 6 && insn->dst_reg <= 9) {
                load_r64(X86::RAX, dst_disp);
                mov_r64(BPF_CALLEE_REG[insn->dst_reg - 6], X86::RAX);
            }
        }
        return true;
    }

    // ── NEG ──
    if (op == BPF_NEG) {
        load_dst();
        if (is_64) neg64(); else neg32();
        store_dst();
        return true;
    }

    // ── MOV with sign-extension (off != 0) ──
    if (op == BPF_MOV) {
        if (is_x) {
            load_bpf(insn->src_reg, X86::RAX);
        } else {
            emit8(0x48); emit8(0xB8); emit64((uint64_t)(int64_t)insn->imm);
        }
        if (is_64) {
            switch (insn->off) {
            case 8:  emit8(0x48); emit8(0x0F); emit8(0xBE); emit8(0xC0); break;
            case 16: emit8(0x48); emit8(0x0F); emit8(0xBF); emit8(0xC0); break;
            case 32: emit8(0x48); emit8(0x63); emit8(0xC0); break;
            default: return false;
            }
        } else {
            switch (insn->off) {
            case 8:  emit8(0x0F); emit8(0xBE); emit8(0xC0); break;
            case 16: emit8(0x0F); emit8(0xBF); emit8(0xC0); break;
            default: return false;
            }
        }
        store_dst();
        return true;
    }

    // ── END (byte-swap / zero-extend) ──
    if (op == BPF_END) {
        if (is_64) {
            load_dst();
            switch (insn->imm) {
            case 16:
                emit8(0x66); emit8(0xC1); emit8(0xC0); emit8(0x08);
                emit8(0x0F); emit8(0xB7); emit8(0xC0);
                break;
            case 32:
                emit8(0x0F); emit8(0xC8);
                break;
            case 64:
                emit8(0x48); emit8(0x0F); emit8(0xC8);
                break;
            default: return false;
            }
        } else {
            if (!is_x && insn->imm == 64) return true;

            if (is_x) {
                load_dst();
                switch (insn->imm) {
                case 16:
                    emit8(0x66); emit8(0xC1); emit8(0xC0); emit8(0x08);
                    emit8(0x0F); emit8(0xB7); emit8(0xC0);
                    break;
                case 32:
                    emit8(0x0F); emit8(0xC8);
                    break;
                case 64: return false;
                default: return false;
                }
            } else {
                switch (insn->imm) {
                case 16:
                    load_dst();
                    emit8(0x25); emit32(0xFFFF);
                    break;
                case 32:
                    load_dst();
                    emit8(0x89); emit8(0xC0);
                    break;
                default: return false;
                }
            }
        }
        store_dst();
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
    constexpr uint8_t shift_mask_64 = 0x3F;
    constexpr uint8_t shift_mask_32 = 0x1F;

    load_dst();
    if (is_x) load_src();

    switch (op) {
    case BPF_ADD:  is_x ? (is_64 ? add64() : add32()) : (is_64 ? add64_imm(insn->imm) : add32_imm(insn->imm)); break;
    case BPF_SUB:  is_x ? (is_64 ? sub64() : sub32()) : (is_64 ? sub64_imm(insn->imm) : sub32_imm(insn->imm)); break;
    case BPF_OR:   is_x ? (is_64 ? or64()  : or32())  : (is_64 ? or64_imm(insn->imm)  : or32_imm(insn->imm));  break;
    case BPF_AND:  is_x ? (is_64 ? and64() : and32()) : (is_64 ? and64_imm(insn->imm) : and32_imm(insn->imm)); break;
    case BPF_XOR:  is_x ? (is_64 ? xor64() : xor32()) : (is_64 ? xor64_imm(insn->imm) : xor32_imm(insn->imm)); break;
    case BPF_LSH:
        if (is_x) { if (is_64) shl64_cl(); else shl32_cl(); }
        else { if (is_64) shl64_imm(insn->imm & shift_mask_64); else shl32_imm(insn->imm & shift_mask_32); }
        break;
    case BPF_RSH:
        if (is_x) { if (is_64) shr64_cl(); else shr32_cl(); }
        else { if (is_64) shr64_imm(insn->imm & shift_mask_64); else shr32_imm(insn->imm & shift_mask_32); }
        break;
    case BPF_ARSH:
        if (is_x) { if (is_64) sar64_cl(); else sar32_cl(); }
        else { if (is_64) sar64_imm(insn->imm & shift_mask_64); else sar32_imm(insn->imm & shift_mask_32); }
        break;
    case BPF_MUL:  is_x ? (is_64 ? mul64() : mul32()) : (is_64 ? mul64_imm(insn->imm) : mul32_imm(insn->imm)); break;
    case BPF_DIV: {
        if (!is_x) {
            emit8(0x48); emit8(0xC7); emit8(0xC1); emit32(insn->imm);
        }
        emit8(0xBA); emit32((uint32_t)(int32_t)insn->off);
        emit_helper_call(is_64 ? helpers_.div64 : helpers_.div32);
        store_dst();
        return true;
    }
    case BPF_MOD: {
        if (!is_x) {
            emit8(0x48); emit8(0xC7); emit8(0xC1); emit32(insn->imm);
        }
        emit8(0xBA); emit32((uint32_t)(int32_t)insn->off);
        emit_helper_call(is_64 ? helpers_.mod64 : helpers_.mod32);
        store_dst();
        return true;
    }
    default: return false;
    }

    store_dst();
    return true;
}

// ---------------------------------------------------------------------------
// LD: load 64-bit immediate
// ---------------------------------------------------------------------------

bool X86Emitter::emit_ld(const bpf_insn* insn) {
    uint8_t mode = insn->code & 0xe0;
    uint8_t size = insn->code & 0x18;
    if (mode != BPF_IMM || size != BPF_DW) return false;
    if (insn->dst_reg >= 10) return false;

    uint64_t imm64 = (uint64_t)(uint32_t)(insn + 1)->imm << 32 | (uint32_t)insn->imm;

    emit8(0x48); emit8(0xB8); emit64(imm64);
    if (insn->dst_reg < 6) {
        store_bpf_wt(insn->dst_reg, X86::RAX);
    } else {
        store_bpf_lazy(insn->dst_reg, X86::RAX);
    }
    return true;
}

// ---------------------------------------------------------------------------
// LDX: load from memory with inline TLB
// ---------------------------------------------------------------------------

bool X86Emitter::emit_ldx(const bpf_insn* insn,
                            std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    uint8_t mode = insn->code & 0xe0;
    uint8_t size_field = insn->code & 0x18;
    if (mode != BPF_MEM && mode != BPF_MEMSX) return false;
    if (mode == BPF_MEMSX && size_field == BPF_DW) return false;
    if (insn->dst_reg >= 10) return false;

    int32_t src_disp = off_reg_ + insn->src_reg * 8;
    int access_size;
    switch (size_field) {
    case BPF_DW: access_size = 8; break;
    case BPF_W:  access_size = 4; break;
    case BPF_H:  access_size = 2; break;
    case BPF_B:  access_size = 1; break;
    default: return false;
    }

    // Flush src_reg (base address) if it's r6-r9
    if (insn->src_reg >= 6 && insn->src_reg <= 9) {
        store_r64((int32_t)(off_reg_ + insn->src_reg * 8), BPF_CALLEE_REG[insn->src_reg - 6]);
    }

    auto ctx = begin_mem_access(src_disp, insn->off, access_size, /*is_write=*/false);

    if (mode == BPF_MEM) {
        switch (size_field) {
        case BPF_DW: emit8(0x48); emit8(0x8B); emit8(0x00); break;
        case BPF_W:  emit8(0x8B); emit8(0x00); break;
        case BPF_H:  emit8(0x0F); emit8(0xB7); emit8(0x00); break;
        case BPF_B:  emit8(0x0F); emit8(0xB6); emit8(0x00); break;
        }
    } else {
        switch (size_field) {
        case BPF_W:  emit8(0x48); emit8(0x63); emit8(0x00); break;
        case BPF_H:  emit8(0x48); emit8(0x0F); emit8(0xBF); emit8(0x00); break;
        case BPF_B:  emit8(0x48); emit8(0x0F); emit8(0xBE); emit8(0x00); break;
        default: return false;
        }
    }

    if (insn->dst_reg < 6) {
        store_bpf_wt(insn->dst_reg, X86::RAX);
    } else {
        store_bpf_lazy(insn->dst_reg, X86::RAX);
    }
    finish_mem_access(ctx, abort_patches, bpf_index);
    return true;
}

// ---------------------------------------------------------------------------
// ST: store immediate to memory with inline TLB
// ---------------------------------------------------------------------------

bool X86Emitter::emit_st(const bpf_insn* insn,
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

    if (insn->dst_reg >= 6 && insn->dst_reg <= 9) {
        store_r64((int32_t)(off_reg_ + insn->dst_reg * 8), BPF_CALLEE_REG[insn->dst_reg - 6]);
    }

    auto ctx = begin_mem_access(dst_disp, insn->off, access_size, /*is_write=*/true);

    switch (size_field) {
    case BPF_DW: emit8(0x48); emit8(0xC7); emit8(0x00); emit32(insn->imm); break;
    case BPF_W:  emit8(0xC7); emit8(0x00); emit32(insn->imm); break;
    case BPF_H:  emit8(0x66); emit8(0xC7); emit8(0x00); emit16((uint16_t)insn->imm); break;
    case BPF_B:  emit8(0xC6); emit8(0x00); emit8((uint8_t)insn->imm); break;
    }

    finish_mem_access(ctx, abort_patches, bpf_index);
    return true;
}

// ---------------------------------------------------------------------------
// STX: store register to memory with inline TLB
// ---------------------------------------------------------------------------

bool X86Emitter::emit_stx(const bpf_insn* insn,
                            std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    uint8_t mode = insn->code & 0xe0;
    uint8_t size_field = insn->code & 0x18;
    if (mode == BPF_ATOMIC) return emit_stx_atomic(insn, abort_patches, bpf_index);
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

    if (insn->dst_reg >= 6 && insn->dst_reg <= 9) {
        store_r64((int32_t)(off_reg_ + insn->dst_reg * 8), BPF_CALLEE_REG[insn->dst_reg - 6]);
    }

    load_bpf(insn->src_reg, X86::RBX);

    auto ctx = begin_mem_access(dst_disp, insn->off, access_size, /*is_write=*/true);

    switch (size_field) {
    case BPF_DW: emit8(0x48); emit8(0x89); emit8(0x18); break;
    case BPF_W:  emit8(0x89); emit8(0x18); break;
    case BPF_H:  emit8(0x66); emit8(0x89); emit8(0x18); break;
    case BPF_B:  emit8(0x88); emit8(0x18); break;
    }

    finish_mem_access(ctx, abort_patches, bpf_index);
    return true;
}

// ---------------------------------------------------------------------------
// STX atomic: locked read-modify-write
// ---------------------------------------------------------------------------

bool X86Emitter::emit_stx_atomic(const bpf_insn* insn,
                                    std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    uint8_t size_field = insn->code & 0x18;
    if (size_field != BPF_DW && size_field != BPF_W) return false;

    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    bool is_dw = (size_field == BPF_DW);
    int access_size = is_dw ? 8 : 4;

    if (insn->dst_reg >= 6 && insn->dst_reg <= 9) {
        store_r64((int32_t)(off_reg_ + insn->dst_reg * 8), BPF_CALLEE_REG[insn->dst_reg - 6]);
    }

    load_bpf(insn->src_reg, X86::RBX);

    auto ctx = begin_mem_access(dst_disp, insn->off, access_size, /*is_write=*/true);

    mov_rdx_rax();

    int32_t op = insn->imm;

    if (op == (BPF_OR  | BPF_FETCH) ||
        op == (BPF_AND | BPF_FETCH) ||
        op == (BPF_XOR | BPF_FETCH)) {
        uint8_t alu_opcode = ((op & ~BPF_FETCH) == BPF_OR)  ? 0x09
                            : ((op & ~BPF_FETCH) == BPF_AND) ? 0x21
                            : 0x31;

        size_t loop_start = size();

        if (is_dw) {
            emit8(0x48); emit8(0x8B); emit8(0x02);
        } else {
            emit8(0x8B); emit8(0x02);
        }

        if (is_dw) emit8(0x48);
        emit8(0x89); emit8(0xC1);
        if (is_dw) emit8(0x48);
        emit8(alu_opcode); emit8(0xD9);

        emit8(0xF0);
        if (is_dw) emit8(0x48);
        emit8(0x0F); emit8(0xB1); emit8(0x0A);

        emit8(0x75);
        emit8(0);
        auto loop_end = size();
        int8_t rel = (int8_t)(loop_start - loop_end);
        data()[loop_end - 1] = (uint8_t)rel;

        if (insn->src_reg < 6) {
            store_bpf_wt(insn->src_reg, X86::RAX);
        } else {
            store_bpf_lazy(insn->src_reg, X86::RAX);
        }

        finish_mem_access(ctx, abort_patches, bpf_index);
        return true;
    }

    switch (op) {
    case BPF_ADD | BPF_FETCH:
        emit8(0xF0);
        if (is_dw) emit8(0x48);
        emit8(0x0F); emit8(0xC1); emit8(0x1A);
        if (insn->src_reg < 6) {
            store_bpf_wt(insn->src_reg, X86::RBX);
        } else {
            store_bpf_lazy(insn->src_reg, X86::RBX);
        }
        break;
    case BPF_ADD:
        emit8(0xF0);
        if (is_dw) emit8(0x48);
        emit8(0x01); emit8(0x1A);
        break;

    case BPF_OR:
    case BPF_AND:
    case BPF_XOR: {
        uint8_t opcode = (op == BPF_OR) ? 0x09
                       : (op == BPF_AND) ? 0x21
                       : 0x31;
        emit8(0xF0);
        if (is_dw) emit8(0x48);
        emit8(opcode); emit8(0x1A);
        break;
    }

    case BPF_XCHG:
        if (is_dw) emit8(0x48);
        emit8(0x87); emit8(0x1A);
        if (insn->src_reg < 6) {
            store_bpf_wt(insn->src_reg, X86::RBX);
        } else {
            store_bpf_lazy(insn->src_reg, X86::RBX);
        }
        break;

    case BPF_CMPXCHG:
        load_r64(X86::RAX, (int32_t)(off_reg_ + 0 * 8));
        emit8(0xF0);
        if (is_dw) emit8(0x48);
        emit8(0x0F); emit8(0xB1); emit8(0x1A);
        store_bpf_wt(0, X86::RAX);
        break;

    default:
        finish_mem_access(ctx, abort_patches, bpf_index);
        return false;
    }

    finish_mem_access(ctx, abort_patches, bpf_index);
    return true;
}

// ---------------------------------------------------------------------------
// Conditional jumps
// ---------------------------------------------------------------------------

bool X86Emitter::emit_jmp(const bpf_insn* insn, int current_index, bool is_64,
                            std::vector<JumpPlaceholder>& placeholders) {
    uint8_t op = insn->code & 0xf0;
    bool is_x = (insn->code & 0x08) == BPF_X;

    if (is_64) {
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

    load_bpf(insn->dst_reg, X86::RAX);

    if (is_test) {
        if (is_x) {
            load_bpf(insn->src_reg, X86::RCX);
            if (is_64) test64(); else test32();
        } else {
            if (is_64) test64_imm(insn->imm); else test32_imm(insn->imm);
        }
    } else {
        if (is_x) {
            load_bpf(insn->src_reg, X86::RCX);
            if (is_64) cmp64(); else cmp32();
        } else {
            if (is_64) cmp64_imm(insn->imm); else cmp32_imm(insn->imm);
        }
    }

    size_t jcc_off = size();
    jcc_rel32(x86_cc);

    int target = current_index + 1 + insn->off;
    placeholders.push_back({jcc_off, target, PlaceholderKind::Jcc});
    return true;
}

// ---------------------------------------------------------------------------
// Unconditional jumps
// ---------------------------------------------------------------------------

void X86Emitter::emit_ja(const bpf_insn* insn, int current_index,
                           std::vector<JumpPlaceholder>& placeholders) {
    size_t jmp_off = size();
    jmp_rel32();
    int target = current_index + 1 + insn->off;
    placeholders.push_back({jmp_off, target, PlaceholderKind::Jmp});
}

void X86Emitter::emit_ja32(const bpf_insn* insn, int current_index,
                             std::vector<JumpPlaceholder>& placeholders) {
    size_t jmp_off = size();
    jmp_rel32();
    int target = current_index + 1 + insn->imm;
    placeholders.push_back({jmp_off, target, PlaceholderKind::Jmp});
}

// ---------------------------------------------------------------------------
// CALL syscall (src_reg==0)
// ---------------------------------------------------------------------------

void X86Emitter::emit_call_syscall(const bpf_insn* insn, int current_index,
                                      const bpf_insn* entry_pc,
                                      size_t vm_exit_offset) {
    flush_r6_r9();
    const bpf_insn* insn_host = entry_pc + current_index;
    mov_rax_imm64((uint64_t)(uintptr_t)insn_host);
    emit8(0x48); emit8(0x89); emit8(0x85); emit32((uint32_t)off_pc_);
    mov_rdi_rbp();
    emit8(0xBE); emit32((uint32_t)insn->imm);
    call_helper(helpers_.do_syscall);
    test_al_al();
    size_t jz_off = size();
    emit8(0x0F); emit8(0x84); emit32(0);  // JZ rel32
    uint32_t rel = (uint32_t)(vm_exit_offset - (jz_off + 6));
    memcpy(data() + jz_off + 2, &rel, 4);

    // Reload r6-r9 from memory
    load_r64(X86::R12, (int32_t)(off_reg_ + 6 * 8));
    load_r64(X86::R13, (int32_t)(off_reg_ + 7 * 8));
    load_r64(X86::R14, (int32_t)(off_reg_ + 8 * 8));
    load_r64(X86::R15, (int32_t)(off_reg_ + 9 * 8));
}

// ---------------------------------------------------------------------------
// CALL BPF-to-BPF (src_reg==1)
// ---------------------------------------------------------------------------

void X86Emitter::emit_call_bpf(const bpf_insn* insn, int current_index,
                                  uint64_t ret_gpa,
                                  const bpf_insn* entry_pc,
                                  size_t vm_exit_offset,
                                  std::vector<AbortPatchInfo>& abort_patches) {
    flush_r6_r9();
    mov_rdi_rbp();
    emit8(0x48); emit8(0xBE); emit64(ret_gpa);
    call_helper(helpers_.push_frame);
    test_al_al();
    abort_patches.push_back({size(), current_index});
    emit8(0x0F); emit8(0x84); emit32(0);

    const bpf_insn* callee_pc = entry_pc + current_index + 1 + insn->imm;
    mov_rax_imm64((uint64_t)(uintptr_t)callee_pc);
    emit8(0x48); emit8(0x89); emit8(0x85); emit32((uint32_t)off_pc_);

    size_t jmp_off = size();
    emit8(0xE9); emit32(0);
    uint32_t rel = (uint32_t)(vm_exit_offset - (jmp_off + 5));
    memcpy(data() + jmp_off + 1, &rel, 4);
}

// ---------------------------------------------------------------------------
// CALL indirect (BPF_CALL | BPF_X)
// ---------------------------------------------------------------------------

void X86Emitter::emit_call_indirect(const bpf_insn* insn, int current_index,
                                      uint64_t ret_gpa,
                                      std::vector<AbortPatchInfo>& abort_patches) {
    flush_r6_r9();
    mov_rdi_rbp();
    emit8(0x48); emit8(0xBE); emit64(ret_gpa);
    load_bpf(insn->dst_reg, X86::RDX);
    call_helper(helpers_.call_indirect);
    test_al_al();
    abort_patches.push_back({size(), current_index});
    emit8(0x0F); emit8(0x84); emit32(0);
}

// ---------------------------------------------------------------------------
// EXIT
// ---------------------------------------------------------------------------

void X86Emitter::emit_exit(size_t vm_exit_offset) {
    flush_r6_r9();
    mov_rdi_rbp();
    call_helper(helpers_.pop_frame);
    test_rax_rax();
    size_t has_ret_jcc = size();
    emit8(0x0F); emit8(0x85); emit32(0);  // JNZ rel32

    // Stack bottom: set VM_EXITED flag
    emit8(0xF0); emit8(0x83); emit8(0x8D);
    emit32((uint32_t)off_flags_);
    emit8(0x01);
    size_t stack_bottom_jmp = size();
    emit8(0xE9); emit32(0);
    uint32_t rel = (uint32_t)(vm_exit_offset - (stack_bottom_jmp + 5));
    memcpy(data() + stack_bottom_jmp + 1, &rel, 4);

    // .has_ret_addr
    size_t has_ret_target = size();
    rel = (uint32_t)(has_ret_target - (has_ret_jcc + 6));
    memcpy(data() + has_ret_jcc + 2, &rel, 4);

    mov_rdi_rbp();
    mov_rsi_rax();
    call_helper(helpers_.return_to_caller);
    size_t exit_jmp = size();
    emit8(0xE9); emit32(0);
    rel = (uint32_t)(vm_exit_offset - (exit_jmp + 5));
    memcpy(data() + exit_jmp + 1, &rel, 4);
}

// ---------------------------------------------------------------------------
// Prologue
// ---------------------------------------------------------------------------

PrologueResult X86Emitter::emit_prologue(std::vector<AbortPatchInfo>& abort_patches) {
    push_rbp();
    emit8(0x53);                      // push rbx
    emit8(0x41); emit8(0x54);  // push r12
    emit8(0x41); emit8(0x55);  // push r13
    emit8(0x41); emit8(0x56);  // push r14
    emit8(0x41); emit8(0x57);  // push r15
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);  // sub rsp, 8
    mov_rbp_rdi();
    // Load r6-r9 from vm->reg[]
    load_r64(X86::R12, (int32_t)(off_reg_ + 6 * 8));
    load_r64(X86::R13, (int32_t)(off_reg_ + 7 * 8));
    load_r64(X86::R14, (int32_t)(off_reg_ + 8 * 8));
    load_r64(X86::R15, (int32_t)(off_reg_ + 9 * 8));
    // jmp .entry
    jmp_rel32();
    size_t entry_jmp_offset = size() - 5;

    // .vm_exit
    size_t vm_exit_offset = size();
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);  // add rsp, 8
    emit8(0x41); emit8(0x5F);  // pop r15
    emit8(0x41); emit8(0x5E);  // pop r14
    emit8(0x41); emit8(0x5D);  // pop r13
    emit8(0x41); emit8(0x5C);  // pop r12
    emit8(0x5B);                  // pop rbx
    emit8(0x5D);                  // pop rbp
    emit8(0xB8); emit32(-1);    // mov eax, -1
    emit8(0xC3);                  // ret

    // .flush_and_exit
    size_t flush_and_exit_offset = size();
    store_r64((int32_t)(off_reg_ + 6 * 8), X86::R12);
    store_r64((int32_t)(off_reg_ + 7 * 8), X86::R13);
    store_r64((int32_t)(off_reg_ + 8 * 8), X86::R14);
    store_r64((int32_t)(off_reg_ + 9 * 8), X86::R15);
    size_t jmp_off = size();
    emit8(0xE9); emit32(0);
    uint32_t rel = (uint32_t)(vm_exit_offset - (jmp_off + 5));
    memcpy(data() + jmp_off + 1, &rel, 4);

    // .entry
    size_t entry_offset = size();
    patch_jmp_rel32(entry_jmp_offset, entry_offset);

    // Safepoint at entry
    flush_r6_r9();
    mov_rdi_rbp();
    call_helper(helpers_.safepoint);
    test_eax_eax();
    abort_patches.push_back({size(), -1});
    emit8(0x0F); emit8(0x85); emit32(0);  // JNE rel32

    return {vm_exit_offset, flush_and_exit_offset};
}

// ---------------------------------------------------------------------------
// Safepoint (at loop back-edge targets)
// ---------------------------------------------------------------------------

void X86Emitter::emit_safepoint(std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    flush_r6_r9();
    mov_rdi_rbp();
    call_helper(helpers_.safepoint);
    test_eax_eax();
    abort_patches.push_back({size(), bpf_index});
    emit8(0x0F); emit8(0x85); emit32(0);  // JNE rel32
}

#endif // __x86_64__
