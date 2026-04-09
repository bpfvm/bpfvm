//
// Emitter implementation: low-level x86_64 code generation.
// Separated from jit.cpp for clarity; depends only on jit.h and <cstring>.
//

#include "jit.h"

#include <cstring>

#if defined(__x86_64__)

// ---------------------------------------------------------------------------
// Emitter implementation
// ---------------------------------------------------------------------------

void Emitter::emit16(uint16_t v) {
    buf_.push_back(v & 0xFF);
    buf_.push_back((v >> 8) & 0xFF);
}

void Emitter::emit32(uint32_t v) {
    buf_.push_back(v & 0xFF);
    buf_.push_back((v >> 8) & 0xFF);
    buf_.push_back((v >> 16) & 0xFF);
    buf_.push_back((v >> 24) & 0xFF);
}

void Emitter::emit64(uint64_t v) {
    emit32((uint32_t)v);
    emit32((uint32_t)(v >> 32));
}

void Emitter::load_r64(uint8_t dst, int32_t disp) {
    // MOV r64, QWORD PTR [RBP+disp32]
    uint8_t rex = 0x48;
    if (dst >= 8) rex |= 0x04;  // REX.R for R8-R15
    emit8(rex);
    emit8(0x8B);
    emit8(modrm(2, dst & 7, X86::RBP));
    emit32(disp);
}

void Emitter::store_r64(int32_t disp, uint8_t src) {
    // MOV QWORD PTR [RBP+disp32], r64
    uint8_t rex = 0x48;
    if (src >= 8) rex |= 0x04;  // REX.R for R8-R15
    emit8(rex);
    emit8(0x89);
    emit8(modrm(2, src & 7, X86::RBP));
    emit32(disp);
}

void Emitter::load_r32(uint8_t dst, int32_t disp) {
    // MOV r32, DWORD PTR [RBP+disp32]  (zero-extends to 64 bits)
    emit8(0x8B);
    emit8(modrm(2, dst, X86::RBP));
    emit32(disp);
}

// ---------------------------------------------------------------------------
// SIB-addressed operations: [RBP + RDI + disp32]
// RDI is used as the TLB index register, freeing RCX for operands.
// SIB byte: scale=0, index=RDI(7), base=RBP(5) → 0x3D
// ---------------------------------------------------------------------------

void Emitter::sib_op_rax(uint8_t opcode, int32_t disp) {
    emit8(0x48); emit8(opcode); emit8(0x84); emit8(0x3D); emit32(disp);
}

void Emitter::sib_op_rdx(uint8_t opcode, int32_t disp) {
    emit8(0x48); emit8(opcode); emit8(0x94); emit8(0x3D); emit32(disp);
}

void Emitter::sib_test_dword(int32_t disp, uint32_t imm) {
    emit8(0xF7); emit8(0x84); emit8(0x3D); emit32(disp); emit32(imm);
}

void Emitter::sib_cmp_byte(int32_t disp, uint8_t imm) {
    emit8(0x80); emit8(0xBC); emit8(0x3D); emit32(disp); emit8(imm);
}

// ---------------------------------------------------------------------------
// BPF register access
// ---------------------------------------------------------------------------

void Emitter::load_bpf(uint8_t bpf_reg, uint8_t x86_dst, size_t off_reg) {
    if (bpf_reg >= 6 && bpf_reg <= 9) {
        // r6-r9: cached in R12-R15 (callee-saved, always valid)
        uint8_t host = BPF_CALLEE_REG[bpf_reg - 6];
        if (host != x86_dst) {
            mov_r64(x86_dst, host);
        }
    } else {
        // r0-r5, r10: always load from vm->reg[] memory
        load_r64(x86_dst, (int32_t)(off_reg + bpf_reg * 8));
    }
}

void Emitter::store_bpf_wt(uint8_t bpf_reg, uint8_t x86_src, size_t off_reg) {
    // Write-through for r0-r5: store directly to vm->reg[] memory.
    store_r64((int32_t)(off_reg + bpf_reg * 8), x86_src);
}

void Emitter::store_bpf_wt32(uint8_t bpf_reg, uint8_t x86_src, size_t off_reg) {
    // 32-bit write-through: zero-extend x86_src to 64 bits, then store to vm->reg[].
    // mov r32, r32 clears upper 32 bits of the 64-bit register.
    {
        uint8_t rex = 0x40;
        if (x86_src >= 8) rex |= 0x05;  // REX.R + REX.B (same register in both fields)
        if (rex != 0x40) emit8(rex);     // only emit REX if needed for extended registers
        emit8(0x89);  // MOV r/m32, r32
        emit8(modrm(3, x86_src & 7, x86_src & 7));
    }
    // Now the full 64-bit register is zero-extended; store the qword
    store_r64((int32_t)(off_reg + bpf_reg * 8), x86_src);
}

void Emitter::store_bpf_lazy(uint8_t bpf_reg, uint8_t x86_src) {
    // Lazy store for r6-r9: write to R12-R15 only, no memory write.
    // Caller must ensure flush_r6_r9() is called before any path that
    // reads vm->reg[6-9] (safepoints, push_frame, syscalls, JIT exit).
    uint8_t host = BPF_CALLEE_REG[bpf_reg - 6];
    if (host != x86_src) {
        mov_r64(host, x86_src);
    }
}

void Emitter::flush_r6_r9(size_t off_reg) {
    // Unconditionally spill R12-R15 to vm->reg[6-9].
    for (int i = 0; i < 4; i++) {
        store_r64((int32_t)(off_reg + (i + 6) * 8), BPF_CALLEE_REG[i]);
    }
}

void Emitter::mov_r64(uint8_t dst, uint8_t src) {
    // mov r64, r64  (48 89 /r with modrm(mod=3, reg=src, rm=dst))
    // For R8-R15 (extended): needs REX.R (0x4C) if src >= 8, REX.B (0x49) if dst >= 8
    uint8_t rex = 0x48;
    if (src >= 8) rex |= 0x04;  // REX.R
    if (dst >= 8) rex |= 0x01;  // REX.B
    emit8(rex);
    emit8(0x89);  // MOV r/m64, r64
    emit8(modrm(3, src & 7, dst & 7));
}

// --- ALU64 reg,reg ---

void Emitter::add64()  { emit8(0x48); emit8(0x01); emit8(0xC8); }
void Emitter::sub64()  { emit8(0x48); emit8(0x29); emit8(0xC8); }
void Emitter::or64()   { emit8(0x48); emit8(0x09); emit8(0xC8); }
void Emitter::and64()  { emit8(0x48); emit8(0x21); emit8(0xC8); }
void Emitter::xor64()  { emit8(0x48); emit8(0x31); emit8(0xC8); }
void Emitter::mul64()  { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xC1); }
void Emitter::neg64()  { emit8(0x48); emit8(0xF7); emit8(0xD8); }

void Emitter::shl64_cl() { emit8(0x48); emit8(0xD3); emit8(0xE0); }
void Emitter::shr64_cl() { emit8(0x48); emit8(0xD3); emit8(0xE8); }
void Emitter::sar64_cl() { emit8(0x48); emit8(0xD3); emit8(0xF8); }

// --- ALU64 reg,imm32 ---

void Emitter::add64_imm(int32_t imm)  { emit8(0x48); emit8(0x05); emit32(imm); }
void Emitter::sub64_imm(int32_t imm)  { emit8(0x48); emit8(0x2D); emit32(imm); }
void Emitter::or64_imm(int32_t imm)   { emit8(0x48); emit8(0x0D); emit32(imm); }
void Emitter::and64_imm(int32_t imm)  { emit8(0x48); emit8(0x25); emit32(imm); }
void Emitter::xor64_imm(int32_t imm)  { emit8(0x48); emit8(0x35); emit32(imm); }

void Emitter::shl64_imm(uint8_t c) { emit8(0x48); emit8(0xC1); emit8(0xE0); emit8(c); }
void Emitter::shr64_imm(uint8_t c) { emit8(0x48); emit8(0xC1); emit8(0xE8); emit8(c); }
void Emitter::sar64_imm(uint8_t c) { emit8(0x48); emit8(0xC1); emit8(0xF8); emit8(c); }

void Emitter::mul64_imm(int32_t imm) { emit8(0x48); emit8(0x69); emit8(0xC0); emit32(imm); }

// --- ALU32 reg,reg ---

void Emitter::add32()  { emit8(0x01); emit8(0xC8); }
void Emitter::sub32()  { emit8(0x29); emit8(0xC8); }
void Emitter::or32()   { emit8(0x09); emit8(0xC8); }
void Emitter::and32()  { emit8(0x21); emit8(0xC8); }
void Emitter::xor32()  { emit8(0x31); emit8(0xC8); }
void Emitter::mul32()  { emit8(0x0F); emit8(0xAF); emit8(0xC1); }
void Emitter::neg32()  { emit8(0xF7); emit8(0xD8); }

void Emitter::shl32_cl() { emit8(0xD3); emit8(0xE0); }
void Emitter::shr32_cl() { emit8(0xD3); emit8(0xE8); }
void Emitter::sar32_cl() { emit8(0xD3); emit8(0xF8); }

// --- ALU32 reg,imm32 ---

void Emitter::add32_imm(int32_t imm)  { emit8(0x05); emit32(imm); }
void Emitter::sub32_imm(int32_t imm)  { emit8(0x2D); emit32(imm); }
void Emitter::or32_imm(int32_t imm)   { emit8(0x0D); emit32(imm); }
void Emitter::and32_imm(int32_t imm)  { emit8(0x25); emit32(imm); }
void Emitter::xor32_imm(int32_t imm)  { emit8(0x35); emit32(imm); }

void Emitter::shl32_imm(uint8_t c) { emit8(0xC1); emit8(0xE0); emit8(c); }
void Emitter::shr32_imm(uint8_t c) { emit8(0xC1); emit8(0xE8); emit8(c); }
void Emitter::sar32_imm(uint8_t c) { emit8(0xC1); emit8(0xF8); emit8(c); }

void Emitter::mul32_imm(int32_t imm) { emit8(0x69); emit8(0xC0); emit32(imm); }

// --- CMP / TEST ---

void Emitter::cmp64()          { emit8(0x48); emit8(0x39); emit8(0xC8); }
void Emitter::cmp64_imm(int32_t imm) { emit8(0x48); emit8(0x3D); emit32(imm); }
void Emitter::cmp32()          { emit8(0x39); emit8(0xC8); }
void Emitter::cmp32_imm(int32_t imm) { emit8(0x3D); emit32(imm); }
void Emitter::test64()         { emit8(0x48); emit8(0x85); emit8(0xC8); }
void Emitter::test64_imm(int32_t imm) { emit8(0x48); emit8(0xA9); emit32(imm); }
void Emitter::test32()         { emit8(0x85); emit8(0xC8); }
void Emitter::test32_imm(int32_t imm) { emit8(0xA9); emit32(imm); }

// --- Conditional/unconditional jumps ---

// Jcc rel32: 0F cc 00000000
void Emitter::jcc_rel32(uint8_t cc) { emit8(0x0F); emit8(cc); emit32(0); }

// JMP rel32: E9 00000000
void Emitter::jmp_rel32() { emit8(0xE9); emit32(0); }

// CALL rel32: E8 00000000
void Emitter::call_rel32() { emit8(0xE8); emit32(0); }

void Emitter::mov_rax_imm64(uint64_t val) {
    emit8(0x48); emit8(0xB8); emit64(val);
}

// --- MOV immediate to memory ---

void Emitter::store_imm64(int32_t disp, int32_t imm) {
    emit8(0x48); emit8(0xC7); emit8(modrm(2, 0, X86::RBP));
    emit32(disp); emit32(imm);
}

void Emitter::store_imm32_zext(int32_t disp, int32_t imm) {
    if (imm >= 0) {
        store_imm64(disp, imm);
    } else {
        emit8(0xB8); emit32(imm);
        store_r64(disp, X86::RAX);
    }
}

// --- Common register-to-register MOVs ---

void Emitter::mov_rdi_rbp()  { emit8(0x48); emit8(0x89); emit8(0xEF); }
void Emitter::mov_rsi_rax()  { emit8(0x48); emit8(0x89); emit8(0xC6); }
void Emitter::mov_rdx_rax()  { emit8(0x48); emit8(0x89); emit8(0xC2); }

// --- Common TEST instructions ---

void Emitter::test_rax_rax() { emit8(0x48); emit8(0x85); emit8(0xC0); }
void Emitter::test_eax_eax() { emit8(0x85); emit8(0xC0); }
void Emitter::test_al_al()   { emit8(0x84); emit8(0xC0); }

// --- Prologue / epilogue ---

void Emitter::push_rbp() { emit8(0x55); }
void Emitter::pop_rbp()  { emit8(0x5D); }
void Emitter::mov_rbp_rdi() { emit8(0x48); emit8(0x89); emit8(0xFD); }

void Emitter::call_helper(void* addr) {
    // movabs r10, addr  (49 BA imm64) — load 64-bit helper address into R10
    emit8(0x49); emit8(0xBA); emit64((uint64_t)(uintptr_t)addr);
    // call r10           (41 FF D2)   — indirect call through R10
    emit8(0x41); emit8(0xFF); emit8(0xD2);
}

// --- Patching ---

// Patch a Jcc rel32 (6 bytes: 0F cc rel32)
void Emitter::patch_rel32(size_t inst_offset, size_t target_offset) {
    uint32_t rel = (uint32_t)(target_offset - (inst_offset + 6));
    memcpy(buf_.data() + inst_offset + 2, &rel, 4);
}

// Patch a JMP/CALL rel32 (5 bytes: E9/E8 rel32)
void Emitter::patch_jmp_rel32(size_t inst_offset, size_t target_offset) {
    uint32_t rel = (uint32_t)(target_offset - (inst_offset + 5));
    memcpy(buf_.data() + inst_offset + 1, &rel, 4);
}

#endif // __x86_64__
