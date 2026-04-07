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
    // MOV r64, QWORD PTR [RBX+disp32]
    emit8(0x48);
    emit8(0x8B);
    emit8(modrm(2, dst, X86::RBX));
    emit32(disp);
}

void Emitter::store_r64(int32_t disp, uint8_t src) {
    // MOV QWORD PTR [RBX+disp32], r64
    emit8(0x48);
    emit8(0x89);
    emit8(modrm(2, src, X86::RBX));
    emit32(disp);
}

void Emitter::load_r32(uint8_t dst, int32_t disp) {
    // MOV r32, DWORD PTR [RBX+disp32]  (zero-extends to 64 bits)
    emit8(0x8B);
    emit8(modrm(2, dst, X86::RBX));
    emit32(disp);
}

// ---------------------------------------------------------------------------
// SIB-addressed operations: [RBX + RCX + disp32]
// ---------------------------------------------------------------------------

void Emitter::sib_op_rax(uint8_t opcode, int32_t disp) {
    emit8(0x48); emit8(opcode); emit8(0x84); emit8(0x0B); emit32(disp);
}

void Emitter::sib_op_rdx(uint8_t opcode, int32_t disp) {
    emit8(0x48); emit8(opcode); emit8(0x94); emit8(0x0B); emit32(disp);
}

void Emitter::sib_test_dword(int32_t disp, uint32_t imm) {
    emit8(0xF7); emit8(0x84); emit8(0x0B); emit32(disp); emit32(imm);
}

void Emitter::sib_cmp_byte(int32_t disp, uint8_t imm) {
    emit8(0x80); emit8(0xBC); emit8(0x0B); emit32(disp); emit8(imm);
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
    emit8(0x48); emit8(0xC7); emit8(modrm(2, 0, X86::RBX));
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

void Emitter::mov_rdi_rbx()  { emit8(0x48); emit8(0x89); emit8(0xDF); }
void Emitter::mov_rsi_rax()  { emit8(0x48); emit8(0x89); emit8(0xC6); }
void Emitter::mov_rdx_rax()  { emit8(0x48); emit8(0x89); emit8(0xC2); }

// --- Common TEST instructions ---

void Emitter::test_rax_rax() { emit8(0x48); emit8(0x85); emit8(0xC0); }
void Emitter::test_eax_eax() { emit8(0x85); emit8(0xC0); }
void Emitter::test_al_al()   { emit8(0x84); emit8(0xC0); }

// --- Prologue / epilogue ---

void Emitter::push_rbx() { emit8(0x53); }
void Emitter::pop_rbx()  { emit8(0x5B); }
void Emitter::mov_rbx_rdi() { emit8(0x48); emit8(0x89); emit8(0xFB); }

void Emitter::call_helper(void* addr) {
    // Emit a CALL rel32 placeholder (5 bytes).  The rel32 displacement is
    // patched by patch_calls() after all code has been emitted.
    size_t off = buf_.size();
    emit8(0xE8); emit32(0);  // call rel32 (placeholder)
    pending_calls_.push_back({off, addr});
}

void Emitter::ret_int(int val) {
    emit8(0xB8); emit32(val);
    emit8(0x5B);  // pop rbx
    emit8(0xC3);  // ret
}

void Emitter::ret_zero() {
    emit8(0x31); emit8(0xC0);  // xor eax, eax
    emit8(0x5B);
    emit8(0xC3);
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

// ---------------------------------------------------------------------------
// Patch deferred CALL rel32 sites to point directly to helper addresses.
//
// Called after mmap allocates the final code region.  Each pending call is
// patched with rel32 = helper_addr - (code_base + call_offset + 5).
// Returns false if any displacement overflows signed 32-bit range.
// ---------------------------------------------------------------------------
bool Emitter::patch_calls(void* code_base) {
    for (auto& pc : pending_calls_) {
        // Address of the instruction *following* the CALL (= call_site + 5)
        auto next_ip = (uintptr_t)code_base + pc.call_offset + 5;
        auto target  = (uintptr_t)pc.helper;
        int64_t disp = (int64_t)target - (int64_t)next_ip;
        if (disp < INT32_MIN || disp > INT32_MAX) {
            return false;  // beyond ±2GB — reject JIT compilation
        }
        uint32_t rel = (uint32_t)(int32_t)disp;
        memcpy(buf_.data() + pc.call_offset + 1, &rel, 4);
    }
    pending_calls_.clear();
    return true;
}

#endif // __x86_64__
