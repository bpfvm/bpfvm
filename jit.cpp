//
// Created by chouryzhou on 26-3-31.
//

#include "jit.h"

#include <cstdlib>
#include <cstdio>

#if defined(__x86_64__)

#include "insn.h"
#include <cstring>
#include <climits>

// ---------------------------------------------------------------------------
// Helper functions for DIV/MOD (called from JIT-generated code, plain C ABI)
//
// Called via System V AMD64 ABI: arg1=RDI, arg2=RSI, arg3=RDX; return in RAX.
// RBX is callee-saved per ABI, so vm* survives every helper call.
//
// Why helpers for DIV/MOD?
//   - BPF divide-by-zero → result = 0 (not #DE fault).
//   - BPF INT64_MIN / -1 → INT64_MIN (not #DE fault).
//   - BPF insn->off selects unsigned (off==0) vs. signed (off!=0) division.
// ---------------------------------------------------------------------------

extern "C" {

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

} // extern "C"

// MMU helpers for JIT slow path (TLB miss) — only called on miss, not the
// common inline TLB fast path.
extern "C" {

void* jit_mmu(vm* v, uint64_t addr, uint64_t size) {
    return v->mmu_slow(addr, (size_t)size);
}

void* jit_mmu_w(vm* v, uint64_t addr, uint64_t size) {
    return v->mmu_w_slow(addr, (size_t)size);
}

} // extern "C"

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
    // REX.W(48) 8B /r ModRM(mod=2,reg=dst,rm=RBX) disp32
    // mod=2: memory operand with 32-bit displacement; rm=RBX(3) as base.
    emit8(0x48);
    emit8(0x8B);
    emit8(modrm(2, dst, X86::RBX));
    emit32(disp);
}

void Emitter::store_r64(int32_t disp, uint8_t src) {
    // MOV QWORD PTR [RBX+disp32], r64
    // REX.W(48) 89 /r ModRM(mod=2,reg=src,rm=RBX) disp32
    emit8(0x48);
    emit8(0x89);
    emit8(modrm(2, src, X86::RBX));
    emit32(disp);
}

void Emitter::load_r32(uint8_t dst, int32_t disp) {
    // MOV r32, DWORD PTR [RBX+disp32]  (zero-extends to 64 bits)
    // No REX prefix needed for low 8 registers.
    // 8B /r ModRM(mod=2,reg=dst,rm=RBX) disp32
    emit8(0x8B);
    emit8(modrm(2, dst, X86::RBX));
    emit32(disp);
}

// ---------------------------------------------------------------------------
// SIB-addressed operations: [RBX + RCX + disp32]
// Used for inline TLB fast-path access.  SIB byte = 0x0B (scale=1, RCX, RBX).
// ---------------------------------------------------------------------------

void Emitter::sib_op_rax(uint8_t opcode, int32_t disp) {
    // REX.W(48) + opcode + ModRM(10,000(RAX),100(SIB)) + SIB(00,RCX,RBX) + disp32
    // ModRM = 0x84 = (2<<6)|(0<<3)|4
    // SIB   = 0x0B = (0<<6)|(1<<3)|3
    emit8(0x48); emit8(opcode); emit8(0x84); emit8(0x0B); emit32(disp);
}

void Emitter::sib_op_rdx(uint8_t opcode, int32_t disp) {
    // REX.W(48) + opcode + ModRM(10,010(RDX),100(SIB)) + SIB(00,RCX,RBX) + disp32
    // ModRM = 0x94 = (2<<6)|(2<<3)|4
    emit8(0x48); emit8(opcode); emit8(0x94); emit8(0x0B); emit32(disp);
}

void Emitter::sib_test_dword(int32_t disp, uint32_t imm) {
    // TEST DWORD [RBX+RCX+disp32], imm32
    // F7 /0  ModRM(10,0,100) SIB(00,RCX,RBX) disp32 imm32
    // ModRM = 0x84
    emit8(0xF7); emit8(0x84); emit8(0x0B); emit32(disp); emit32(imm);
}

void Emitter::sib_cmp_byte(int32_t disp, uint8_t imm) {
    // CMP BYTE [RBX+RCX+disp32], imm8
    // 80 /7  ModRM(10,7,100) SIB(00,RCX,RBX) disp32 imm8
    // ModRM = (2<<6)|(7<<3)|4 = 0xBC
    emit8(0x80); emit8(0xBC); emit8(0x0B); emit32(disp); emit8(imm);
}

// --- ALU64 reg,reg ---
// All ops: REX.W(48) + opcode + ModRM(0xC8)
// ModRM 0xC8 = 11 001 000: mod=3(reg), reg=1(RCX), rm=0(RAX)  →  op RAX, RCX
// Exception: IMUL and NEG use different ModRM (see below).
//
//   Function     Bytes          Instruction
//   add64()   48 01 C8      ADD  RAX, RCX   (opcode 01 /r: r/m64 += r64)
//   sub64()   48 29 C8      SUB  RAX, RCX   (opcode 29 /r: r/m64 -= r64)
//   or64()    48 09 C8      OR   RAX, RCX   (opcode 09 /r)
//   and64()   48 21 C8      AND  RAX, RCX   (opcode 21 /r)
//   xor64()   48 31 C8      XOR  RAX, RCX   (opcode 31 /r)
//   mul64()   48 0F AF C1   IMUL RAX, RCX   (0F AF /r: r64 *= r/m64;
//                                            ModRM C1=11 000 001: reg=RAX rm=RCX)
//   neg64()   48 F7 D8      NEG  RAX        (F7 /3: r/m64 = -r/m64;
//                                            ModRM D8=11 011 000: /3 rm=RAX)

void Emitter::add64()  { emit8(0x48); emit8(0x01); emit8(0xC8); }
void Emitter::sub64()  { emit8(0x48); emit8(0x29); emit8(0xC8); }
void Emitter::or64()   { emit8(0x48); emit8(0x09); emit8(0xC8); }
void Emitter::and64()  { emit8(0x48); emit8(0x21); emit8(0xC8); }
void Emitter::xor64()  { emit8(0x48); emit8(0x31); emit8(0xC8); }
void Emitter::mul64()  { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xC1); }
void Emitter::neg64()  { emit8(0x48); emit8(0xF7); emit8(0xD8); }

// Shifts with CL: REX.W(48) + D3 + ModRM(/ext, RAX)
// D3 /4=SHL /5=SHR /7=SAR; ModRM = 11 ext 000 (mod=3, rm=RAX)
//   shl64_cl()   48 D3 E0   SHL RAX, CL   (ModRM E0=11 100 000: /4 rm=RAX)
//   shr64_cl()   48 D3 E8   SHR RAX, CL   (ModRM E8=11 101 000: /5 rm=RAX)
//   sar64_cl()   48 D3 F8   SAR RAX, CL   (ModRM F8=11 111 000: /7 rm=RAX)

void Emitter::shl64_cl() { emit8(0x48); emit8(0xD3); emit8(0xE0); }
void Emitter::shr64_cl() { emit8(0x48); emit8(0xD3); emit8(0xE8); }
void Emitter::sar64_cl() { emit8(0x48); emit8(0xD3); emit8(0xF8); }

// --- ALU64 reg,imm32 ---
// Short-form RAX encodings (no ModRM byte; imm32 is sign-extended to 64 bits).
//   Function          Bytes             Instruction
//   add64_imm(imm)   48 05 imm32    ADD  RAX, imm32
//   sub64_imm(imm)   48 2D imm32    SUB  RAX, imm32
//   or64_imm(imm)    48 0D imm32    OR   RAX, imm32
//   and64_imm(imm)   48 25 imm32    AND  RAX, imm32
//   xor64_imm(imm)   48 35 imm32    XOR  RAX, imm32

void Emitter::add64_imm(int32_t imm)  { emit8(0x48); emit8(0x05); emit32(imm); }
void Emitter::sub64_imm(int32_t imm)  { emit8(0x48); emit8(0x2D); emit32(imm); }
void Emitter::or64_imm(int32_t imm)   { emit8(0x48); emit8(0x0D); emit32(imm); }
void Emitter::and64_imm(int32_t imm)  { emit8(0x48); emit8(0x25); emit32(imm); }
void Emitter::xor64_imm(int32_t imm)  { emit8(0x48); emit8(0x35); emit32(imm); }

// Shifts with imm8: REX.W(48) + C1 + ModRM(/ext, RAX) + imm8
//   shl64_imm(c)   48 C1 E0 c    SHL RAX, c
//   shr64_imm(c)   48 C1 E8 c    SHR RAX, c
//   sar64_imm(c)   48 C1 F8 c    SAR RAX, c

void Emitter::shl64_imm(uint8_t c) { emit8(0x48); emit8(0xC1); emit8(0xE0); emit8(c); }
void Emitter::shr64_imm(uint8_t c) { emit8(0x48); emit8(0xC1); emit8(0xE8); emit8(c); }
void Emitter::sar64_imm(uint8_t c) { emit8(0x48); emit8(0xC1); emit8(0xF8); emit8(c); }

// IMUL RAX, RAX, imm32 — three-operand form avoids loading imm into RCX first.
// REX.W(48) 69 /r ModRM(C0=11 000 000: reg=RAX rm=RAX) imm32
void Emitter::mul64_imm(int32_t imm) { emit8(0x48); emit8(0x69); emit8(0xC0); emit32(imm); }

// --- ALU32 reg,reg ---
// Same opcodes as ALU64 but without the REX.W (0x48) prefix → 32-bit operands.
// x86_64 rule: any 32-bit write implicitly zeroes the upper 32 bits of the
// destination register, so BPF ALU32 zero-extension to 64 bits is free.
//
//   Function     Bytes       Instruction
//   add32()   01 C8       ADD  EAX, ECX
//   sub32()   29 C8       SUB  EAX, ECX
//   or32()    09 C8       OR   EAX, ECX
//   and32()   21 C8       AND  EAX, ECX
//   xor32()   31 C8       XOR  EAX, ECX
//   mul32()   0F AF C1    IMUL EAX, ECX   (ModRM C1=11 000 001: reg=EAX rm=ECX)
//   neg32()   F7 D8       NEG  EAX        (ModRM D8=11 011 000: /3 rm=EAX)

void Emitter::add32()  { emit8(0x01); emit8(0xC8); }
void Emitter::sub32()  { emit8(0x29); emit8(0xC8); }
void Emitter::or32()   { emit8(0x09); emit8(0xC8); }
void Emitter::and32()  { emit8(0x21); emit8(0xC8); }
void Emitter::xor32()  { emit8(0x31); emit8(0xC8); }
void Emitter::mul32()  { emit8(0x0F); emit8(0xAF); emit8(0xC1); }
void Emitter::neg32()  { emit8(0xF7); emit8(0xD8); }

// Shifts 32-bit with CL: D3 + ModRM(/ext, EAX)  (no REX prefix)
//   shl32_cl()   D3 E0    SHL EAX, CL
//   shr32_cl()   D3 E8    SHR EAX, CL
//   sar32_cl()   D3 F8    SAR EAX, CL

void Emitter::shl32_cl() { emit8(0xD3); emit8(0xE0); }
void Emitter::shr32_cl() { emit8(0xD3); emit8(0xE8); }
void Emitter::sar32_cl() { emit8(0xD3); emit8(0xF8); }

// --- ALU32 reg,imm32 ---
// Short-form EAX encodings (no ModRM; same opcodes as 64-bit without REX.W).
//   Function          Bytes          Instruction
//   add32_imm(imm)   05 imm32    ADD  EAX, imm32
//   sub32_imm(imm)   2D imm32    SUB  EAX, imm32
//   or32_imm(imm)    0D imm32    OR   EAX, imm32
//   and32_imm(imm)   25 imm32    AND  EAX, imm32
//   xor32_imm(imm)   35 imm32    XOR  EAX, imm32

void Emitter::add32_imm(int32_t imm)  { emit8(0x05); emit32(imm); }
void Emitter::sub32_imm(int32_t imm)  { emit8(0x2D); emit32(imm); }
void Emitter::or32_imm(int32_t imm)   { emit8(0x0D); emit32(imm); }
void Emitter::and32_imm(int32_t imm)  { emit8(0x25); emit32(imm); }
void Emitter::xor32_imm(int32_t imm)  { emit8(0x35); emit32(imm); }

// Shifts 32-bit with imm8: C1 + ModRM(/ext, EAX) + imm8  (no REX prefix)
//   shl32_imm(c)   C1 E0 c    SHL EAX, c
//   shr32_imm(c)   C1 E8 c    SHR EAX, c
//   sar32_imm(c)   C1 F8 c    SAR EAX, c

void Emitter::shl32_imm(uint8_t c) { emit8(0xC1); emit8(0xE0); emit8(c); }
void Emitter::shr32_imm(uint8_t c) { emit8(0xC1); emit8(0xE8); emit8(c); }
void Emitter::sar32_imm(uint8_t c) { emit8(0xC1); emit8(0xF8); emit8(c); }

// IMUL EAX, EAX, imm32 — 32-bit three-operand form (no REX prefix).
// 69 /r ModRM(C0=11 000 000: reg=EAX rm=EAX) imm32
void Emitter::mul32_imm(int32_t imm) { emit8(0x69); emit8(0xC0); emit32(imm); }

// --- CMP / TEST (for conditional jumps) ---

// CMP RAX, RCX  (64-bit): REX.W 39 /r ModRM(C8 = 11 001 000)
void Emitter::cmp64()          { emit8(0x48); emit8(0x39); emit8(0xC8); }
// CMP RAX, imm32 (64-bit short form): REX.W 3D imm32
void Emitter::cmp64_imm(int32_t imm) { emit8(0x48); emit8(0x3D); emit32(imm); }
// CMP EAX, ECX  (32-bit): 39 C8
void Emitter::cmp32()          { emit8(0x39); emit8(0xC8); }
// CMP EAX, imm32 (32-bit short form): 3D imm32
void Emitter::cmp32_imm(int32_t imm) { emit8(0x3D); emit32(imm); }
// TEST RAX, RCX (64-bit): REX.W 85 C8
void Emitter::test64()         { emit8(0x48); emit8(0x85); emit8(0xC8); }
// TEST RAX, imm32 (64-bit): REX.W A9 imm32
void Emitter::test64_imm(int32_t imm) { emit8(0x48); emit8(0xA9); emit32(imm); }
// TEST EAX, ECX (32-bit): 85 C8
void Emitter::test32()         { emit8(0x85); emit8(0xC8); }
// TEST EAX, imm32 (32-bit): A9 imm32
void Emitter::test32_imm(int32_t imm) { emit8(0xA9); emit32(imm); }

// Conditional jump with rel32 placeholder: 0F cc 00000000
void Emitter::jcc_rel32(uint8_t cc) { emit8(0x0F); emit8(cc); emit32(0); }

// MOVABS RAX, imm64 (48 B8 imm64)
void Emitter::mov_rax_imm64(uint64_t val) {
    emit8(0x48); emit8(0xB8); emit64(val);
}

// --- MOV immediate to memory ---

void Emitter::store_imm64(int32_t disp, int32_t imm) {
    // MOV QWORD PTR [RBX+disp32], sign-extended-imm32
    // Encoding: REX.W(48) C7 /0 ModRM(10,0,RBX) disp32 imm32
    // ModRM = modrm(2,0,RBX): mod=2(disp32), reg=0(/0 opcode ext), rm=RBX
    // imm32 is automatically sign-extended to 64 bits by the CPU.
    emit8(0x48); emit8(0xC7); emit8(modrm(2, 0, X86::RBX));
    emit32(disp); emit32(imm);
}

void Emitter::store_imm32_zext(int32_t disp, int32_t imm) {
    // BPF ALU32 MOV immediate: result must be zero-extended to 64 bits.
    if (imm >= 0) {
        // Non-negative: sign-extension == zero-extension, so the single
        // QWORD store with sign-extended imm32 produces the correct result.
        // MOV QWORD PTR [RBX+disp32], imm32  (10 bytes vs 12 for the general path)
        store_imm64(disp, imm);
    } else {
        // Negative: sign-extension would set upper 32 bits, but BPF ALU32
        // requires zero-extension.  Load into EAX (zeroes upper 32) then store.
        // MOV EAX, imm32   (B8 imm32) — 32-bit write zeroes upper 32 bits of RAX
        emit8(0xB8); emit32(imm);
        // MOV QWORD PTR [RBX+disp32], RAX — store full 64 bits (upper half = 0)
        store_r64(disp, X86::RAX);
    }
}

// --- Prologue / epilogue / control flow ---

// PUSH RBX  (53) — saves caller's RBX; also aligns stack to 16 bytes (was 8
// after the CALL that entered the JIT block, now 16 after this push).
void Emitter::push_rbx() { emit8(0x53); }

// POP RBX  (5B) — restores caller's RBX before returning.
void Emitter::pop_rbx()  { emit8(0x5B); }

// MOV RBX, RDI  (48 89 FB)
// REX.W(48) MOV /r(89) ModRM(FB): mod=3(reg) reg=7(RDI) rm=3(RBX)
// Copies the vm* argument (RDI) into our callee-saved register (RBX).
void Emitter::mov_rbx_rdi() { emit8(0x48); emit8(0x89); emit8(0xFB); }

void Emitter::call_helper(void* addr) {
    // MOVABS RAX, imm64  (48 B8 <8-byte addr>) — load absolute 64-bit address
    emit8(0x48); emit8(0xB8); emit64((uint64_t)addr);
    // CALL RAX  (FF D0) — indirect call; RBX survives (callee-saved by ABI)
    emit8(0xFF); emit8(0xD0);
}

void Emitter::ret_int(int val) {
    // Success epilogue: return the number of BPF instructions executed.
    // MOV EAX, imm32  (B8 imm32) — set return value
    emit8(0xB8); emit32(val);
    // POP RBX  (5B)             — restore caller's RBX
    emit8(0x5B);
    // RET       (C3)
    emit8(0xC3);
}

void Emitter::ret_zero() {
    // Abort epilogue: safepoint fired, tell the caller to fall back to interpreter.
    // XOR EAX, EAX  (31 C0) — return 0
    emit8(0x31); emit8(0xC0);
    // POP RBX  (5B)
    emit8(0x5B);
    // RET       (C3)
    emit8(0xC3);
}

void Emitter::patch_rel32(size_t inst_offset, size_t target_offset) {
    // Back-patches the rel32 field of a two-byte-opcode conditional jump
    // (e.g. 0F 85 rel32) that was emitted with a placeholder zero.
    //
    // Layout of the jump instruction at inst_offset:
    //   [inst_offset+0]  0F          (escape byte)
    //   [inst_offset+1]  8x          (condition opcode)
    //   [inst_offset+2]  rel32 (4B)  ← patched here
    //
    // rel32 = target - (end of instruction) = target - (inst_offset + 6)
    uint32_t rel = (uint32_t)(target_offset - (inst_offset + 6));
    memcpy(buf_.data() + inst_offset + 2, &rel, 4);
}

// ---------------------------------------------------------------------------
// JitCompiler implementation
// ---------------------------------------------------------------------------

// vm field offsets — offsetof is conditionally-supported on non-standard-layout
// types (C++17 §21.2.4), but works correctly on all major compilers (GCC/Clang).
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winvalid-offsetof"
const size_t JitCompiler::off_reg_            = offsetof(vm, reg);
const size_t JitCompiler::off_flags_          = offsetof(vm, flags);
const size_t JitCompiler::off_signal_pending_ = offsetof(vm, signal_pending);
const size_t JitCompiler::off_signal_depth_   = offsetof(vm, signal_depth);
const size_t JitCompiler::off_tlb_            = offsetof(vm, tlb);
const size_t JitCompiler::off_pc_             = offsetof(vm, pc);
#pragma GCC diagnostic pop

JitCompiler::JitCompiler() = default;

JitCompiler::~JitCompiler() {
    for (auto& [pc, b] : blocks_) {
        if (b.code) munmap(b.code, b.code_size);
    }
}

void JitCompiler::emit_safepoint(Emitter& e, std::vector<size_t>& abort_jumps) {
    // Generated code layout:
    //
    //   mov  eax, [rbx + off_flags_]       ; load vm::flags (int, 32-bit)
    //   test eax, 0x7                       ; VM_EXITED(1)|VM_KILLED(2)|VM_STOPPED(4)
    //   jnz  .abort                         ; → return 0 if any termination flag set
    //
    //   cmp  qword [rbx + off_signal_depth_], 0
    //   jnz  .skip_signal                   ; inside signal handler → skip pending check
    //   cmp  byte  [rbx + off_signal_pending_], 0
    //   jne  .abort                         ; → return 0 so interpreter can deliver signal
    //
    // .skip_signal:
    //   <body of JIT block>
    //
    // .abort:
    //   xor eax, eax; pop rbx; ret         ; return 0
    //
    // vm::flags and vm::signal_pending are read without C++ atomic operations.
    // This is intentional: the JIT safepoint is a performance hint, not a
    // strict synchronisation point.  x86_64 aligned loads are coherent by
    // hardware, so we will never observe a torn value; at worst we miss one
    // quantum and the interpreter catches it on the next step.

    // mov eax, [rbx + off_flags_]  — 32-bit load (flags is std::atomic<int>)
    e.emit8(0x8B); e.emit8(Emitter::modrm(2, X86::RAX, X86::RBX)); e.emit32(off_flags_);
    // test eax, 0x7
    e.emit8(0xA9); e.emit32(0x7);
    // jnz .abort  (rel32 placeholder)
    abort_jumps.push_back(e.size());
    e.emit8(0x0F); e.emit8(0x85); e.emit32(0);

    // cmp qword [rbx + off_signal_depth_], 0  — 64-bit cmp with sign-extended imm8
    e.emit8(0x48); e.emit8(0x83); e.emit8(Emitter::modrm(2, 7, X86::RBX));
    e.emit32(off_signal_depth_);
    e.emit8(0x00);  // imm8 = 0
    // jnz .skip_signal  (short jump; gap is ~13 bytes, always fits in int8)
    size_t jnz_depth = e.size();
    e.emit8(0x75); e.emit8(0);

    // cmp byte [rbx + off_signal_pending_], 0  — 8-bit load (std::atomic<bool>)
    e.emit8(0x80);
    e.emit8(Emitter::modrm(2, 7, X86::RBX));
    e.emit32(off_signal_pending_);
    e.emit8(0x00);
    // jne .abort  (rel32 placeholder)
    abort_jumps.push_back(e.size());
    e.emit8(0x0F); e.emit8(0x85); e.emit32(0);

    // .skip_signal: patch the short jnz above to land here
    size_t skip_target = e.size();
    e.data()[jnz_depth + 1] = (uint8_t)(skip_target - (jnz_depth + 2));
}

void JitCompiler::emit_helper_call(Emitter& e, void* helper, int32_t dst_disp) {
    // Assumes on entry: RAX = dst value, RCX = src value, RDX = off (if needed).
    // Marshals to System V arg registers, calls helper, stores result.
    //
    //   mov  rdi, rax            ; arg1 = dst
    //   mov  rsi, rcx            ; arg2 = src
    //   ; rdx = arg3 (off) already set by caller when required
    //   movabs rax, <helper>; call rax
    //   mov  [rbx + dst_disp], rax  ; write result back to reg[dst]
    //
    // RBX is callee-saved per ABI → vm* survives the call intact.
    e.emit8(0x48); e.emit8(0x89); e.emit8(0xC7);  // mov rdi, rax
    e.emit8(0x48); e.emit8(0x89); e.emit8(0xCE);  // mov rsi, rcx
    e.call_helper(helper);
    e.store_r64(dst_disp, X86::RAX);
}

bool JitCompiler::emit_alu64(Emitter& e, const bpf_insn* insn) {
    // ALU64 instruction pattern:
    //   load dst → RAX    (64-bit)
    //   load src → RCX    (only when BPF_X; shift ops need src in CL)
    //   <x86 64-bit ALU op>
    //   store RAX → dst   (64-bit store)
    //
    // For MUL/DIV/MOD, a C helper is called instead (see emit_helper_call).
    // For MOV/NEG/END, special-cased below to avoid loading an unused operand.
    //
    // BPF reg[n] is at [RBX + off_reg_ + n*8].
    bool is_x = (insn->code & 0x08) == BPF_X;
    uint8_t op = insn->code & 0xf0;
    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    int32_t src_disp = off_reg_ + insn->src_reg * 8;

    // MOV off==0: special handling (no need to load dst first)
    if (op == BPF_MOV && insn->off == 0) {
        // MOV64 r, r with same register is a no-op
        if (is_x && insn->dst_reg == insn->src_reg) return true;
        if (is_x) {
            // MOV_X: load src, store to dst
            e.load_r64(X86::RCX, src_disp);
            e.store_r64(dst_disp, X86::RCX);
        } else {
            // MOV_K: store immediate (sign-extended imm32)
            e.store_imm64(dst_disp, insn->imm);
        }
        return true;
    }

    // NEG: no src operand
    if (op == BPF_NEG) {
        e.load_r64(X86::RAX, dst_disp);
        e.neg64();
        e.store_r64(dst_disp, X86::RAX);
        return true;
    }

    // MOV with sign-extend (off != 0): inline MOVSX / MOVSXD
    if (op == BPF_MOV) {
        // Load src into RAX
        if (is_x) {
            e.load_r64(X86::RAX, src_disp);
        } else {
            // movabs rax, imm64
            e.emit8(0x48); e.emit8(0xB8); e.emit64((uint64_t)(int64_t)insn->imm);
        }
        // Sign-extend in-place within RAX
        switch (insn->off) {
        case 8:  // MOVSX RAX, AL  — REX.W 0F BE C0
            e.emit8(0x48); e.emit8(0x0F); e.emit8(0xBE); e.emit8(0xC0);
            break;
        case 16: // MOVSX RAX, AX  — REX.W 0F BF C0
            e.emit8(0x48); e.emit8(0x0F); e.emit8(0xBF); e.emit8(0xC0);
            break;
        case 32: // MOVSXD RAX, EAX — REX.W 63 C0
            e.emit8(0x48); e.emit8(0x63); e.emit8(0xC0);
            break;
        default: return false;
        }
        e.store_r64(dst_disp, X86::RAX);
        return true;
    }

    // BPF_END: byte swap — inline BSWAP / ROL
    if (op == BPF_END) {
        e.load_r64(X86::RAX, dst_disp);
        switch (insn->imm) {
        case 16:
            // ROL AX, 8 — swap two bytes of AX (66 C1 C0 08)
            e.emit8(0x66); e.emit8(0xC1); e.emit8(0xC0); e.emit8(0x08);
            // MOVZX EAX, AX — zero-extend to 64 bits (0F B7 C0)
            e.emit8(0x0F); e.emit8(0xB7); e.emit8(0xC0);
            break;
        case 32:
            // BSWAP EAX (0F C8) — auto-zeroes upper 32 bits
            e.emit8(0x0F); e.emit8(0xC8);
            break;
        case 64:
            // BSWAP RAX (REX.W 0F C8)
            e.emit8(0x48); e.emit8(0x0F); e.emit8(0xC8);
            break;
        default: return false;
        }
        e.store_r64(dst_disp, X86::RAX);
        return true;
    }

    // Peephole: ALU64 with imm where result == dst (true no-op, skip entirely)
    if (!is_x) {
        if (insn->imm == 0 && (op == BPF_ADD || op == BPF_SUB || op == BPF_OR ||
            op == BPF_XOR || op == BPF_LSH || op == BPF_RSH || op == BPF_ARSH)) {
            return true;
        }
        if (insn->imm == 1 && (op == BPF_MUL || op == BPF_DIV)) {
            return true;
        }
    }

    // General case: load dst into rax, load src (if X) into rcx
    e.load_r64(X86::RAX, dst_disp);
    if (is_x) e.load_r64(X86::RCX, src_disp);

    // Dispatch by operation
    switch (op) {
    case BPF_ADD:  is_x ? e.add64() : e.add64_imm(insn->imm); break;
    case BPF_SUB:  is_x ? e.sub64() : e.sub64_imm(insn->imm); break;
    case BPF_OR:   is_x ? e.or64()  : e.or64_imm(insn->imm);  break;
    case BPF_AND:  is_x ? e.and64() : e.and64_imm(insn->imm); break;
    case BPF_XOR:  is_x ? e.xor64() : e.xor64_imm(insn->imm); break;
    case BPF_LSH:
        if (is_x) e.shl64_cl(); else e.shl64_imm(insn->imm & 0x3F);
        break;
    case BPF_RSH:
        if (is_x) e.shr64_cl(); else e.shr64_imm(insn->imm & 0x3F);
        break;
    case BPF_ARSH:
        if (is_x) e.sar64_cl(); else e.sar64_imm(insn->imm & 0x3F);
        break;
    case BPF_MUL:  is_x ? e.mul64() : e.mul64_imm(insn->imm); break;
    case BPF_DIV: {
        if (!is_x) {
            e.emit8(0x48); e.emit8(0xC7); e.emit8(0xC1); e.emit32(insn->imm); // mov rcx, imm
        }
        // Set rdx = off for the helper
        e.emit8(0xBA); e.emit32((uint32_t)(int32_t)insn->off); // mov edx, off
        emit_helper_call(e, (void*)jit_div64, dst_disp);
        return true;
    }
    case BPF_MOD: {
        if (!is_x) {
            e.emit8(0x48); e.emit8(0xC7); e.emit8(0xC1); e.emit32(insn->imm); // mov rcx, imm
        }
        e.emit8(0xBA); e.emit32((uint32_t)(int32_t)insn->off); // mov edx, off
        emit_helper_call(e, (void*)jit_mod64, dst_disp);
        return true;
    }
    default: return false;
    }

    // Store result back to reg[dst]
    e.store_r64(dst_disp, X86::RAX);
    return true;
}

bool JitCompiler::emit_alu32(Emitter& e, const bpf_insn* insn) {
    // ALU32 instruction pattern:
    //   load dst → EAX    (32-bit load, zero-extends to 64)
    //   load src → ECX    (only when BPF_X; shift ops need src in CL)
    //   <x86 32-bit ALU op>  (32-bit write auto-zeroes upper 32 of RAX/RCX)
    //   store RAX → dst   (64-bit store; upper 32 already zero)
    //
    // x86_64 rule: any 32-bit write implicitly zeroes the upper 32 bits of the
    // destination register, so BPF ALU32 zero-extension to 64 bits is free.
    bool is_x = (insn->code & 0x08) == BPF_X;
    uint8_t op = insn->code & 0xf0;
    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    int32_t src_disp = off_reg_ + insn->src_reg * 8;

    // MOV off==0: special handling (no need to load dst first)
    // ALU32 MOV same-reg is NOT a no-op: must zero-extend upper 32 bits.
    if (op == BPF_MOV && insn->off == 0) {
        if (is_x) {
            // MOV_X: load src (32-bit, zero-extends), store 64-bit (upper zero)
            e.load_r32(X86::RCX, src_disp);
            e.store_r64(dst_disp, X86::RCX);
        } else {
            // MOV_K: store immediate with zero-extension
            e.store_imm32_zext(dst_disp, insn->imm);
        }
        return true;
    }

    // NEG: no src operand
    if (op == BPF_NEG) {
        e.load_r32(X86::RAX, dst_disp);
        e.neg32();
        e.store_r64(dst_disp, X86::RAX);
        return true;
    }

    // MOV with sign-extend (off != 0): inline MOVSX
    // ALU32 has no 32→32 sign-extend (only 8→32, 16→32).
    if (op == BPF_MOV) {
        // Load src into RAX (full 64-bit load, MOVSX will zero upper bits)
        if (is_x) {
            e.load_r64(X86::RAX, src_disp);
        } else {
            // movabs rax, imm64
            e.emit8(0x48); e.emit8(0xB8); e.emit64((uint64_t)(int64_t)insn->imm);
        }
        switch (insn->off) {
        case 8:  // MOVSX EAX, AL — 0F BE C0 (32-bit result, upper zeroed)
            e.emit8(0x0F); e.emit8(0xBE); e.emit8(0xC0);
            break;
        case 16: // MOVSX EAX, AX — 0F BF C0
            e.emit8(0x0F); e.emit8(0xBF); e.emit8(0xC0);
            break;
        default: return false;
        }
        e.store_r64(dst_disp, X86::RAX);
        return true;
    }

    // BPF_END: byte swap / zero-extend
    // ALU32 END uses BPF_X (is_x) to distinguish big-endian (byte swap) vs
    // little-endian (zero-extend) semantics.
    if (op == BPF_END) {
        if (is_x) {
            // ALU32 END BE: byte swap
            e.load_r32(X86::RAX, dst_disp);
            switch (insn->imm) {
            case 16:
                // ROL AX, 8 — swap two bytes of AX (66 C1 C0 08)
                e.emit8(0x66); e.emit8(0xC1); e.emit8(0xC0); e.emit8(0x08);
                // MOVZX EAX, AX — zero-extend to 64 bits (0F B7 C0)
                e.emit8(0x0F); e.emit8(0xB7); e.emit8(0xC0);
                break;
            case 32:
                // BSWAP EAX (0F C8)
                e.emit8(0x0F); e.emit8(0xC8);
                break;
            default: return false;
            }
        } else {
            // ALU32 END LE: zero-extend (no byte swap needed on LE host)
            switch (insn->imm) {
            case 16:
                e.load_r32(X86::RAX, dst_disp);
                e.emit8(0x25); e.emit32(0xFFFF);  // AND EAX, 0xFFFF
                break;
            case 32:
                e.load_r32(X86::RAX, dst_disp);
                break;
            case 64:
                // no-op (already native endian, 64-bit value unchanged)
                return true;
            default: return false;
            }
        }
        e.store_r64(dst_disp, X86::RAX);
        return true;
    }

    // General case: load dst into eax, load src (if X) into ecx
    e.load_r32(X86::RAX, dst_disp);
    if (is_x) e.load_r32(X86::RCX, src_disp);

    // Dispatch by operation (shift mask: 0x1F for 32-bit)
    switch (op) {
    case BPF_ADD:  is_x ? e.add32() : e.add32_imm(insn->imm); break;
    case BPF_SUB:  is_x ? e.sub32() : e.sub32_imm(insn->imm); break;
    case BPF_OR:   is_x ? e.or32()  : e.or32_imm(insn->imm);  break;
    case BPF_AND:  is_x ? e.and32() : e.and32_imm(insn->imm); break;
    case BPF_XOR:  is_x ? e.xor32() : e.xor32_imm(insn->imm); break;
    case BPF_LSH:
        if (is_x) e.shl32_cl(); else e.shl32_imm(insn->imm & 0x1F);
        break;
    case BPF_RSH:
        if (is_x) e.shr32_cl(); else e.shr32_imm(insn->imm & 0x1F);
        break;
    case BPF_ARSH:
        if (is_x) e.sar32_cl(); else e.sar32_imm(insn->imm & 0x1F);
        break;
    case BPF_MUL:  is_x ? e.mul32() : e.mul32_imm(insn->imm); break;
    case BPF_DIV: {
        if (!is_x) {
            e.emit8(0x48); e.emit8(0xC7); e.emit8(0xC1); e.emit32(insn->imm); // mov rcx, imm
        }
        // Set rdx = off for the helper
        e.emit8(0xBA); e.emit32((uint32_t)(int32_t)insn->off); // mov edx, off
        emit_helper_call(e, (void*)jit_div32, dst_disp);
        return true;
    }
    case BPF_MOD: {
        if (!is_x) {
            e.emit8(0x48); e.emit8(0xC7); e.emit8(0xC1); e.emit32(insn->imm); // mov rcx, imm
        }
        e.emit8(0xBA); e.emit32((uint32_t)(int32_t)insn->off); // mov edx, off
        emit_helper_call(e, (void*)jit_mod32, dst_disp);
        return true;
    }
    default: return false;
    }

    // Store result back to reg[dst]
    e.store_r64(dst_disp, X86::RAX);
    return true;
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
//
// For write operations (is_write=true), also checks PF_W permission and !cow.
// `miss_jumps` receives the offsets of all conditional jumps targeting .slow.
// `abort_jumps` receives the JE offset after the slow-path helper call.
// Returns: {slow_start, tlb_done} offsets for patching the JMP .done and
//          any miss jumps that use rel32.
// ---------------------------------------------------------------------------

struct TlbPatchInfo {
    size_t slow_start;   // offset of .slow label
    size_t tlb_done;     // offset of .done label (after load/store code)
    size_t done_jmp;     // offset of JMP .done (fast path) — needs patching
};

static TlbPatchInfo emit_tlb_lookup(Emitter& e, int32_t tlb_off, int size,
                                     bool is_write,
                                     std::vector<size_t>& miss_jumps,
                                     std::vector<size_t>& abort_jumps) {
    TlbPatchInfo info{};

    // ── Compute TLB index: (addr >> 20) & 0xF, scaled by sizeof(TlbEntry)=32 ──
    e.emit8(0x48); e.emit8(0x89); e.emit8(0xC9);  // mov rcx, rax
    e.emit8(0x48); e.emit8(0xC1); e.emit8(0xE9); e.emit8(20); // shr rcx, 20
    e.emit8(0x48); e.emit8(0x83); e.emit8(0xE1); e.emit8(0x0F); // and rcx, 0xF
    e.emit8(0x48); e.emit8(0xC1); e.emit8(0xE1); e.emit8(5);   // shl rcx, 5

    // ── Bounds check 1: addr >= entry.guest_base ──
    // CMP RAX, [RBX+RCX+tlb_off]
    e.sib_op_rax(0x3B, tlb_off);
    // JB .slow (rel32 placeholder)
    miss_jumps.push_back(e.size());
    e.emit8(0x0F); e.emit8(0x82); e.emit32(0);

    // ── Bounds check 2: addr + size <= entry.guest_end ──
    e.emit8(0x48); e.emit8(0x89); e.emit8(0xC2);  // mov rdx, rax
    e.emit8(0x48); e.emit8(0x83); e.emit8(0xC2); e.emit8((uint8_t)size); // add rdx, size
    // CMP RDX, [RBX+RCX+tlb_off+8]
    e.sib_op_rdx(0x3B, tlb_off + 8);
    // JA .slow
    miss_jumps.push_back(e.size());
    e.emit8(0x0F); e.emit8(0x87); e.emit32(0);

    if (is_write) {
        // ── Write permission: flags & PF_W (PF_W = 0x2) ──
        e.sib_test_dword(tlb_off + 24, 0x2);
        miss_jumps.push_back(e.size());
        e.emit8(0x0F); e.emit8(0x84); e.emit32(0);  // JZ .slow

        // ── No CoW: !cow (byte at offset 28) ──
        e.sib_cmp_byte(tlb_off + 28, 0);
        miss_jumps.push_back(e.size());
        e.emit8(0x0F); e.emit8(0x85); e.emit32(0);  // JNE .slow
    }

    // ── TLB hit: compute host_ptr = host_base + (addr - guest_base) ──
    e.sib_op_rax(0x2B, tlb_off);      // SUB RAX, [SIB+tlb_off]  (addr - guest_base)
    e.sib_op_rax(0x03, tlb_off + 16); // ADD RAX, [SIB+tlb_off+16]  (+ host_base)

    // JMP .done (rel32 placeholder)
    info.done_jmp = e.size();
    e.emit8(0xE9); e.emit32(0);

    // ── .slow: TLB miss — call C helper ──
    info.slow_start = e.size();

    // Set up args: rdi=vm*, rsi=addr, edx=size
    e.emit8(0x48); e.emit8(0x89); e.emit8(0xDF);  // mov rdi, rbx
    e.emit8(0x48); e.emit8(0x89); e.emit8(0xC6);  // mov rsi, rax
    e.emit8(0xBA); e.emit32((uint32_t)size);       // mov edx, size
    // Call the appropriate MMU helper
    e.call_helper(is_write ? (void*)jit_mmu_w : (void*)jit_mmu);

    // Test for null (memory violation)
    e.emit8(0x48); e.emit8(0x85); e.emit8(0xC0);  // test rax, rax
    abort_jumps.push_back(e.size());
    e.emit8(0x0F); e.emit8(0x84); e.emit32(0);     // JZ .error → abort_pos

    // ── .done: RAX = host pointer ──
    info.tlb_done = e.size();

    return info;
}

// Patch all miss jumps to slow_start, and done_jmp to tlb_done
static void patch_tlb_jumps(Emitter& e, const std::vector<size_t>& miss_jumps,
                             const TlbPatchInfo& info) {
    for (size_t off : miss_jumps) {
        // All miss jumps are 6-byte (0F 8x rel32); patch rel32 at off+2
        uint32_t rel = (uint32_t)(info.slow_start - (off + 6));
        memcpy(e.data() + off + 2, &rel, 4);
    }
    // JMP .done: E9 rel32 at done_jmp; patch rel32 at done_jmp+1
    {
        uint32_t rel = (uint32_t)(info.tlb_done - (info.done_jmp + 5));
        memcpy(e.data() + info.done_jmp + 1, &rel, 4);
    }
}

// ---------------------------------------------------------------------------
// emit_ld: LD DW | IMM — load 64-bit immediate (no memory access, no TLB)
// ---------------------------------------------------------------------------
bool JitCompiler::emit_ld(Emitter& e, const bpf_insn* insn) {
    uint8_t mode = insn->code & 0xe0;
    uint8_t size = insn->code & 0x18;
    if (mode != BPF_IMM || size != BPF_DW) return false;
    if (insn->dst_reg >= 10) return false;

    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    uint64_t imm64 = (uint64_t)(int32_t)(insn + 1)->imm << 32 | (uint32_t)insn->imm;

    // movabs rax, imm64
    e.emit8(0x48); e.emit8(0xB8); e.emit64(imm64);
    // mov [rbx + dst_disp], rax
    e.store_r64(dst_disp, X86::RAX);
    // Note: caller advances p by 2 and count by 2
    return true;
}

// ---------------------------------------------------------------------------
// emit_ldx: load from memory with inline TLB
// ---------------------------------------------------------------------------
bool JitCompiler::emit_ldx(Emitter& e, const bpf_insn* insn,
                            std::vector<size_t>& abort_jumps) {
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

    // Compute guest address: reg[src] + off
    e.load_r64(X86::RAX, src_disp);
    if (insn->off != 0) {
        e.emit8(0x48); e.emit8(0x05); e.emit32((uint32_t)(int32_t)insn->off); // add rax, off
    }

    // Inline TLB lookup
    std::vector<size_t> miss_jumps;
    auto tlb = emit_tlb_lookup(e, (int32_t)off_tlb_, access_size, false,
                                miss_jumps, abort_jumps);

    // At .tlb_done: RAX = host pointer, perform the actual load
    if (mode == BPF_MEM) {
        switch (size_field) {
        case BPF_DW:
            // mov rax, [rax]  (48 8B 00)
            e.emit8(0x48); e.emit8(0x8B); e.emit8(0x00);
            break;
        case BPF_W:
            // mov eax, [rax]  (8B 00) — auto zero-extends
            e.emit8(0x8B); e.emit8(0x00);
            break;
        case BPF_H:
            // movzx eax, word [rax]  (0F B7 00)
            e.emit8(0x0F); e.emit8(0xB7); e.emit8(0x00);
            break;
        case BPF_B:
            // movzx eax, byte [rax]  (0F B6 00)
            e.emit8(0x0F); e.emit8(0xB6); e.emit8(0x00);
            break;
        }
    } else { // BPF_MEMSX
        switch (size_field) {
        case BPF_W:
            // movsxd rax, dword [rax]  (48 63 00)
            e.emit8(0x48); e.emit8(0x63); e.emit8(0x00);
            break;
        case BPF_H:
            // movsx rax, word [rax]  (48 0F BF 00)
            e.emit8(0x48); e.emit8(0x0F); e.emit8(0xBF); e.emit8(0x00);
            break;
        case BPF_B:
            // movsx rax, byte [rax]  (48 0F BE 00)
            e.emit8(0x48); e.emit8(0x0F); e.emit8(0xBE); e.emit8(0x00);
            break;
        default: return false;
        }
    }

    // Store result to reg[dst]
    e.store_r64(dst_disp, X86::RAX);

    // Patch TLB jumps
    patch_tlb_jumps(e, miss_jumps, tlb);
    return true;
}

// ---------------------------------------------------------------------------
// emit_st: store immediate to memory with inline TLB
// ---------------------------------------------------------------------------
bool JitCompiler::emit_st(Emitter& e, const bpf_insn* insn,
                           std::vector<size_t>& abort_jumps) {
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

    // Compute guest address: reg[dst] + off
    e.load_r64(X86::RAX, dst_disp);
    if (insn->off != 0) {
        e.emit8(0x48); e.emit8(0x05); e.emit32((uint32_t)(int32_t)insn->off); // add rax, off
    }

    // Inline TLB lookup (write)
    std::vector<size_t> miss_jumps;
    auto tlb = emit_tlb_lookup(e, (int32_t)off_tlb_, access_size, true,
                                miss_jumps, abort_jumps);

    // Store immediate value to [rax]
    switch (size_field) {
    case BPF_DW:
        // mov qword [rax], sign-extended imm32  (48 C7 00 imm32)
        e.emit8(0x48); e.emit8(0xC7); e.emit8(0x00); e.emit32(insn->imm);
        break;
    case BPF_W:
        // mov dword [rax], imm32  (C7 00 imm32)
        e.emit8(0xC7); e.emit8(0x00); e.emit32(insn->imm);
        break;
    case BPF_H:
        // mov word [rax], imm16  (66 C7 00 imm16)
        e.emit8(0x66); e.emit8(0xC7); e.emit8(0x00); e.emit16((uint16_t)insn->imm);
        break;
    case BPF_B:
        // mov byte [rax], imm8  (C6 00 imm8)
        e.emit8(0xC6); e.emit8(0x00); e.emit8((uint8_t)insn->imm);
        break;
    }

    // Patch TLB jumps
    patch_tlb_jumps(e, miss_jumps, tlb);
    return true;
}

// ---------------------------------------------------------------------------
// emit_stx: store register to memory with inline TLB
// ---------------------------------------------------------------------------
bool JitCompiler::emit_stx(Emitter& e, const bpf_insn* insn,
                            std::vector<size_t>& abort_jumps) {
    uint8_t mode = insn->code & 0xe0;
    uint8_t size_field = insn->code & 0x18;
    if (mode == BPF_ATOMIC) return emit_stx_atomic(e, insn, abort_jumps);
    if (mode != BPF_MEM) return false;

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

    // Compute guest address: reg[dst] + off
    e.load_r64(X86::RAX, dst_disp);
    if (insn->off != 0) {
        e.emit8(0x48); e.emit8(0x05); e.emit32((uint32_t)(int32_t)insn->off); // add rax, off
    }

    // Inline TLB lookup (write)
    std::vector<size_t> miss_jumps;
    auto tlb = emit_tlb_lookup(e, (int32_t)off_tlb_, access_size, true,
                                miss_jumps, abort_jumps);

    // At .tlb_done: RAX = host pointer, load src value and store it
    e.load_r64(X86::RCX, src_disp);

    switch (size_field) {
    case BPF_DW:
        // mov [rax], rcx  (48 89 08)
        e.emit8(0x48); e.emit8(0x89); e.emit8(0x08);
        break;
    case BPF_W:
        // mov [rax], ecx  (89 08)
        e.emit8(0x89); e.emit8(0x08);
        break;
    case BPF_H:
        // mov [rax], cx  (66 89 08)
        e.emit8(0x66); e.emit8(0x89); e.emit8(0x08);
        break;
    case BPF_B:
        // mov [rax], cl  (88 08)
        e.emit8(0x88); e.emit8(0x08);
        break;
    }

    // Patch TLB jumps
    patch_tlb_jumps(e, miss_jumps, tlb);
    return true;
}

// ---------------------------------------------------------------------------
// emit_stx_atomic: locked read-modify-write with inline TLB
// ---------------------------------------------------------------------------
// Matches Linux kernel's arch/x86/net/bpf_jit_comp.c approach:
//
//   ADD, OR, AND, XOR           → lock add/or/and/xor [mem], reg
//   ADD|FETCH                   → lock xadd [mem], reg  (naturally returns old)
//   OR|FETCH, AND|FETCH, XCHG   → lock cmpxchg loop (CAS loop)
//   XCHG                        → xchg [mem], reg  (implicitly locked by x86)
//   CMPXCHG                     → lock cmpxchg [mem], reg
//
// Register allocation at the point where we start emitting:
//   RAX = host pointer (from TLB)
//   RBX = vm*
//   RCX, RDX, RDI = scratch
// ---------------------------------------------------------------------------
bool JitCompiler::emit_stx_atomic(Emitter& e, const bpf_insn* insn,
                                    std::vector<size_t>& abort_jumps) {
    uint8_t size_field = insn->code & 0x18;
    if (size_field != BPF_DW && size_field != BPF_W) return false;

    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    int32_t src_disp = off_reg_ + insn->src_reg * 8;
    int32_t r0_disp  = off_reg_;  // r(0)
    bool is_dw = (size_field == BPF_DW);
    int access_size = is_dw ? 8 : 4;

    // Compute guest address: reg[dst] + off
    e.load_r64(X86::RAX, dst_disp);
    if (insn->off != 0) {
        e.emit8(0x48); e.emit8(0x05); e.emit32((uint32_t)(int32_t)insn->off); // add rax, off
    }

    // Inline TLB lookup (write)
    std::vector<size_t> miss_jumps;
    auto tlb = emit_tlb_lookup(e, (int32_t)off_tlb_, access_size, true,
                                miss_jumps, abort_jumps);

    // ── RAX = host pointer.  Save to RDX, load src to RCX ──
    e.emit8(0x48); e.emit8(0x89); e.emit8(0xC2);              // mov rdx, rax
    e.load_r64(X86::RCX, src_disp);                            // mov rcx, [rbx+src_disp]

    int32_t op = insn->imm;

    // ── OR/AND/XOR | FETCH: CAS loop (matches Linux kernel) ──
    // x86 has no single instruction for atomic fetch-or/and/xor,
    // so we use a lock cmpxchg loop like the kernel does.
    if (op == (BPF_OR  | BPF_FETCH) ||
        op == (BPF_AND | BPF_FETCH) ||
        op == (BPF_XOR | BPF_FETCH)) {
        uint8_t alu_opcode = ((op & ~BPF_FETCH) == BPF_OR)  ? 0x09
                            : ((op & ~BPF_FETCH) == BPF_AND) ? 0x21
                            : 0x31;  // XOR

        // Save r(0) to RDI (CMPXCHG uses RAX as comparison value)
        e.emit8(0x48); e.emit8(0x8B); e.emit8(0x3B);           // mov rdi, [rbx]  (r0)

        size_t loop_start = e.size();

        // Load old value from memory
        if (is_dw) {
            e.emit8(0x48); e.emit8(0x8B); e.emit8(0x02);       // mov rax, [rdx]
        } else {
            e.emit8(0x8B); e.emit8(0x02);                       // mov eax, [rdx]
        }

        // Compute new = old OP src into RDI
        if (is_dw) {
            e.emit8(0x48); e.emit8(0x89); e.emit8(0xC7);       // mov rdi, rax
        } else {
            e.emit8(0x89); e.emit8(0xC7);                       // mov edi, eax
        }
        if (is_dw) e.emit8(0x48);
        e.emit8(alu_opcode); e.emit8(0xCF);                     // op rdi/edi, rcx/ecx

        // lock cmpxchg [rdx], rdi — try to swap in new value
        if (is_dw) e.emit8(0x48);
        e.emit8(0xF0);                                           // lock prefix
        e.emit8(0x0F); e.emit8(0xB1); e.emit8(0x3A);           // cmpxchg [rdx], rdi

        // If ZF=0 (race lost, RAX updated to current value), retry
        e.emit8(0x75);                                           // jnz loop_start
        auto loop_end = e.size();
        int8_t rel = (int8_t)(loop_start - loop_end);
        e.data()[loop_end - 1] = (uint8_t)rel;

        // src_reg = old value (now in RAX after successful cmpxchg)
        e.store_r64(src_disp, X86::RAX);

        // Restore r(0)
        e.emit8(0x48); e.emit8(0x89); e.emit8(0x3B);           // mov [rbx], rdi (saved r0)

        patch_tlb_jumps(e, miss_jumps, tlb);
        return true;
    }

    switch (op) {
    // ── lock xadd [rdx], rcx — old value ends up in rcx ──
    case BPF_ADD:
    case BPF_ADD | BPF_FETCH:
        e.emit8(0xF0);                                           // lock prefix
        if (is_dw) e.emit8(0x48);                               // REX.W
        e.emit8(0x0F); e.emit8(0xC1); e.emit8(0x0A);           // xadd [rdx], rcx
        if (op & BPF_FETCH) {
            e.store_r64(src_disp, X86::RCX);                    // src_reg = old
        }
        break;

    // ── lock or/and/xor [rdx], rcx — no old value needed ──
    case BPF_OR:
    case BPF_AND:
    case BPF_XOR: {
        uint8_t opcode = (op == BPF_OR) ? 0x09
                       : (op == BPF_AND) ? 0x21
                       : 0x31;  // XOR
        e.emit8(0xF0);                                           // lock prefix
        if (is_dw) e.emit8(0x48);                               // REX.W
        e.emit8(opcode); e.emit8(0x0A);                         // op [rdx], rcx
        break;
    }

    // ── xchg [rdx], rcx (implicitly locked by x86, no F0 needed) ──
    case BPF_XCHG:
        if (is_dw) e.emit8(0x48);                               // REX.W
        e.emit8(0x87); e.emit8(0x0A);                           // xchg [rdx], rcx
        // Old value is now in RCX
        e.store_r64(src_disp, X86::RCX);                        // src_reg = old
        break;

    // ── lock cmpxchg [rdx], rcx — RAX = r(0) (comparison value) ──
    case BPF_CMPXCHG:
        // Load r(0) into RAX (clobbers host ptr, but we saved it to RDX)
        e.load_r64(X86::RAX, r0_disp);                          // mov rax, [rbx+r0_disp]
        e.emit8(0xF0);                                           // lock prefix
        if (is_dw) e.emit8(0x48);                               // REX.W
        e.emit8(0x0F); e.emit8(0xB1); e.emit8(0x0A);           // cmpxchg [rdx], rcx
        // Old destination value is now in RAX; store to r(0)
        e.store_r64(r0_disp, X86::RAX);                         // r(0) = old
        break;

    default:
        return false;
    }

    patch_tlb_jumps(e, miss_jumps, tlb);
    return true;
}

// ---------------------------------------------------------------------------
// emit_jmp64: conditional jumps (64-bit compare)
// ---------------------------------------------------------------------------
// Emits: load dst → RAX, load/imm src, CMP/TEST, Jcc .taken.
// On not-taken: falls through to the next instruction in the block.
// On taken: jumps to a taken-handler (emitted later) that sets vm::pc and returns
// a negative count.
//
// Returns false for JA/CALL/EXIT (block terminates; interpreter handles them).
// ---------------------------------------------------------------------------
bool JitCompiler::emit_jmp64(Emitter& e, const bpf_insn* insn, int index,
                              std::vector<JumpPatchInfo>& jump_patches) {
    uint8_t op = insn->code & 0xf0;
    bool is_x = (insn->code & 0x08) == BPF_X;
    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    int32_t src_disp = off_reg_ + insn->src_reg * 8;

    // JA/CALL/EXIT: cannot JIT within block, terminate
    if (op == BPF_JA || op == BPF_CALL || op == BPF_EXIT) return false;

    uint8_t x86_cc = 0;
    bool is_test = false;

    switch (op) {
    case BPF_JEQ:  x86_cc = 0x84; break; // JE
    case BPF_JNE:  x86_cc = 0x85; break; // JNE
    case BPF_JGT:  x86_cc = 0x87; break; // JA  (unsigned above)
    case BPF_JGE:  x86_cc = 0x83; break; // JAE (unsigned above-or-equal)
    case BPF_JLT:  x86_cc = 0x82; break; // JB  (unsigned below)
    case BPF_JLE:  x86_cc = 0x86; break; // JBE (unsigned below-or-equal)
    case BPF_JSGT: x86_cc = 0x8F; break; // JG  (signed greater)
    case BPF_JSGE: x86_cc = 0x8D; break; // JGE (signed greater-or-equal)
    case BPF_JSLT: x86_cc = 0x8C; break; // JL  (signed less)
    case BPF_JSLE: x86_cc = 0x8E; break; // JLE (signed less-or-equal)
    case BPF_JSET: x86_cc = 0x85; is_test = true; break; // JNZ after TEST
    default: return false;
    }

    // Load dst into RAX (64-bit)
    e.load_r64(X86::RAX, dst_disp);

    // Compare / test
    if (is_test) {
        if (is_x) {
            e.load_r64(X86::RCX, src_disp);
            e.test64();
        } else {
            e.test64_imm(insn->imm);
        }
    } else {
        if (is_x) {
            e.load_r64(X86::RCX, src_disp);
            e.cmp64();
        } else {
            e.cmp64_imm(insn->imm);
        }
    }

    // Jcc rel32 (placeholder, patched later to taken-handler)
    size_t jcc_off = e.size();
    e.jcc_rel32(x86_cc);

    jump_patches.push_back({jcc_off, insn + insn->off, index});
    return true;
}

// ---------------------------------------------------------------------------
// emit_jmp32: conditional jumps (32-bit compare)
// ---------------------------------------------------------------------------
// Same as emit_jmp64 but uses 32-bit loads and compares (lower 32 bits only).
// ---------------------------------------------------------------------------
bool JitCompiler::emit_jmp32(Emitter& e, const bpf_insn* insn, int index,
                              std::vector<JumpPatchInfo>& jump_patches) {
    uint8_t op = insn->code & 0xf0;
    bool is_x = (insn->code & 0x08) == BPF_X;
    int32_t dst_disp = off_reg_ + insn->dst_reg * 8;
    int32_t src_disp = off_reg_ + insn->src_reg * 8;

    // JA in JMP32 uses imm field; CALL/EXIT not valid in JMP32
    if (op == BPF_JA || op == BPF_CALL || op == BPF_EXIT) return false;

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

    // Load dst lower 32 bits into EAX (zero-extends to 64)
    e.load_r32(X86::RAX, dst_disp);

    if (is_test) {
        if (is_x) {
            e.load_r32(X86::RCX, src_disp);
            e.test32();
        } else {
            e.test32_imm(insn->imm);
        }
    } else {
        if (is_x) {
            e.load_r32(X86::RCX, src_disp);
            e.cmp32();
        } else {
            e.cmp32_imm(insn->imm);
        }
    }

    size_t jcc_off = e.size();
    e.jcc_rel32(x86_cc);

    jump_patches.push_back({jcc_off, insn + insn->off, index});
    return true;
}

// ---------------------------------------------------------------------------
// compile: build a JIT block of consecutive JIT-able instructions
// ---------------------------------------------------------------------------
JitBlock* JitCompiler::compile(const bpf_insn* pc) {
    // If we already compiled this block, return it.
    auto it = blocks_.find(pc);
    if (it != blocks_.end()) {
        return &it->second;
    }

    Emitter e;
    std::vector<size_t> abort_jumps;  // all jumps targeting abort_pos (safepoint + memory violation)
    std::vector<JumpPatchInfo> jump_patches;  // conditional jump patching

    // ── Prologue ──────────────────────────────────────────────────────────
    // push RBX          ; save caller's RBX (callee-saved); aligns stack to 16
    // mov  RBX, RDI     ; RBX = vm*  (kept live for the entire block)
    e.push_rbx();
    e.mov_rbx_rdi();

    // ── Safepoint check ───────────────────────────────────────────────────
    emit_safepoint(e, abort_jumps);

    // ── Scan and emit ────────────────────────────────────────────────────
    // Emit consecutive JIT-able instructions (ALU/ALU64/LD/LDX/ST/STX).
    int count = 0;
    bool hit_max = false;
    const int MAX_BLOCK = 512;
    const bpf_insn* p = pc;
    for (; count < MAX_BLOCK; ) {
        uint8_t cls = p->code & 0x07;
        bool emitted = false;

        switch (cls) {
        case BPF_ALU64:
            if (p->dst_reg >= 10) goto done;
            emitted = emit_alu64(e, p);
            if (emitted) { p++; count++; }
            break;
        case BPF_ALU:
            if (p->dst_reg >= 10) goto done;
            emitted = emit_alu32(e, p);
            if (emitted) { p++; count++; }
            break;
        case BPF_LD:
            emitted = emit_ld(e, p);
            if (emitted) { p += 2; count += 2; }  // LD DW consumes 2 insns
            break;
        case BPF_LDX:
            if (p->dst_reg >= 10) goto done;
            emitted = emit_ldx(e, p, abort_jumps);
            if (emitted) { p++; count++; }
            break;
        case BPF_ST:
            emitted = emit_st(e, p, abort_jumps);
            if (emitted) { p++; count++; }
            break;
        case BPF_STX:
            emitted = emit_stx(e, p, abort_jumps);
            if (emitted) { p++; count++; }
            break;
        case BPF_JMP:
            emitted = emit_jmp64(e, p, count, jump_patches);
            if (emitted) { p++; count++; }
            break;
        case BPF_JMP32:
            emitted = emit_jmp32(e, p, count, jump_patches);
            if (emitted) { p++; count++; }
            break;
        default:
            goto done;
        }

        if (!emitted) break;
        if (count >= MAX_BLOCK) { hit_max = true; break; }
    }
done:

    if (count == 0) return nullptr;

    // Track block termination reason
    if (hit_max) {
        stats.term_max_block++;
    } else {
        uint8_t cls = p->code & 0x07;
        uint8_t op = p->code & 0xf0;
        if (cls == BPF_JMP) {
            if (op == BPF_CALL) stats.term_call++;
            else if (op == BPF_EXIT) stats.term_exit++;
            else if (op == BPF_JA) stats.term_ja++;
            else stats.term_unsupported++;
        } else {
            stats.term_unsupported++;
        }
    }

    // ── Success epilogue ──────────────────────────────────────────────────
    // mov EAX, count    ; return value = number of BPF instructions executed
    // pop RBX           ; restore caller's RBX
    // ret
    e.ret_int(count);

    // ── Taken-handler stubs (conditional jumps that were taken) ───────────
    // Each stub sets vm::pc to the branch target and returns a negative count.
    for (auto& jp : jump_patches) {
        e.patch_rel32(jp.jcc_offset, e.size());
        // movabs rax, <target bpf_insn*>
        e.mov_rax_imm64((uint64_t)jp.target);
        // mov [rbx + off_pc_], rax
        e.store_r64((int32_t)off_pc_, X86::RAX);
        // return -(index + 1)
        e.ret_int(-(jp.index + 1));
    }

    // ── Abort epilogue (safepoint / memory violation target) ──────────────
    // xor EAX, EAX      ; return 0 → interpreter takes over
    // pop RBX
    // ret
    size_t abort_pos = e.size();
    e.ret_zero();

    // Patch all abort jumps (safepoint + memory violation) to abort_pos.
    for (size_t off : abort_jumps) {
        e.patch_rel32(off, abort_pos);
    }

    // Allocate executable memory and copy code
    size_t code_size = e.size();
    // Round up to page size
    size_t alloc_size = (code_size + 4095) & ~(size_t)4095;
    // W^X: allocate writable first, write code, then switch to executable-only
    void* code_mem = mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code_mem == MAP_FAILED) return nullptr;

    memcpy(code_mem, e.data(), code_size);

    if (mprotect(code_mem, alloc_size, PROT_READ | PROT_EXEC) != 0) {
        munmap(code_mem, alloc_size);
        return nullptr;
    }

    stats.jit_compiles++;
    stats.jit_compiled_insns += count;
    return &blocks_.emplace(pc, JitBlock{code_mem, count, alloc_size}).first->second;
}

#endif // __x86_64__

void JitCompiler::dump_stats(const JitStats& s) {
    if (!getenv("JIT_DEBUG")) return;
    double pct = s.total_insns ? (100.0 * s.jit_insns / s.total_insns) : 0.0;
    fprintf(stderr, "[JIT] 总指令条数: %lu\n", s.total_insns);
    fprintf(stderr, "[JIT] JIT执行条数: %lu (%.1f%%)\n", s.jit_insns, pct);
    fprintf(stderr, "[JIT] JIT编译block数: %lu\n", s.jit_compiles);
    fprintf(stderr, "[JIT] JIT执行block次数: %lu\n", s.jit_block_runs);
    if (s.jit_compiles) {
        fprintf(stderr, "[JIT] 编译时平均block大小: %.1f条\n",
                (double)s.jit_compiled_insns / s.jit_compiles);
    }
    if (s.jit_block_runs) {
        fprintf(stderr, "[JIT] 运行时平均每次执行: %.1f条\n",
                (double)s.jit_insns / s.jit_block_runs);
    }
    fprintf(stderr, "[JIT] Block终止原因: CALL=%lu EXIT=%lu JA=%lu MAX_BLOCK=%lu UNSUPPORTED=%lu\n",
            s.term_call, s.term_exit, s.term_ja, s.term_max_block, s.term_unsupported);
}
