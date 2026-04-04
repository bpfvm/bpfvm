//
// Created by chouryzhou on 26-3-31.
//

#include "jit.h"

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

// ---------------------------------------------------------------------------
// Emitter implementation
// ---------------------------------------------------------------------------

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
#pragma GCC diagnostic pop

JitCompiler::JitCompiler() = default;

JitCompiler::~JitCompiler() {
    for (auto& [pc, b] : blocks_) {
        if (b.code) munmap(b.code, b.code_size);
    }
}

void JitCompiler::emit_safepoint(Emitter& e, size_t& jnz_flags, size_t& jne_signal) {
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
    // jnz .abort  (rel32 placeholder; patched in emit_patch_safepoint)
    jnz_flags = e.size();
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
    jne_signal = e.size();
    e.emit8(0x0F); e.emit8(0x85); e.emit32(0);

    // .skip_signal: patch the short jnz above to land here
    size_t skip_target = e.size();
    e.data()[jnz_depth + 1] = (uint8_t)(skip_target - (jnz_depth + 2));
}

void JitCompiler::emit_patch_safepoint(Emitter& e, size_t jnz_flags, size_t jne_signal, size_t abort_pos) {
    e.patch_rel32(jnz_flags, abort_pos);
    e.patch_rel32(jne_signal, abort_pos);
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

JitBlock* JitCompiler::compile(const bpf_insn* pc) {
    // if has exist block, return it.
    auto it = blocks_.find(pc);
    if (it != blocks_.end()) {
        return &it->second;
    }

    Emitter e;

    // ── Prologue ──────────────────────────────────────────────────────────
    // push RBX          ; save caller's RBX (callee-saved); aligns stack to 16
    // mov  RBX, RDI     ; RBX = vm*  (kept live for the entire block)
    e.push_rbx();
    e.mov_rbx_rdi();

    // ── Safepoint check ───────────────────────────────────────────────────
    size_t jnz_flags = 0, jne_signal = 0;
    emit_safepoint(e, jnz_flags, jne_signal);

    // ── Scan and emit ────────────────────────────────────────────────────
    // Emit consecutive BPF_ALU / BPF_ALU64 instructions.
    // Stop at the first non-ALU instruction, an out-of-range dst_reg, or
    // an encoding emit_insn64/emit_insn32 cannot handle.
    int count = 0;
    const int MAX_BLOCK = 512;
    for (const bpf_insn* p = pc; count < MAX_BLOCK; p++, count++) {
        uint8_t cls = p->code & 0x07;
        if (cls != BPF_ALU && cls != BPF_ALU64) break;
        if (p->dst_reg >= 10) break;
        if (!(cls == BPF_ALU64 ? emit_alu64(e, p) : emit_alu32(e, p))) break;
    }

    if (count == 0) return nullptr;

    // ── Success epilogue ──────────────────────────────────────────────────
    // mov EAX, count    ; return value = number of BPF instructions executed
    // pop RBX           ; restore caller's RBX
    // ret
    e.ret_int(count);

    // ── Abort epilogue (safepoint target) ─────────────────────────────────
    // xor EAX, EAX      ; return 0 → interpreter takes over
    // pop RBX
    // ret
    size_t abort_pos = e.size();
    e.ret_zero();

    // Back-patch the two conditional jumps in the safepoint to land here.
    emit_patch_safepoint(e, jnz_flags, jne_signal, abort_pos);

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

    return &blocks_.emplace(pc, JitBlock{code_mem, count, alloc_size}).first->second;
}

#endif // __x86_64__
