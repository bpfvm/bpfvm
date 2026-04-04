//
// Created by chouryzhou on 26-3-31.
//

#ifndef JIT_H
#define JIT_H

#include <stdint.h>
#include <stddef.h>
#include <unordered_map>
#include <vector>
#include <sys/mman.h>

struct bpf_insn;
class vm;

struct JitBlock {
    void* code;          // executable entry point
    int insn_count;      // number of BPF instructions in this block
    size_t code_size;    // mmap'd size
};

#if defined(__x86_64__)

// ---------------------------------------------------------------------------
// JIT compiler overview (x86_64 only)
// ---------------------------------------------------------------------------
//
// Scope
// -----
// Consecutive BPF_ALU / BPF_ALU64 / BPF_LD / BPF_LDX / BPF_ST / BPF_STX
// instructions are JIT-compiled into a single "block".  Other instruction
// classes (JMP, JMP32, CALL, EXIT, STX ATOMIC …) remain interpreted.
// Memory instructions use an inline TLB fast path; TLB misses fall through
// to a C helper for the slow path (map scan + TLB fill + CoW resolution).
//
// Register mapping
// ----------------
// BPF has 11 logical registers (r0–r10).  They are stored in the vm::reg[]
// array in host memory.  The JIT does NOT maintain a permanent mapping between
// BPF registers and x86 registers; instead each instruction is compiled as a
// load–operate–store sequence using the following scratch registers:
//
//   x86 reg  | role inside JIT block
//   ---------+--------------------------------------------------
//   RBX      | vm* pointer (callee-saved; set in prologue, live throughout)
//   RAX      | dst operand (loaded from reg[dst], result written back)
//   RCX      | src operand (loaded from reg[src] when BPF_X)
//             | also shift count (x86 requires shift amount in CL)
//   RDX      | 3rd argument to helper functions (e.g. insn->off for div/mod)
//   RDI      | 1st argument when calling a C helper (= RAX before call)
//   RSI      | 2nd argument when calling a C helper (= RCX before call)
//
// BPF reg n is at: [RBX + offsetof(vm, reg) + n*8]
//
// JIT block calling convention
// ----------------------------
// Each compiled block has the signature:  int block(vm* v)
//   - Called with vm* in RDI (System V AMD64 ABI).
//   - Prologue: push RBX; mov RBX, RDI   (save callee-saved RBX, set vm ptr)
//   - Returns the number of BPF instructions consumed (> 0) on success.
//   - Returns 0 if the safepoint check fires (VM flags or signal pending);
//     the interpreter then handles the single instruction and checks signals.
//   - Epilogue: mov EAX, count; pop RBX; ret
//
// Safepoint
// ---------
// At block entry (before any BPF work) the JIT checks:
//   1. vm::flags & 0x7 (VM_EXITED | VM_KILLED | VM_STOPPED) → abort if set.
//   2. If vm::signal_depth == 0: vm::signal_pending != 0 → abort if set.
// Both checks jump to the "abort" epilogue (xor EAX,EAX; pop RBX; ret) which
// returns 0 to the interpreter.
//
// BPF → x86 instruction correspondence
// --------------------------------------
// BPF ALU64 (64-bit):
//   BPF_ADD  dst += src/imm   →  ADD  RAX, RCX / ADD RAX, imm32
//   BPF_SUB  dst -= src/imm   →  SUB  RAX, RCX / SUB RAX, imm32
//   BPF_MUL  dst *= src/imm   →  helper jit_mul64(dst, src)
//   BPF_DIV  dst /= src/imm   →  helper jit_div64(dst, src, off)
//   BPF_MOD  dst %= src/imm   →  helper jit_mod64(dst, src, off)
//   BPF_OR   dst |= src/imm   →  OR   RAX, RCX / OR  RAX, imm32
//   BPF_AND  dst &= src/imm   →  AND  RAX, RCX / AND RAX, imm32
//   BPF_XOR  dst ^= src/imm   →  XOR  RAX, RCX / XOR RAX, imm32
//   BPF_NEG  dst = -dst       →  NEG  RAX
//   BPF_LSH  dst <<= src/imm  →  SHL  RAX, CL  / SHL RAX, imm8  (imm & 0x3F)
//   BPF_RSH  dst >>= src/imm  →  SHR  RAX, CL  / SHR RAX, imm8  (imm & 0x3F)
//   BPF_ARSH dst s>>= src/imm →  SAR  RAX, CL  / SAR RAX, imm8  (imm & 0x3F)
//   BPF_MOV  dst = src/imm    →  direct load/store (or movabs for imm64)
//   BPF_MOV  (off≠0) movsx    →  helper jit_mov_sx{8,16,32}
//   BPF_END  bswap            →  helper jit_end{16,32,64}
//
// BPF ALU32 (32-bit, results zero-extended to 64):
//   Same ops as ALU64 but uses 32-bit x86 variants (no REX.W prefix).
//   x86 32-bit writes automatically zero-extend to 64 bits (x86_64 rule),
//   so writing EAX implicitly clears the upper 32 bits of RAX.
//   BPF_MOV  (off≠0) movsx    →  helper jit_mov_sx{8,16} + mov EAX,EAX
//   BPF_END BE bswap          →  helper jit_end{16,32}_32
//   BPF_END LE zero-extend    →  AND EAX,0xFFFF (16-bit) / load_r32 (32-bit)
//                                no-op (64-bit, already native endian)
//
// MUL, DIV, MOD, and all sign-extend / byte-swap ops use C helpers because
// BPF semantics for divide-by-zero and overflow differ from native x86.
// ---------------------------------------------------------------------------

// x86_64 register encoding (ModRM rm/reg field values)
namespace X86 {
    constexpr uint8_t RAX = 0;  // scratch: dst value, return value, 1st helper arg (via RDI)
    constexpr uint8_t RCX = 1;  // scratch: src value, shift count (CL), 2nd helper arg (via RSI)
    constexpr uint8_t RDX = 2;  // scratch: 3rd helper argument (e.g. insn->off)
    constexpr uint8_t RBX = 3;  // vm* pointer — callee-saved, live for the entire block
    constexpr uint8_t RSP = 4;
    constexpr uint8_t RBP = 5;
    constexpr uint8_t RSI = 6;  // 2nd System V arg register (used only in helper calls)
    constexpr uint8_t RDI = 7;  // 1st System V arg register (used only in helper calls)
}

class Emitter {
    std::vector<uint8_t> buf_;
public:
    void emit8(uint8_t v) { buf_.push_back(v); }
    void emit16(uint16_t v);
    void emit32(uint32_t v);
    void emit64(uint64_t v);

    static uint8_t modrm(uint8_t mod, uint8_t reg, uint8_t rm) {
        return (mod << 6) | ((reg & 7) << 3) | (rm & 7);
    }

    // mov r64, [rbx + disp32]
    void load_r64(uint8_t dst, int32_t disp);
    // mov [rbx + disp32], r64
    void store_r64(int32_t disp, uint8_t src);
    // mov r32, [rbx + disp32]  (zero-extends to 64 bits)
    void load_r32(uint8_t dst, int32_t disp);

    // SIB-addressed operations: [RBX + RCX + disp32]
    // Used for inline TLB access.  SIB byte = 0x0B (scale=1, index=RCX, base=RBX).
    // REX.W + opcode + ModRM(10,reg,100) + SIB(00,RCX,RBX) + disp32
    void sib_op_rax(uint8_t opcode, int32_t disp);
    void sib_op_rdx(uint8_t opcode, int32_t disp);
    // TEST DWORD [RBX+RCX+disp], imm32  (for flags check)
    void sib_test_dword(int32_t disp, uint32_t imm);
    // CMP BYTE [RBX+RCX+disp], imm8  (for cow check)
    void sib_cmp_byte(int32_t disp, uint8_t imm);

    // CMP / TEST: compare and test (for conditional jumps)
    void cmp64();           // CMP RAX, RCX   (48 39 C8)
    void cmp64_imm(int32_t imm); // CMP RAX, imm32 (48 3D imm32)
    void cmp32();           // CMP EAX, ECX   (39 C8)
    void cmp32_imm(int32_t imm); // CMP EAX, imm32 (3D imm32)
    void test64();          // TEST RAX, RCX  (48 85 C8)
    void test64_imm(int32_t imm); // TEST RAX, imm32 (48 A9 imm32)
    void test32();          // TEST EAX, ECX  (85 C8)
    void test32_imm(int32_t imm); // TEST EAX, imm32 (A9 imm32)

    // Conditional jump with rel32 placeholder: 0F cc 00000000
    void jcc_rel32(uint8_t cc);
    // MOVABS RAX, imm64 (48 B8 imm64)
    void mov_rax_imm64(uint64_t val);

    // ALU64 reg,reg: op rax, rcx
    void add64();    // 48 01 C8
    void sub64();    // 48 29 C8
    void or64();     // 48 09 C8
    void and64();    // 48 21 C8
    void xor64();    // 48 31 C8
    void mul64();    // 48 0F AF C1
    void neg64();    // 48 F7 D8
    void shl64_cl(); // 48 D3 E0
    void shr64_cl(); // 48 D3 E8
    void sar64_cl(); // 48 D3 F8

    // ALU64 reg,imm32: op rax, imm32
    void add64_imm(int32_t imm);
    void sub64_imm(int32_t imm);
    void or64_imm(int32_t imm);
    void and64_imm(int32_t imm);
    void xor64_imm(int32_t imm);
    void shl64_imm(uint8_t count);
    void shr64_imm(uint8_t count);
    void sar64_imm(uint8_t count);
    void mul64_imm(int32_t imm);

    // ALU32 reg,reg: op eax, ecx
    void add32();
    void sub32();
    void or32();
    void and32();
    void xor32();
    void mul32();
    void neg32();
    void shl32_cl(); // D3 E0
    void shr32_cl(); // D3 E8
    void sar32_cl(); // D3 F8

    // ALU32 reg,imm32
    void add32_imm(int32_t imm);
    void sub32_imm(int32_t imm);
    void or32_imm(int32_t imm);
    void and32_imm(int32_t imm);
    void xor32_imm(int32_t imm);
    void shl32_imm(uint8_t count);
    void shr32_imm(uint8_t count);
    void sar32_imm(uint8_t count);
    void mul32_imm(int32_t imm);

    // MOV: store immediate (64-bit, sign-extended imm32)
    void store_imm64(int32_t disp, int32_t imm);
    // MOV: mov eax, imm32; store rax 64-bit
    void store_imm32_zext(int32_t disp, int32_t imm);

    // Helper call: movabs rax, addr; call rax
    // Presumes rdi=arg1, rsi=arg2, rdx=arg3 already set
    void call_helper(void* addr);

    // Save/restore vm* (rbx) around helper calls
    // vm* is in rbx; before call: save rbx, move rdi to rbx
    // Actually we keep vm* in rbx always. Before helper call we need to
    // set rdi as arg1. After call, we don't need to restore (rbx preserved).
    // push/pop rbx around the call to be safe against potential stack alignment issues
    void push_rbx();
    void pop_rbx();
    void mov_rbx_rdi();  // mov rbx, rdi

    // Control flow
    void ret_int(int val);
    void ret_zero();

    size_t size() const { return buf_.size(); }
    uint8_t* data() { return buf_.data(); }

    // Patch a rel32 at offset (at the 4 bytes after offset+2)
    void patch_rel32(size_t inst_offset, size_t target_offset);
};



struct JumpPatchInfo {
    size_t jcc_offset;       // offset in Emitter buffer of the Jcc instruction
    const bpf_insn* target;  // target bpf_insn* pointer (insn + insn->off)
    int index;               // sequential index of this jump instruction in the block
};

class JitCompiler {
public:
    JitCompiler();
    ~JitCompiler();

    // Compile or find a block of consecutive ALU/ALU64 instructions starting at pc.
    // Returns nullptr if first instruction is not ALU/ALU64.
    JitBlock* compile(const bpf_insn* pc);
private:
    // vm field offsets (defined in jit.cpp via offsetof)
    static const size_t off_reg_;
    static const size_t off_flags_;
    static const size_t off_signal_pending_;
    static const size_t off_signal_depth_;
    static const size_t off_tlb_;
    static const size_t off_pc_;

    std::unordered_map<const bpf_insn*, JitBlock> blocks_;

    void emit_safepoint(Emitter& e, std::vector<size_t>& abort_jumps);

    // Emit code for one ALU64 (64-bit) instruction. Returns false if cannot JIT.
    bool emit_alu64(Emitter& e, const bpf_insn* insn);
    // Emit code for one ALU (32-bit) instruction. Returns false if cannot JIT.
    bool emit_alu32(Emitter& e, const bpf_insn* insn);

    // Emit code for memory instructions.  abort_jumps collects JE offsets that
    // must be patched to the block's abort_pos (memory violation → return 0).
    bool emit_ld(Emitter& e, const bpf_insn* insn);
    bool emit_ldx(Emitter& e, const bpf_insn* insn, std::vector<size_t>& abort_jumps);
    bool emit_st(Emitter& e, const bpf_insn* insn, std::vector<size_t>& abort_jumps);
    bool emit_stx(Emitter& e, const bpf_insn* insn, std::vector<size_t>& abort_jumps);
    bool emit_stx_atomic(Emitter& e, const bpf_insn* insn, std::vector<size_t>& abort_jumps);

    // Emit code for one JMP (64-bit) conditional jump. Returns false if cannot JIT.
    bool emit_jmp64(Emitter& e, const bpf_insn* insn, int index,
                    std::vector<JumpPatchInfo>& jump_patches);
    // Emit code for one JMP32 (32-bit) conditional jump. Returns false if cannot JIT.
    bool emit_jmp32(Emitter& e, const bpf_insn* insn, int index,
                    std::vector<JumpPatchInfo>& jump_patches);

    void emit_helper_call(Emitter& e, void* helper, int32_t dst_disp);
};

#else // !__x86_64__

// Stub: JIT not supported on this architecture.
class JitCompiler {
public:
    JitBlock* compile(const bpf_insn*) { return nullptr; }
};

#endif // __x86_64__

#endif // JIT_H
