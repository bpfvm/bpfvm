//
// x86_emitter.h — x86_64-specific JIT code emitter.
//

#ifndef X86_EMITTER_H
#define X86_EMITTER_H

#include "jit_base_emitter.h"
#include "jit.h"

#if defined(__x86_64__)

struct bpf_insn;

// ---------------------------------------------------------------------------
// x86_64 register encoding (ModRM rm/reg field values)
// ---------------------------------------------------------------------------
namespace X86 {
    constexpr uint8_t RAX = 0;
    constexpr uint8_t RCX = 1;
    constexpr uint8_t RDX = 2;
    constexpr uint8_t RBX = 3;
    constexpr uint8_t RSP = 4;
    constexpr uint8_t RBP = 5;
    constexpr uint8_t RSI = 6;
    constexpr uint8_t RDI = 7;
    constexpr uint8_t R8  = 8;
    constexpr uint8_t R9  = 9;
    constexpr uint8_t R10 = 10;
    constexpr uint8_t R11 = 11;
    constexpr uint8_t R12 = 12;
    constexpr uint8_t R13 = 13;
    constexpr uint8_t R14 = 14;
    constexpr uint8_t R15 = 15;
}

// BPF r6-r9 → x86 callee-saved register mapping
constexpr uint8_t BPF_CALLEE_REG[4] = { X86::R12, X86::R13, X86::R14, X86::R15 };

// ---------------------------------------------------------------------------
// X86Emitter: full x86_64 JIT backend
// ---------------------------------------------------------------------------
class X86Emitter : public EmitterBase {
public:
    // VM state setup (call before each compilation session)
    void set_vm_offsets(size_t off_reg, size_t off_pc, size_t off_flags, size_t off_tlb);
    void set_helpers(const HelperTable& h);

    // --- High-level BPF instruction emission ---

    PrologueResult emit_prologue(std::vector<AbortPatchInfo>& abort_patches);
    void emit_safepoint(std::vector<AbortPatchInfo>& abort_patches, int bpf_index);

    bool emit_alu(const bpf_insn* insn, bool is_64);
    bool emit_ld(const bpf_insn* insn);
    bool emit_ldx(const bpf_insn* insn, std::vector<AbortPatchInfo>& abort_patches, int bpf_index);
    bool emit_st(const bpf_insn* insn, std::vector<AbortPatchInfo>& abort_patches, int bpf_index);
    bool emit_stx(const bpf_insn* insn, std::vector<AbortPatchInfo>& abort_patches, int bpf_index);
    bool emit_stx_atomic(const bpf_insn* insn, std::vector<AbortPatchInfo>& abort_patches, int bpf_index);

    bool emit_jmp(const bpf_insn* insn, int current_index, bool is_64,
                  std::vector<JumpPlaceholder>& placeholders);
    void emit_ja(const bpf_insn* insn, int current_index,
                 std::vector<JumpPlaceholder>& placeholders);
    void emit_ja32(const bpf_insn* insn, int current_index,
                   std::vector<JumpPlaceholder>& placeholders);

    void emit_call_syscall(const bpf_insn* insn, int current_index,
                           const bpf_insn* entry_pc, size_t vm_exit_offset);
    void emit_call_bpf(const bpf_insn* insn, int current_index,
                       uint64_t ret_gpa, const bpf_insn* entry_pc,
                       size_t vm_exit_offset, std::vector<AbortPatchInfo>& abort_patches);
    void emit_call_indirect(const bpf_insn* insn, int current_index,
                            uint64_t ret_gpa, std::vector<AbortPatchInfo>& abort_patches);
    void emit_exit(size_t vm_exit_offset);

    MemAccessContext begin_mem_access(int32_t base_disp, int16_t offset,
                                      int access_size, bool is_write);
    void finish_mem_access(MemAccessContext& ctx,
                           std::vector<AbortPatchInfo>& abort_patches, int bpf_index);

private:
    // VM field offsets
    size_t off_reg_ = 0;
    size_t off_pc_ = 0;
    size_t off_flags_ = 0;
    size_t off_tlb_ = 0;

    // Helper function pointers
    HelperTable helpers_;

    // --- ModRM ---
    static uint8_t modrm(uint8_t mod, uint8_t reg, uint8_t rm) {
        return (mod << 6) | ((reg & 7) << 3) | (rm & 7);
    }

    // --- Memory access (frame-relative) ---
    void load_r64(uint8_t dst, int32_t disp);
    void store_r64(int32_t disp, uint8_t src);
    void load_r32(uint8_t dst, int32_t disp);

    // --- SIB-addressed operations: [RBP + RDI + disp32] ---
    void sib_op_rax(uint8_t opcode, int32_t disp);
    void sib_op_rdx(uint8_t opcode, int32_t disp);
    void sib_test_dword(int32_t disp, uint32_t imm);
    void sib_cmp_byte(int32_t disp, uint8_t imm);

    // --- BPF register access ---
    void load_bpf(uint8_t bpf_reg, uint8_t x86_dst);
    void store_bpf_wt(uint8_t bpf_reg, uint8_t x86_src);
    void store_bpf_wt32(uint8_t bpf_reg, uint8_t x86_src);
    void store_bpf_lazy(uint8_t bpf_reg, uint8_t x86_src);
    void flush_r6_r9();

    // --- Register-to-register ---
    void mov_r64(uint8_t dst, uint8_t src);

    // --- ALU64 reg,reg ---
    void add64();    void sub64();    void or64();     void and64();
    void xor64();    void mul64();    void neg64();
    void shl64_cl(); void shr64_cl(); void sar64_cl();

    // --- ALU64 reg,imm32 ---
    void add64_imm(int32_t imm);  void sub64_imm(int32_t imm);
    void or64_imm(int32_t imm);   void and64_imm(int32_t imm);
    void xor64_imm(int32_t imm);  void mul64_imm(int32_t imm);
    void shl64_imm(uint8_t count); void shr64_imm(uint8_t count);
    void sar64_imm(uint8_t count);

    // --- ALU32 reg,reg ---
    void add32();    void sub32();    void or32();     void and32();
    void xor32();    void mul32();    void neg32();
    void shl32_cl(); void shr32_cl(); void sar32_cl();

    // --- ALU32 reg,imm32 ---
    void add32_imm(int32_t imm);  void sub32_imm(int32_t imm);
    void or32_imm(int32_t imm);   void and32_imm(int32_t imm);
    void xor32_imm(int32_t imm);  void mul32_imm(int32_t imm);
    void shl32_imm(uint8_t count); void shr32_imm(uint8_t count);
    void sar32_imm(uint8_t count);

    // --- CMP / TEST ---
    void cmp64();          void cmp64_imm(int32_t imm);
    void cmp32();          void cmp32_imm(int32_t imm);
    void test64();         void test64_imm(int32_t imm);
    void test32();         void test32_imm(int32_t imm);

    // --- Control flow ---
    void jcc_rel32(uint8_t cc);
    void jmp_rel32();

    // --- Immediate / common patterns ---
    void mov_rax_imm64(uint64_t val);
    void store_imm64(int32_t disp, int32_t imm);
    void store_imm32_zext(int32_t disp, int32_t imm);
    void call_helper(void* addr);
    void mov_rdi_rbp();    void mov_rsi_rax();    void mov_rdx_rax();
    void test_rax_rax();   void test_eax_eax();  void test_al_al();

    // --- Prologue/epilogue helpers ---
    void push_rbp();       void pop_rbp();
    void mov_rbp_rdi();

    // --- Internal emit helpers ---
    void emit_helper_call(void* helper);
};

#endif // __x86_64__

#endif // X86_EMITTER_H
