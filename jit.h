//
// Created by chouryzhou on 26-3-31.
//

#ifndef JIT_H
#define JIT_H

#include <stdint.h>
#include <stddef.h>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <sys/mman.h>

struct bpf_insn;
class vm;
struct JitFunction;

// ---------------------------------------------------------------------------
// JIT compiler overview (x86_64 only)
// ---------------------------------------------------------------------------
//
// Scope
// -----
// Each BPF function is compiled independently into its own x86 function.
// Reachable BPF instructions within a single function (discovered via BFS
// from the entry PC, NOT following BPF-to-BPF CALL targets) are compiled
// into a contiguous x86 function.  Jumps use near rel32 with placeholders
// patched after code generation.
//
// Control flow inside JIT:
//   - Conditional/unconditional jumps  → Jcc/JMP rel32 (patched post-scan)
//   - CALL syscall (src_reg==0)        → call jit_do_syscall helper
//   - CALL BPF-to-BPF (src_reg==1)     → push_frame + set vm::pc + exit JIT
//   - CALL indirect (BPF_X)            → call jit_resolve_indirect + exit JIT
//   - EXIT                             → call jit_pop_frame + exit JIT
//   - Safepoint                        → call jit_safepoint helper (loop headers)
//   - Memory violation                 → jump to .vm_exit
//
// The JIT function always returns -1 to the interpreter (step()), which then:
//   - Re-enters JIT for the new pc (CALL/EXIT changed pc)
//   - Handles VM exit flags (VM_EXITED, VM_KILLED)
//   - Falls through to interpreter on compilation failure
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
//   RDI      | 1st argument when calling a C helper (= vm*)
//   RSI      | 2nd argument when calling a C helper
//
// BPF reg n is at: [RBX + offsetof(vm, reg) + n*8]
//
// JIT function calling convention
// -------------------------------
// Each compiled function has the signature:  int jit_func(vm* v)
//   - Called with vm* in RDI (System V AMD64 ABI).
//   - Prologue: push RBX; mov RBX, RDI; JMP .entry
//     .entry: safepoint + BPF instruction code
//   - Returns -1 on all exits (vm_exit label)
//   - step() checks vm::flags and vm::pc to determine next action
//
// BPF → x86 instruction correspondence
// --------------------------------------
// BPF ALU64 (64-bit):
//   BPF_ADD  dst += src/imm   →  ADD  RAX, RCX / ADD RAX, imm32
//   BPF_SUB  dst -= src/imm   →  SUB  RAX, RCX / SUB RAX, imm32
//   BPF_MUL  dst *= src/imm   →  IMUL RAX, RCX / IMUL RAX, imm32
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
// ---------------------------------------------------------------------------

#if defined(__x86_64__)

// x86_64 register encoding (ModRM rm/reg field values)
namespace X86 {
    constexpr uint8_t RAX = 0;  // scratch: dst value, return value
    constexpr uint8_t RCX = 1;  // scratch: src value, shift count (CL)
    constexpr uint8_t RDX = 2;  // scratch: 3rd helper argument
    constexpr uint8_t RBX = 3;  // vm* pointer — callee-saved, live throughout
    constexpr uint8_t RSP = 4;
    constexpr uint8_t RBP = 5;
    constexpr uint8_t RSI = 6;  // 2nd System V arg register
    constexpr uint8_t RDI = 7;  // 1st System V arg register
}

// ---------------------------------------------------------------------------
// Emitter: low-level x86_64 code generation
// ---------------------------------------------------------------------------
class Emitter {
    std::vector<uint8_t> buf_;
    struct PendingCall {
        size_t call_offset;  // offset of the CALL rel32 instruction
        void* helper;        // target helper address
    };
    std::vector<PendingCall> pending_calls_;
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
    void sib_op_rax(uint8_t opcode, int32_t disp);
    void sib_op_rdx(uint8_t opcode, int32_t disp);
    void sib_test_dword(int32_t disp, uint32_t imm);
    void sib_cmp_byte(int32_t disp, uint8_t imm);

    // CMP / TEST: compare and test (for conditional jumps)
    void cmp64();
    void cmp64_imm(int32_t imm);
    void cmp32();
    void cmp32_imm(int32_t imm);
    void test64();
    void test64_imm(int32_t imm);
    void test32();
    void test32_imm(int32_t imm);

    // Conditional jump with rel32 placeholder: 0F cc 00000000
    void jcc_rel32(uint8_t cc);
    // Unconditional jump with rel32 placeholder: E9 00000000
    void jmp_rel32();
    // Near call with rel32 placeholder: E8 00000000
    void call_rel32();

    // MOVABS RAX, imm64 (48 B8 imm64)
    void mov_rax_imm64(uint64_t val);

    // ALU64 reg,reg: op rax, rcx
    void add64();    void sub64();    void or64();     void and64();
    void xor64();    void mul64();    void neg64();
    void shl64_cl(); void shr64_cl(); void sar64_cl();

    // ALU64 reg,imm32: op rax, imm32
    void add64_imm(int32_t imm);  void sub64_imm(int32_t imm);
    void or64_imm(int32_t imm);   void and64_imm(int32_t imm);
    void xor64_imm(int32_t imm);  void mul64_imm(int32_t imm);
    void shl64_imm(uint8_t count); void shr64_imm(uint8_t count);
    void sar64_imm(uint8_t count);

    // ALU32 reg,reg: op eax, ecx
    void add32();    void sub32();    void or32();     void and32();
    void xor32();    void mul32();    void neg32();
    void shl32_cl(); void shr32_cl(); void sar32_cl();

    // ALU32 reg,imm32
    void add32_imm(int32_t imm);  void sub32_imm(int32_t imm);
    void or32_imm(int32_t imm);   void and32_imm(int32_t imm);
    void xor32_imm(int32_t imm);  void mul32_imm(int32_t imm);
    void shl32_imm(uint8_t count); void shr32_imm(uint8_t count);
    void sar32_imm(uint8_t count);

    // MOV: store immediate
    void store_imm64(int32_t disp, int32_t imm);
    void store_imm32_zext(int32_t disp, int32_t imm);

    // Helper call: emit CALL rel32 (5 bytes), patched by patch_calls() after mmap.
    void call_helper(void* addr);

    // Patch all deferred CALL rel32 sites given the final code base address.
    // Returns false if any helper is beyond ±2GB (caller should reject the JIT).
    bool patch_calls(void* code_base);

    // Common register-to-register MOVs
    void mov_rdi_rbx();    // mov rdi, rbx  (48 89 DF) — 1st arg = vm*
    void mov_rsi_rax();    // mov rsi, rax  (48 89 C6) — 2nd arg = rax
    void mov_rdx_rax();    // mov rdx, rax  (48 89 C2) — 3rd arg = rax

    // Common TEST instructions
    void test_rax_rax();   // test rax, rax (48 85 C0) — null check
    void test_eax_eax();   // test eax, eax (85 C0)    — zero check (32-bit)
    void test_al_al();     // test al, al   (84 C0)    — bool check

    // Save/restore vm* (rbx)
    void push_rbx();
    void pop_rbx();
    void mov_rbx_rdi();

    // Control flow
    void ret_int(int val);
    void ret_zero();

    size_t size() const { return buf_.size(); }
    uint8_t* data() { return buf_.data(); }

    // Patch a Jcc rel32 at offset (4 bytes after offset+2)
    void patch_rel32(size_t inst_offset, size_t target_offset);
    // Patch a JMP/CALL rel32 at offset (4 bytes after offset+1)
    void patch_jmp_rel32(size_t inst_offset, size_t target_offset);
};

// ---------------------------------------------------------------------------
// Jump / call placeholder for deferred patching
// ---------------------------------------------------------------------------
enum class PlaceholderKind : uint8_t {
    Jcc,    // conditional jump Jcc rel32 (6 bytes, patch at offset+2)
    Jmp,    // unconditional JMP rel32 (5 bytes, patch at offset+1)
};

struct JumpPlaceholder {
    size_t patch_offset;      // offset in Emitter buffer
    int target_bpf_index;     // target BPF instruction index (relative to entry_pc)
    PlaceholderKind kind;
};

struct AbortPatchInfo {
    size_t jump_offset;       // offset of the conditional jump to .vm_exit
    int bpf_index;            // BPF instruction index that may trigger abort
};

// Context for inline TLB memory access: begin_mem_access() fills this,
// the caller emits the actual load/store, then finish_mem_access() patches.
struct MemAccessContext {
    std::vector<size_t> miss_jumps;   // TLB miss Jcc offsets → .slow
    std::vector<size_t> abort_jumps;  // null-pointer Jcc offsets → .vm_exit
    size_t slow_start;   // offset of .slow label
    size_t done_offset;  // offset of .done label (after load/store code)
    size_t done_jmp;     // offset of JMP .done (fast path) — needs patching
};

// ---------------------------------------------------------------------------
// JitFunction: one compiled BPF function
// ---------------------------------------------------------------------------
struct JitFunction {
    void* code;                    // executable entry point
    int insn_count;                // total BPF instructions compiled
    size_t code_size;              // mmap'd allocation size
    const bpf_insn* entry_pc;      // first BPF instruction
    std::vector<uint32_t> pc_offsets; // BPF index → x86 code offset
};

// ---------------------------------------------------------------------------
// JitStats
// ---------------------------------------------------------------------------
struct JitStats {
    uint64_t total_insns = 0;
    uint64_t jit_insns = 0;
    uint64_t jit_compiles = 0;
    uint64_t jit_compiled_insns = 0;
    uint64_t jit_func_runs = 0;
    uint64_t compile_ns = 0;       // total JIT compilation time (ns)
};

// ---------------------------------------------------------------------------
// JitCompiler
// ---------------------------------------------------------------------------
class JitCompiler {
public:
    JitCompiler();
    ~JitCompiler();

    // Compile or find a JIT function starting at pc.
    // Returns nullptr if the instruction cannot be JIT-compiled.
    // v is the VM instance (needed for code segment bounds and address translation).
    JitFunction* compile(vm* v, const bpf_insn* pc);

    JitStats stats;

    static void dump_stats(const JitStats& s);

private:
    // vm field offsets
    static const size_t off_reg_;
    static const size_t off_pc_;
    static const size_t off_flags_;
    static const size_t off_signal_pending_;
    static const size_t off_signal_depth_;
    static const size_t off_tlb_;

    std::unordered_map<const bpf_insn*, JitFunction> functions_;
    std::unordered_set<const bpf_insn*> failed_;
    bool enabled_ = true;

    // JIT runtime helpers — called from JIT-generated code via function pointer.
    // Static member functions use System V AMD64 ABI (same as C functions on x86-64 Linux),
    // so call_helper() works correctly with their addresses.
    static int helper_safepoint(vm* v);
    static bool helper_push_frame(vm* v, uint64_t ret_addr);
    static uint64_t helper_pop_frame(vm* v);
    static bool helper_do_syscall(vm* v, uint32_t call_id);
    static bool helper_call_indirect(vm* v, uint64_t ret_gpa, uint64_t target);
    static int helper_return_to_caller(vm* v, uint64_t ret_gpa);
    static void* helper_mmu(vm* v, uint64_t addr, uint64_t size);
    static void* helper_mmu_w(vm* v, uint64_t addr, uint64_t size);

    // Pre-scan: discover all reachable BPF instructions via BFS.
    // Returns a vector<bool> indexed by BPF instruction offset from start.
    // seg_limit is the max number of instructions in the segment (bounds check).
    // back_edge_targets is filled with indices that are backward jump targets.
    // func_size is set to the function extent (one past max reachable index).
    std::vector<bool> discover_reachable(const bpf_insn* start, int seg_limit,
                                         std::vector<bool>& back_edge_targets,
                                         int& func_size);

    // Emit methods for each instruction type.
    // All return true on success, false if the instruction cannot be JIT-compiled.
    bool emit_alu64(Emitter& e, const bpf_insn* insn) { return emit_alu<true>(e, insn); }
    bool emit_alu32(Emitter& e, const bpf_insn* insn) { return emit_alu<false>(e, insn); }
    template<bool Is64> bool emit_alu(Emitter& e, const bpf_insn* insn);
    bool emit_ld(Emitter& e, const bpf_insn* insn);
    bool emit_ldx(Emitter& e, const bpf_insn* insn, std::vector<AbortPatchInfo>& abort_patches, int bpf_index);
    bool emit_st(Emitter& e, const bpf_insn* insn, std::vector<AbortPatchInfo>& abort_patches, int bpf_index);
    bool emit_stx(Emitter& e, const bpf_insn* insn, std::vector<AbortPatchInfo>& abort_patches, int bpf_index);
    bool emit_stx_atomic(Emitter& e, const bpf_insn* insn, std::vector<AbortPatchInfo>& abort_patches, int bpf_index);

    // Conditional jumps — emit CMP/TEST + Jcc with placeholder
    bool emit_jmp64(Emitter& e, const bpf_insn* insn, int current_index,
                    std::vector<JumpPlaceholder>& placeholders) { return emit_jmp<true>(e, insn, current_index, placeholders); }
    bool emit_jmp32(Emitter& e, const bpf_insn* insn, int current_index,
                    std::vector<JumpPlaceholder>& placeholders) { return emit_jmp<false>(e, insn, current_index, placeholders); }
    template<bool Is64> bool emit_jmp(Emitter& e, const bpf_insn* insn, int current_index,
                                       std::vector<JumpPlaceholder>& placeholders);

    // Unconditional jump (JA)
    void emit_ja(Emitter& e, const bpf_insn* insn, int current_index,
                 std::vector<JumpPlaceholder>& placeholders);
    void emit_ja32(Emitter& e, const bpf_insn* insn, int current_index,
                   std::vector<JumpPlaceholder>& placeholders);

    // CALL variants
    void emit_call_syscall(Emitter& e, const bpf_insn* insn, int current_index,
                         const bpf_insn* entry_pc,
                           std::vector<AbortPatchInfo>& abort_patches);
    void emit_call_bpf(Emitter& e, const bpf_insn* insn, int current_index,
                       uint64_t ret_gpa,
                       const bpf_insn* entry_pc,
                       size_t vm_exit_offset,
                       std::vector<AbortPatchInfo>& abort_patches);
    void emit_call_indirect(Emitter& e, const bpf_insn* insn, int current_index,
                            uint64_t ret_gpa,
                            std::vector<AbortPatchInfo>& abort_patches);

    // EXIT
    void emit_exit(Emitter& e, size_t vm_exit_offset);

    // Helper call (div/mod/etc.)
    void emit_helper_call(Emitter& e, void* helper, int32_t dst_disp);

    // TLB memory access helpers: begin loads address + TLB lookup, finish patches jumps.
    MemAccessContext begin_mem_access(Emitter& e, int32_t base_disp,
                                      int16_t offset, int access_size, bool is_write);
    void finish_mem_access(Emitter& e, MemAccessContext& ctx,
                            std::vector<AbortPatchInfo>& abort_patches, int bpf_index);

    // compile() sub-methods
    size_t emit_prologue(Emitter& e, std::vector<AbortPatchInfo>& abort_patches);
    bool emit_instruction(Emitter& e, vm* v, const bpf_insn* entry_pc, int i,
                          size_t vm_exit_offset,
                          std::vector<JumpPlaceholder>& placeholders,
                          std::vector<AbortPatchInfo>& abort_patches,
                          int& compiled_count);
    void* finalize_code(Emitter& e);
};

#else // !__x86_64__

// Stub: JIT not supported on this architecture.
class JitCompiler {
public:
    struct JitFunction { void* code; int insn_count; size_t code_size; const bpf_insn* entry_pc; };
    JitFunction* compile(vm*, const bpf_insn*) { return nullptr; }
    JitStats stats;
    static void dump_stats(const JitStats& s);
};

#endif // __x86_64__

#endif // JIT_H
