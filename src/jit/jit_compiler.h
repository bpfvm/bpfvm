//
// jit_compiler.h — Architecture-independent JIT compiler template.
//

#ifndef JIT_COMPILER_H
#define JIT_COMPILER_H

#include "jit.h"

#include <concepts>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <vector>

// Forward declaration
class vm;

// ---------------------------------------------------------------------------
// JitEmitter concept — interface required by JitCompiler from EmitterT
// ---------------------------------------------------------------------------
// Any EmitterT passed to JitCompiler<EmitterT> must satisfy this concept.
// If a method is missing or has the wrong signature, the compiler will
// produce a clear error message indicating which requirement is not met.
// ---------------------------------------------------------------------------
template<typename T>
concept JitEmitter = requires(T& e, const bpf_insn* insn, int idx,
                              std::vector<JumpPlaceholder>& jmps,
                              std::vector<AbortPatchInfo>& aborts,
                              std::vector<size_t>& cache_offs,
                              uint64_t gpa, uint64_t ret_gpa, uint64_t callee_gpa,
                              uint64_t frame,
                              const HelperTable& helpers,
                              const bpf_insn* entry_pc) {
    // VM state setup
    e.set_vm_offsets(0u, 0u, 0u, 0u, 0u, 0u);
    e.set_budget(0u, 0u, false);
    e.set_helpers(helpers);

    // Prologue / safepoint
    { e.emit_prologue() } -> std::same_as<size_t>;
    e.emit_safepoint(0u, (uint64_t)0);

    // BPF instruction emission
    e.emit_alu(insn, true);
    e.emit_ld(insn);
    e.emit_ldx(insn, aborts, idx);
    e.emit_st(insn, aborts, idx);
    e.emit_stx(insn, aborts, idx);
    e.emit_jmp(insn, idx, true, jmps);
    e.emit_ja(insn, idx, jmps);
    e.emit_set_pc_imm(gpa);
    { e.emit_jmp_deopt(insn, true, gpa, jmps) } -> std::convertible_to<bool>;
    e.emit_ja32(insn, idx, jmps);
    e.emit_call_syscall(insn, idx, gpa);
    e.emit_call_bpf(ret_gpa, callee_gpa, frame, aborts, idx, cache_offs);
    e.emit_call_indirect(insn, gpa, aborts, idx, cache_offs);
    e.emit_exit(aborts, idx);

    // Buffer access
    { e.size() } -> std::same_as<size_t>;
    { e.data() } -> std::convertible_to<uint8_t*>;
    // emulate fp instruction (BPF_FP_*) in JIT (x86 SSE/FP) natively, or fall
    // back to helper_do_softfp (e.g. x86 unsigned fp<->int conversion lacks AVX-512).
    { e.emit_call_softfp(insn) } -> std::same_as<bool>;
    e.emit_call_softfp_slow(insn, idx, gpa);

    // Patching
    e.patch_branch_cond(0u, 0u);
    e.patch_branch_uncond(0u, 0u);
    e.patch_branch_abort(0u, 0u);
};

// ---------------------------------------------------------------------------
// JitCompiler<EmitterT> — architecture-independent compilation logic
// ---------------------------------------------------------------------------

template<typename EmitterT>
class JitCompiler : public JitCompilerBase {
    static_assert(JitEmitter<EmitterT>, "EmitterT must satisfy JitEmitter concept");
public:
    JitCompiler();
    ~JitCompiler();

    // Compile or find a JIT function starting at pc.
    // Returns nullptr if the instruction cannot be JIT-compiled.
    JitEntry* compile(vm* v, uint64_t gpa) override;
    // execve 后失效所有旧 JIT 缓存。注意：与原实现一致，这里只丢弃映射、不 munmap
    // code 页——execve 的 syscall 仍在某段 JIT 代码的调用链中（helper_do_syscall
    // 返回后 JIT .cont 续段还要跑 flag check），此刻 munmap 正在执行的 code 页会
    // segfault。code 页随 JitCompiler 析构（VM 销毁）时统一释放。
    void clear() override {
        entries_.clear();
        std::memset(pc_cache_, 0, sizeof(pc_cache_));
        std::memset(hot_counters_, 0, sizeof(hot_counters_));
    }
    // callee 已编译则返回其 entry_fast 入口，否则 nullptr。
    void* resolve_call(vm* v, uint64_t callee_gpa) override;

private:
    // VM field offsets
    static const size_t off_reg_;
    static const size_t off_pc_;
    static const size_t off_flags_;
    static const size_t off_tlb_;
    static const size_t off_insn_count_;
    static const size_t off_insn_limit_;
    static const size_t off_stack_limit_;
    static const size_t off_scratch_;

    // 已编译/已失败入口的登记表。热点计数不在此表（见 hot_counters_）：被探测
    // pc 是十万量级（python 启动 ~17 万），JitEntry ~120B/条放表里内存与 rehash
    // 代价都不可接受，故 entries_ 只登记过阈值的 pc（规模 ~编译片段数）。
    std::unordered_map<uint64_t, JitEntry> entries_;
    // step() 每条解释指令都探测 compile()：已编译/已失败的入口经此按 pc 直接映射的
    // 影子缓存命中，免哈希查找。解释执行的指令大多落在 JIT 编译失败的代码里（Failed
    // 永久缓存），这类每步一次的哈希查找是纯开销；Counting 态不缓存（计数语义保留）。
    // 槽冲突/未填时回退哈希路径。entries_ 为 node-based，指针跨 rehash 稳定。
    struct PcCacheSlot {
        uint64_t gpa;   // 0 = 未填
        JitEntry* e;    // &failed_sentinel_ 表示 Failed（compile 返回 nullptr）
    };
    static constexpr size_t kPcCacheSlots = 1u << 16;
    PcCacheSlot pc_cache_[kPcCacheSlots] = {};
    // 热点计数表（Counting 态）：开放寻址、基址起 8 槽窗口；窗口满则淘汰计数最小者
    // （被淘汰 pc 的计数进度丢失，真热的会重新数上来）。计数达阈值提升进 entries_
    // 走编译路径并清槽。gpa==0 表示空槽（gpa 0 不是合法 pc）。
    struct HotCounter {
        uint64_t gpa;
        uint32_t count;
    };
    static constexpr size_t kHotCounterSlots = 1u << 18;
    static constexpr unsigned kHotCounterProbe = 8;
    HotCounter hot_counters_[kHotCounterSlots] = {};
    JitEntry failed_sentinel_;

    // --- 编译工作区：仅 emitter 缓冲跨编译复用——每片段 ~10 轮倍增扩容的
    //     拷贝是工作区开销大头，其余向量的分配额可忽略。compile() 无重入 ---
    EmitterT work_emitter_;

    // --- RX code arena：每片段 bump 分配 + 整块 mprotect RX，替代逐片段
    //     mmap/mprotect（消 mmap 系统调用与首次触碰缺页）。片段起始恒页对齐，
    //     下一片段从 used+aligned 续（页对齐保证 mprotect 不波及邻片）。
    //     clear() 不回收：execve 后旧 code 页可能仍在某段 JIT 代码的调用链中
    //     执行，回收即踩正在执行的页；arena 随析构统一释放。 ---
    struct CodeArena {
        uint8_t* base;
        size_t size;
        size_t used;
    };
    std::vector<CodeArena> arenas_;
    static constexpr size_t kCodeArenaSize = 2u << 20;
    bool enabled_ = true;
    bool debug_enabled_ = false;
    bool jit_dump_enabled_ = false;
    // 热点检测阈值：每个 pc 的 compile() 调用计数达到阈值才编译。
    uint32_t threshold_ = 100;
    // helper 函数指针表
    HelperTable helpers_;

    // JIT runtime helpers — called from JIT-generated code via function pointer.
    static int helper_safepoint(vm* v);
    static bool helper_push_frame(vm* v, uint64_t ret_addr);
    static uint64_t helper_pop_frame(vm* v);
    static bool helper_do_syscall(vm* v, uint32_t call_id);
    static bool helper_do_softfp(vm* v, uint32_t call_id);
    static void helper_call_indirect(vm* v, uint64_t ret_gpa, uint64_t target);
    // 间接调用慢路径 + 单型 IC 填槽（目标已编译时）
    static void helper_call_indirect_ic(vm* v, uint64_t ret_gpa, uint64_t target,
                                        IndirectICSlot* slot);
    static void helper_call_bpf(vm* v, uint64_t ret_gpa, uint64_t callee_gpa);
    static int helper_return_to_caller(vm* v, uint64_t ret_gpa);
    // inline cache miss 慢路径：查 callee；命中则 *slot=target 返回 target，
    //   未编译则 v->pc_=callee_gpa 返回 nullptr。
    static void* helper_resolve_and_cache(vm* v, uint64_t callee_gpa, uint64_t* slot);
    static void* helper_mmu(vm* v, uint64_t addr, uint64_t size);
    static void* helper_mmu_w(vm* v, uint64_t addr, uint64_t size);

    // Pre-scan: discover all reachable BPF instructions via BFS（结果写入复用向量）。
    void discover_reachable(const bpf_insn* start, int seg_limit,
                            std::vector<bool>& reachable,
                            std::vector<bool>& back_edge_targets,
                            std::vector<uint32_t>& loop_body_sizes,
                            int& func_size);

    // Emit a single BPF instruction. Returns false if cannot be compiled.
    bool emit_instruction(EmitterT& e, const bpf_insn* entry_pc, uint64_t entry_gpa, int i,
                          int num_insns,
                          std::vector<JumpPlaceholder>& placeholders,
                          std::vector<AbortPatchInfo>& abort_patches,
                          std::vector<size_t>& call_cache_offs,
                          std::vector<size_t>& ic_cache_offs,
                          int& compiled_count, vm* v);

    // Allocate executable memory (W^X), return pointer or nullptr.
    void* finalize_code(EmitterT& e);
};

#endif // JIT_COMPILER_H
