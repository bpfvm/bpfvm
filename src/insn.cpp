//
// Created by chouryzhou on 24-10-28.
//

#include "insn.h"
#include "include/bpf_call.h"   // BPF_CALL_TO_ID / BPF_FP_*（do_syscall 拦截 FP 段）
#include <iostream>

#include "jit/jit.h"
#include "include/auxv.h"
#include <cstring>
#include <cmath>

#if defined(__x86_64__)
#include "jit/jit_compiler.h"
#include "jit/x86_emitter.h"
using JitCompilerImpl = JitCompiler<X86Emitter>;
#elif defined(__aarch64__)
#include "jit/jit_compiler.h"
#include "jit/aarch64_emitter.h"
using JitCompilerImpl = JitCompiler<AArch64Emitter>;
#else
class StubJitCompiler : public JitCompilerBase {
public:
    JitFunction* compile(vm*, const bpf_insn*) override { return nullptr; }
};
using JitCompilerImpl = StubJitCompiler;
#endif

#include <libelf.h>
#include <gelf.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <mutex>
#include <time.h>


std::mutex log_mutex;



void dump(uint64_t addr, const bpf_insn* insn) {
    static const char* aluop[] = {
        "add", "sub", "mul", "div", "or", "and", "lsh",
        "rsh", "neg", "mod", "xor", "mov", "arsh", "end"
    };
    static const char* jmpop[] = {
        "ja", "jeq", "jgt", "jge", "jset", "jne", "jsgt",
        "jsge", "call", "exit", "jlt", "jle", "jslt", "jsle"
    };
    static const char* lsize[] = {
        "w", "h", "b", "dw"
    };
    printf("%" PRIx64 ": 0x%02x %d %d %d 0x%x: ", addr, insn->code, insn->dst_reg, insn->src_reg, insn->off, insn->imm);
    switch(insn->code & 0x07) {
    case BPF_ALU: case BPF_ALU64: {
        printf("%s ", aluop[(insn->code & 0xf0) >> 4]);
        printf("r%d ", insn->dst_reg);
        if ((insn->code & 0xf0) == BPF_END) { // Specific formatting for BPF_END
            if ((insn->code & 0x08) == BPF_X) { // BPF_TO_BE (corresponds to BPF_X value 0x08)
                printf("be, %d\n", insn->imm); // imm is width
            } else { // BPF_TO_LE (corresponds to BPF_K value 0x00)
                printf("le, %d\n", insn->imm); // imm is width
            }
        } else { // Formatting for other ALU operations
            if((insn->code & 0x08) == BPF_X) { // Source is register
                printf("r%d\n", insn->src_reg);
            } else { // Source is immediate
                printf("%d\n", insn->imm);
            }
        }
        break;
    }
    case BPF_JMP: case BPF_JMP32: {
        printf("%s ", jmpop[(insn->code & 0xf0) >> 4]);
        if((insn->code & 0xf0) == BPF_EXIT){
            printf("\n");
        }else if((insn->code & 0xf0) == BPF_JA){
            if((insn->code & 0x07) == BPF_JMP32){
                printf("%d\n", insn->imm);
            }else{
                printf("%d\n", insn->off);
            }
        }else if((insn->code & 0xf0) == BPF_CALL){
            if(insn->code & 0x08)
                printf("r%d\n", insn->dst_reg);
            else if(insn->src_reg == 0) {
                printf("sys 0x%X\n", insn->imm);
            }else if(insn->src_reg == 1) {
                printf("%d\n", insn->imm);
            }else if(insn->src_reg == 2) {
                printf("fp 0x%X\n", insn->imm);
            }else {
                printf("!unknown!\n");
            }
        }else if((insn->code & 0x08) == BPF_X) {
            printf("r%d r%d %d\n", insn->dst_reg, insn->src_reg, insn->off);
        } else {
            printf("r%d %d %d\n", insn->dst_reg, insn->imm, insn->off);
        }
        break;
    }
    case BPF_LD: {
        printf("ld%s ", lsize[(insn->code & 0x18) >> 3]);
        if((insn->code & 0xe0) != BPF_IMM) {
            fprintf(stderr, "Invalid mode for ld\n");
            return;
        }
        printf("r%d 0x%lx\n", insn->dst_reg, (uint64_t)(insn+1)->imm << 32 | (uint32_t)insn->imm);
        break;
    }
    case BPF_LDX: {
        printf("ldx%s ", lsize[(insn->code & 0x18) >> 3]);
        if((insn->code & 0xe0) != BPF_MEM && (insn->code & 0xe0) != BPF_MEMSX) {
            fprintf(stderr, "Invalid mode for ldx\n");
            return;
        }
        printf("r%d ", insn->dst_reg);
        if(insn->off == 0) {
            printf("[r%d]\n", insn->src_reg);
        } else if(insn->off > 0){
            printf("[r%d+%d]\n", insn->src_reg, insn->off);
        } else {
            printf("[r%d%d]\n", insn->src_reg, insn->off);
        }
        break;
    }
    case BPF_ST: {
        printf("st%s ", lsize[(insn->code & 0x18) >> 3]);
        if((insn->code & 0xe0) != BPF_MEM) {
            fprintf(stderr, "Invalid mode for st\n");
            return;
        }
        if(insn->off == 0) {
            printf("[r%d] ", insn->dst_reg);
        }else if(insn->off > 0) {
            printf("[r%d+%d] ", insn->dst_reg, insn->off);
        } else {
            printf("[r%d%d] ", insn->dst_reg, insn->off);
        }
        printf("%d\n", insn->imm);
        break;
    }
    case BPF_STX: {
        if((insn->code & 0xe0) == BPF_ATOMIC) {
            static const char* atomicop[] = {
                "add", "or", "and", "xor",
            };
            const char* size = (insn->code & 0x18) == BPF_DW ? "64" : "32";
            int32_t op = insn->imm;
            if(insn->off == 0) {
                printf("lock%s [r%d] ", size, insn->dst_reg);
            } else if(insn->off > 0) {
                printf("lock%s [r%d+%d] ", size, insn->dst_reg, insn->off);
            } else {
                printf("lock%s [r%d%d] ", size, insn->dst_reg, insn->off);
            }
            int base_op = op & ~BPF_FETCH;
            if(base_op == (BPF_XCHG & ~BPF_FETCH)) {
                printf("xchg r%d\n", insn->src_reg);
            } else if(base_op == (BPF_CMPXCHG & ~BPF_FETCH)) {
                printf("cmpxchg r%d\n", insn->src_reg);
            } else if(base_op == BPF_ADD || base_op == BPF_OR ||
                      base_op == BPF_AND || base_op == BPF_XOR) {
                int idx = base_op == BPF_ADD ? 0 : base_op == BPF_OR ? 1 :
                          base_op == BPF_AND ? 2 : 3;
                if(op & BPF_FETCH) {
                    printf("fetch_%s r%d\n", atomicop[idx], insn->src_reg);
                } else {
                    printf("%s r%d\n", atomicop[idx], insn->src_reg);
                }
            } else {
                printf("unknown(0x%x) r%d\n", op, insn->src_reg);
            }
            break;
        }
        printf("stx%s ", lsize[(insn->code & 0x18) >> 3]);
        if((insn->code & 0xe0) != BPF_MEM) {
            fprintf(stderr, "Invalid mode for stx\n");
            return;
        }
        if(insn->off == 0) {
            printf("[r%d] ", insn->dst_reg);
        }else if(insn->off > 0) {
            printf("[r%d+%d] ", insn->dst_reg, insn->off);
        } else {
            printf("[r%d%d] ", insn->dst_reg, insn->off);
        }
        printf("r%d\n", insn->src_reg);
        break;
    }
    default:
        break;
    }
}

vm::vm(Token) {
    pthread_mutex_init(&wait_mutex, nullptr);
    pthread_cond_init(&wait_cv, nullptr);
    memset(reg, 0, sizeof(reg));
}

vm::~vm() {
    pthread_cond_destroy(&wait_cv);
    pthread_mutex_destroy(&wait_mutex);
}

std::shared_ptr<vm> vm::create() {
    return std::make_shared<vm>(Token{});
}

ElfLoadInfo vm::load_elf(const char* elf_file_path) {
    return ::load_elf(elf_file_path, [this](memmap&& m) { addmem(std::move(m)); });
}

/*
 * Stack Frame Layout:
 *
 * frame_base[0] 编码（见 insn.h 的 FRAME_FLAG_* / frame_*）：
 *   bit  0..31 : 本函数栈帧总长度 = stack_limit + alloca_len
 *   bit     32 : is_signal（1=信号帧 / 0=普通帧）；其余保留。
 *
 * Normal Frame (64 bytes):
 * +------------------+
 * | flags+total_len  | frame_base[0]
 * +------------------+
 * | r6               | frame_base[1]
 * | r7               | frame_base[2]
 * | r8               | frame_base[3]
 * | r9               | frame_base[4]
 * +------------------+
 * | old_r10 (SP)     | frame_base[5]
 * +------------------+
 * | return_address   | frame_base[6]
 * +------------------+
 * | unused           | frame_base[7]
 * +------------------+
 *
 * Signal Frame (128 bytes):
 * +------------------+
 * | flags+total_len  | frame_base[0]
 * +------------------+
 * | r0               | frame_base[1]
 * | r1               | frame_base[2]
 * | r2               | frame_base[3]
 * | r3               | frame_base[4]
 * | r4               | frame_base[5]
 * | r5               | frame_base[6]
 * | r6               | frame_base[7]
 * | r7               | frame_base[8]
 * | r8               | frame_base[9]
 * | r9               | frame_base[10]
 * +------------------+
 * | old_r10 (SP)     | frame_base[11]
 * +------------------+
 * | return_address   | frame_base[12]
 * +------------------+
 * | unused (3 slots) | frame_base[13..15]
 * +------------------+
 */
bool vm::push_frame(uint64_t return_addr, bool is_signal) {
    uint32_t frame_size = is_signal ? 128 : 64;
    // 调用者（被中断函数）栈帧的总长度 = stack_limit + alloca_len，读"当前 r10
    //   处那个帧"frame_base[0] 的低 32 位。调用者的局部变量区是
    //   [r10 - stack_limit, r10]，alloca 区在其下 [r10 - total_len, r10 - stack_limit]。
    uint64_t* cur_frame = (uint64_t*)mmu(r(10), sizeof(uint64_t));
    uint64_t caller_total_len = cur_frame ? frame_total_len(cur_frame[0]) : 0;
    if(r(10) - caller_total_len - frame_size < STACK_BASE) {
        log_mem_violation("stack overflow", r(10));
        return false;
    }
    if(options.verbose) {
        std::lock_guard<std::mutex> lock(log_mutex);
        printf("[#%d] [STACK] PUSH sp=%lx ret=%lx sig=%d size=%d caller_len=%lu\n",
            options.sys->id(), r(10), return_addr, is_signal, frame_size, caller_total_len);
    }
    uint64_t sp = r(10) - caller_total_len;
    uint64_t frame_base_addr = sp - frame_size;
    // 检查整段新帧 [frame_base_addr, sp)
    uint64_t* frame_base = (uint64_t*)mmu_w(frame_base_addr, sp - frame_base_addr);
    if(!frame_base) {
        log_mem_violation("stack access", frame_base_addr);
        return false;
    }

    // flags + total_len(=stack_limit)：新函数的局部变量区，尚未 alloca。
    frame_base[0] = frame_flags_make(is_signal, options.stack_limit);
    if (is_signal) {
        signal_depth++;
        frame_base[1] = r(0);
        frame_base[2] = r(1);
        frame_base[3] = r(2);
        frame_base[4] = r(3);
        frame_base[5] = r(4);
        frame_base[6] = r(5);
        frame_base[7] = r(6);
        frame_base[8] = r(7);
        frame_base[9] = r(8);
        frame_base[10] = r(9);
        frame_base[11] = r(10);
        frame_base[12] = return_addr;
    } else {
        frame_base[1] = r(6);
        frame_base[2] = r(7);
        frame_base[3] = r(8);
        frame_base[4] = r(9);
        frame_base[5] = r(10);
        frame_base[6] = return_addr;
    }

    r(10) = frame_base_addr;
    return true;
}

uint64_t vm::pop_frame() {
    uint64_t sp = r(10);
    uint64_t* frame_base = (uint64_t*)mmu(sp);
    if(!frame_base) return 0;

    uint64_t old_sp;
    uint64_t ret_addr;
    bool is_signal = frame_is_signal(frame_base[0]);
    if (is_signal) {
        signal_depth--;
        r(0) = frame_base[1];
        r(1) = frame_base[2];
        r(2) = frame_base[3];
        r(3) = frame_base[4];
        r(4) = frame_base[5];
        r(5) = frame_base[6];
        r(6) = frame_base[7];
        r(7) = frame_base[8];
        r(8) = frame_base[9];
        r(9) = frame_base[10];
        old_sp = frame_base[11];
        ret_addr = frame_base[12];
    } else {
        r(6) = frame_base[1];
        r(7) = frame_base[2];
        r(8) = frame_base[3];
        r(9) = frame_base[4];
        old_sp = frame_base[5];
        ret_addr = frame_base[6];
    }

    if(options.verbose) {
        std::lock_guard<std::mutex> lock(log_mutex);
        printf("[#%d] [STACK] POP sp=%lx new_sp=%lx ret=%lx sig=%d\n",
            options.sys->id(), sp, old_sp, ret_addr, is_signal);
    }
    r(10) = old_sp;
    return ret_addr;
}


// alloca(inc) — 当前栈帧 alloca 区的增量调整
// 栈布局（每个函数从其 r10 向下）：
//     [r10 - stack_limit, r10)                              编译器分配的局部变量区
//     [r10 - total_len, r10 - stack_limit)                  本函数已 alloca 的区
//     ...                                                   本函数帧头 / 调用者
//
// 三种用法
//   inc > 0：扩展 inc 字节。新块 = [新下界, 新下界 + inc) = [r10 - new_total,
//            r10 - new_total + inc)，紧贴上一块 alloca 下方，块间不重叠。
//            返回新下界正是新块起始地址（C alloca 语义：buf[0] 在 ret，
//            buf[i] 在 ret+i*sizeof(T)）。
//   inc = 0：只读，返回当前下界
//   inc < 0：收缩 -inc 字节，返回新下界（高于旧下界，往高地址截回）
//
// 注意：栈往低地址生长，所以 inc 的符号是 "alloca_len 增量"，不是 "下界地址增量"
// （符合 C alloca(n) 中 n > 0 即分配的直觉）。
int64_t vm::alloca(int64_t inc) {
    uint64_t stack_limit = options.stack_limit;

    // 当前 r10 处的帧头：读 frame_base[0]，更新其低 32 位的 total_len。
    uint64_t* frame = (uint64_t*)mmu_w(r(10), sizeof(uint64_t));
    if(!frame) return -EFAULT;
    uint64_t flags0 = frame[0];
    uint64_t cur_total = frame_total_len(flags0);

    // 防御：若 frame[0] 损坏 / 旧 ABI 残留（total_len < stack_limit）—— 拒绝。
    if(cur_total < stack_limit) return -EFAULT;
    int64_t cur_alloca = (int64_t)(cur_total - stack_limit);

    // 带符号累加；负到越过 0 视为错误（不能缩进局部变量区）。
    int64_t new_alloca = cur_alloca + inc;
    if(new_alloca < 0) return -EINVAL;
    uint64_t new_total = stack_limit + (uint64_t)new_alloca;

    // 32 位长度编码上限 + 栈区下界不得低于 STACK_BASE。
    if(new_total > FRAME_LEN_MASK || r(10) < STACK_BASE + new_total)
        return -ENOMEM;

    // 扩展时（inc>0）保证新 alloca 区 [r10-new_total, r10) 整段在同一可写映射里
    if(inc > 0 && !mmu_w(r(10) - new_total, new_total))
        return -ENOMEM;

    // 保留 is_signal 等高位，仅替换低 32 位的 total_len。
    frame[0] = (flags0 & ~FRAME_LEN_MASK) | (new_total & FRAME_LEN_MASK);

    // 返回新下界（= inc>0 时新块起始地址；= inc=0 时当前下界作 stacksave token）。
    return (int64_t)(r(10) - new_total);
}


// ---------------------------------------------------------------------------
// 虚拟浮点指令的解释器实现
// r1/r2 是操作数位模式，用宿主硬件浮点算出结果，位模式写回 r0。
// 解释器经 src_reg=2 的 dispatch 直达此处；JIT 无原生 lowering 时（如 x86 的
// uint 转换）经 emit_call_softfp_slow 回退到此处（helper_do_softfp）。
// call 即 imm 字段，本身就是 bpf_fp_op 枚举值（1..N，无 BASE 偏移），直接 switch。
// ---------------------------------------------------------------------------
bool vm::do_softfp(uint32_t call) {
    const uint32_t op = call;   // FP 编号空间独立，imm 即 enum 值，无需 BPF_CALL_TO_ID

    // 取出两个 i64 操作数（比较/算术用 r1,r2；一元只用 r1）。
    // 题外：glue 函数中所有位转换（double<->i64）已被 clang 优化为寄存器直传，
    // 因此 r1/r2 直接就是操作数的 IEEE754 bit pattern。
    const uint64_t a_bits = r(1);
    const uint64_t b_bits = r(2);

    auto d_in = [](uint64_t u) {
        double d;
        memcpy(&d, &u, sizeof(d));
        return d;
    };
    auto f_in = [](uint64_t u) {
        float f;
        uint32_t b = (uint32_t)u;
        memcpy(&f, &b, sizeof(f));
        return f;
    };
    auto d_out = [](double d) -> uint64_t {
        uint64_t u;
        memcpy(&u, &d, sizeof(u));
        return u;
    };
    auto f_out = [](float f) -> uint32_t {
        uint32_t u;
        memcpy(&u, &f, sizeof(u));
        return u;
    };

    switch (op) {
    // double 二元算术
    case BPF_FP_ADD_D: r(0) = d_out(d_in(a_bits) + d_in(b_bits)); return true;
    case BPF_FP_SUB_D: r(0) = d_out(d_in(a_bits) - d_in(b_bits)); return true;
    case BPF_FP_MUL_D: r(0) = d_out(d_in(a_bits) * d_in(b_bits)); return true;
    case BPF_FP_DIV_D: r(0) = d_out(d_in(a_bits) / d_in(b_bits)); return true;
    // float 二元算术
    case BPF_FP_ADD_F: r(0) = (uint64_t)f_out(f_in(a_bits) + f_in(b_bits)); return true;
    case BPF_FP_SUB_F: r(0) = (uint64_t)f_out(f_in(a_bits) - f_in(b_bits)); return true;
    case BPF_FP_MUL_F: r(0) = (uint64_t)f_out(f_in(a_bits) * f_in(b_bits)); return true;
    case BPF_FP_DIV_F: r(0) = (uint64_t)f_out(f_in(a_bits) / f_in(b_bits)); return true;
    // 一元
    case BPF_FP_NEG_D: r(0) = d_out(-d_in(a_bits)); return true;
    case BPF_FP_NEG_F: r(0) = (uint64_t)f_out(-f_in(a_bits)); return true;
    case BPF_FP_SQRT_D: r(0) = d_out(__builtin_sqrt(d_in(a_bits))); return true;
    case BPF_FP_SQRT_F: r(0) = (uint64_t)f_out(__builtin_sqrtf(f_in(a_bits))); return true;
    // double -> int（截断向 0）
    case BPF_FP_D2SI:  r(0) = (uint64_t)(int64_t)(int32_t)d_in(a_bits); return true;
    case BPF_FP_D2DI:  r(0) = (uint64_t)(int64_t)d_in(a_bits); return true;
    case BPF_FP_D2USI: r(0) = (uint64_t)(uint64_t)(uint32_t)d_in(a_bits); return true;
    case BPF_FP_D2UDI: r(0) = (uint64_t)(uint64_t)d_in(a_bits); return true;
    // float -> int
    case BPF_FP_F2SI:  r(0) = (uint64_t)(int64_t)(int32_t)f_in(a_bits); return true;
    case BPF_FP_F2DI:  r(0) = (uint64_t)(int64_t)f_in(a_bits); return true;
    case BPF_FP_F2USI: r(0) = (uint64_t)(uint64_t)(uint32_t)f_in(a_bits); return true;
    case BPF_FP_F2UDI: r(0) = (uint64_t)(uint64_t)f_in(a_bits); return true;
    // int -> double
    case BPF_FP_SI2D:  r(0) = d_out((double)(int64_t)(int32_t)a_bits); return true;
    case BPF_FP_DI2D:  r(0) = d_out((double)(int64_t)a_bits); return true;
    case BPF_FP_USI2D: r(0) = d_out((double)(uint64_t)(uint32_t)a_bits); return true;
    case BPF_FP_UDI2D: r(0) = d_out((double)(uint64_t)a_bits); return true;
    // int -> float
    case BPF_FP_SI2F:  r(0) = (uint64_t)f_out((float)(int64_t)(int32_t)a_bits); return true;
    case BPF_FP_DI2F:  r(0) = (uint64_t)f_out((float)(int64_t)a_bits); return true;
    case BPF_FP_USI2F: r(0) = (uint64_t)f_out((float)(uint64_t)(uint32_t)a_bits); return true;
    case BPF_FP_UDI2F: r(0) = (uint64_t)f_out((float)(uint64_t)a_bits); return true;
    // 类型转换
    case BPF_FP_EXTEND: r(0) = d_out((double)f_in(a_bits)); return true;
    case BPF_FP_TRUNC:  r(0) = (uint64_t)f_out((float)d_in(a_bits)); return true;
    // 比较：返回 -1/0/1（GCC 软浮点 ABI）。glue 侧的 __eq/__ne/__lt/...
    // 都映射到同一个 CMP helper；对于 == 和 != 的 unordered 处理由调用点
    // 的谓词决定（<0/=0/>0），这里统一返回有序比较的三态结果。
    case BPF_FP_CMP_D: {
        double a = d_in(a_bits), b = d_in(b_bits);
        r(0) = (a < b) ? (uint64_t)-1 : (a > b) ? 1ULL : 0ULL;
        return true;
    }
    case BPF_FP_CMP_F: {
        float a = f_in(a_bits), b = f_in(b_bits);
        r(0) = (a < b) ? (uint64_t)-1 : (a > b) ? 1ULL : 0ULL;
        return true;
    }
    // 无序判定：任一操作数为 NaN 返回 1，否则 0（__unordXX2 语义）。
    // 利用 IEEE754 不等性（NaN != NaN）判定，不依赖 <cmath>。
    case BPF_FP_UNORD_D: {
        double a = d_in(a_bits), b = d_in(b_bits);
        r(0) = (a != a || b != b) ? 1ULL : 0ULL;
        return true;
    }
    case BPF_FP_UNORD_F: {
        float a = f_in(a_bits), b = f_in(b_bits);
        r(0) = (a != a || b != b) ? 1ULL : 0ULL;
        return true;
    }
    // fabs/copysign：musl 实现体是一条位运算，会被 instcombine 折叠回同名 intrinsic，
    case BPF_FP_FABS_D: r(0) = d_out(std::fabs(d_in(a_bits))); return true;
    case BPF_FP_FABS_F: r(0) = (uint64_t)f_out(std::fabs(f_in(a_bits))); return true;
    case BPF_FP_COPYSIGN_D: r(0) = d_out(std::copysign(d_in(a_bits), d_in(b_bits))); return true;
    case BPF_FP_COPYSIGN_F: r(0) = (uint64_t)f_out(std::copysign(f_in(a_bits), f_in(b_bits))); return true;
    case BPF_FP_EMUTLS_GET_ADDR: {
        // emutls：r1 = __emutls_control*（guest 地址，指向 __emutls_v.<name>）。
        // 控制块布局：{ i64 size, i64 align, i64 index, ptr value }
        //   - index==0：尚未分配下标，全局原子分配一个递增正数（>=1）。
        //   - value==0：零初始化；非 0：指向初始化模板（guest 地址）。
        // 返回该线程该变量的副本地址（guest 地址），写入 r0。
        //
        // 副本内存：host mmap 一块 + 构造 memmap 登记到 guest 地址空间（尾部分配），
        // 这样 guest 后续的 load/store 经 mmu 能命中。每个 TLS 变量独立一块，
        // 简单但每块占一页；后续可优化为 slab/arena。
        struct emutls_control { uint64_t size, align, index, value; };
        // 控制块位于 .data（PF_W），fork 后变成 CoW 段。读字段（size/align/value）
        // 用 mmu 只读路径即可；但写 ctrl->index 必须经 mmu_w，否则会写共享页、
        // 破坏 CoW 语义（fork 后父子进程的 index 应各自独立 CoW）。所以这里拆成
        // 只读视图 + 可写视图两次翻译。
        const auto* ctrl_ro = reinterpret_cast<const emutls_control*>(
            mmu(a_bits, sizeof(emutls_control)));
        if (!ctrl_ro) { r(0) = 0; return true; }
        auto* ctrl = reinterpret_cast<emutls_control*>(
            mmu_w(a_bits, sizeof(emutls_control)));
        if (!ctrl) { r(0) = 0; return true; }

        // 懒分配 index（全局递增，>=1）。多线程同时首次访问同一变量时可能多消耗
        // 几个 id（每线程各 fetch_add 一次），但每 vm 独立 slot，隔离仍成立。
        if (ctrl->index == 0) {
            static std::atomic<uint64_t> g_next{1};
            ctrl->index = g_next.fetch_add(1);
        }
        size_t idx = ctrl->index;
        const uint64_t size = ctrl_ro->size;
        const uint64_t value = ctrl_ro->value;
        if (emutls_slots_.size() < idx) emutls_slots_.resize(idx, 0);
        if (emutls_slots_[idx - 1] != 0) {
            r(0) = emutls_slots_[idx - 1];   // 已分配
            return true;
        }

        // 首次访问：分配副本内存。
        const size_t PAGE = 4096;
        size_t sz = size;
        size_t alloc_sz = (sz + PAGE - 1) & ~(PAGE - 1);  // 至少一页
        unsigned char* host = (unsigned char*)mmap(nullptr, alloc_sz,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (host == MAP_FAILED) { r(0) = 0; return true; }

        // 初始化：零初始化（value==0）→ mmap 本身清零；否则从模板拷贝。
        if (value != 0) {
            if (const void* tmpl = mmu(value, sz))
                memcpy(host, tmpl, sz);
        }

        // 登记到 guest 地址空间：尾部分配一个 guest 地址。
        memmap m;
        m.set_data(host, alloc_sz);
        m.size = alloc_sz;
        m.flags = PF_R | PF_W;
        uint64_t guest_addr = 0;
        {
            auto& ml = *maps;
            std::lock_guard<std::mutex> lock(*maps_mutex);
            uint64_t next = 0;
            if (!ml.empty()) next = ml.back().paddr + ml.back().size;
            next = (next + PAGE - 1) & ~(PAGE - 1);
            if (next == 0) next = 0x70000000ULL;  // 兜底起始地址，避开栈/堆/ELF
            m.paddr = next;
            guest_addr = next;
            ml.push_back(std::move(m));
        }
        flush_tlb();
        emutls_slots_[idx - 1] = guest_addr;
        r(0) = guest_addr;
        return true;
    }
    default:
        r(0) = -ENOSYS;
        return true;
    }
}

bool vm::jmp(const bpf_insn* cur) {
    uint64_t src = (cur->code & 0x08) == BPF_X ? r(cur->src_reg) : cur->imm;
    switch (cur->code & 0xf0) {
    case BPF_JA:
        pc += (int64_t)cur->off * sizeof(bpf_insn);
        break;
    case BPF_JEQ:
        if (r(cur->dst_reg) == src) { 
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JGT:
        if (r(cur->dst_reg) > src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JGE:
        if (r(cur->dst_reg) >= src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSET:
        if (r(cur->dst_reg) & src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JNE:
        if (r(cur->dst_reg) != src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSGT:
        if ((int64_t)r(cur->dst_reg) > (int64_t)src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSGE:
        if ((int64_t)r(cur->dst_reg) >= (int64_t)src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_CALL:
        if((cur->code & 0x08) == BPF_X) {
            if(!push_frame(pc + sizeof(bpf_insn))) {
                return false;
            }
            pc = r(cur->dst_reg) - sizeof(bpf_insn);
        }else if(cur->src_reg == 0) {
            return do_syscall(cur->imm);
        }else if(cur->src_reg == 1) {
            if(!push_frame(pc + sizeof(bpf_insn))) {
                return false;
            }
            pc += (int64_t)cur->imm * sizeof(bpf_insn);
        }else if(cur->src_reg == 2) {
            return do_softfp(cur->imm);
        }
        break;
    case BPF_EXIT:
    {
        uint64_t ret = pop_frame();
        if(ret == 0) {
            //到栈底了
            return false;
        }
        pc = ret - sizeof(bpf_insn);  // run() 循环的 pc+=sizeof(bpf_insn) 会落到 ret
        break;
    }
    case BPF_JLT:
        if (r(cur->dst_reg) < src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JLE:
        if (r(cur->dst_reg) <= src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSLT:
        if ((int64_t)r(cur->dst_reg) < (int64_t)src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSLE:
        if ((int64_t)r(cur->dst_reg) <= (int64_t)src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    }
    return true;
}

bool vm::jmp32(const bpf_insn* cur) {
    uint32_t src = (cur->code & 0x08) == BPF_X ? (uint32_t)r(cur->src_reg) : cur->imm;
    auto dst = (uint32_t)r(cur->dst_reg);
    switch (cur->code & 0xf0) {
    case BPF_JA:
        pc += (int64_t)cur->imm * sizeof(bpf_insn);
        break;
    case BPF_JEQ:
        if (dst == src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JGT:
        if (dst > src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JGE:
        if (dst >= src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSET:
        if (dst & src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JNE:
        if (dst != src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSGT:
        if ((int32_t)dst > (int32_t)src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSGE:
        if ((int32_t)dst >= (int32_t)src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_CALL:
    case BPF_EXIT:
        return false;
    case BPF_JLT:
        if (dst < src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JLE:
        if (dst <= src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSLT:
        if ((int32_t)dst < (int32_t)src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSLE:
        if ((int32_t)dst <= (int32_t)src) {
            pc += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    }
    return true;
}


void vm::log_mem_violation(const char* type, uint64_t addr) {
    std::cerr << "Memory access violation at PC 0x" << std::hex << pc
              << ": invalid " << type << " at address 0x" << addr << std::dec << std::endl;

    // 寄存器转储
    std::cerr << "Registers:" << std::hex;
    for (int i = 0; i < 11; i++) {
        if (i % 4 == 0) std::cerr << "\n  ";
        std::cerr << "r" << std::dec << i << "=0x" << std::hex << reg[i] << "  " << std::dec;
    }
    std::cerr << std::endl;

    // 调用栈回溯：沿 frame 链向上遍历
    // 正常帧: flags+alloca_len[0] r6..r9[1..4] old_r10[5] ret_addr[6]
    // 信号帧: flags+alloca_len[0] r0..r9[1..10] old_r10[11] ret_addr[12]
    std::cerr << "Call stack:" << std::hex;
    uint64_t cur_sp = r(10);
    uint64_t cur_pc = pc;
    int depth = 0;
    constexpr int MAX_FRAMES = 64;
    while (cur_sp != 0 && depth < MAX_FRAMES) {
        std::cerr << "\n  #" << std::dec << depth << " pc=0x" << std::hex << cur_pc
                  << " sp=0x" << cur_sp << std::dec;
        uint64_t* frame_base = (uint64_t*)mmu(cur_sp, sizeof(uint64_t) * 16);
        if (!frame_base) {
            std::cerr << " (frame unreadable at 0x" << std::hex << cur_sp << ")" << std::dec;
            break;
        }
        bool is_signal = frame_is_signal(frame_base[0]);
        uint64_t old_sp   = is_signal ? frame_base[11] : frame_base[5];
        uint64_t ret_addr = is_signal ? frame_base[12] : frame_base[6];
        std::cerr << (is_signal ? " [signal]" : "");
        if (old_sp == 0 || old_sp <= cur_sp || ret_addr == 0) {
            // 到达栈底
            break;
        }
        cur_sp = old_sp;
        cur_pc = ret_addr;
        depth++;
    }
    std::cerr << std::dec << std::endl;

    std::cerr << "Current memory maps:" << std::endl;
    for(const auto& map : *maps) {
        // 权限符号化（PF_R=0x4, PF_W=0x2, PF_X=0x1），形如 /proc/<pid>/maps 的 rwx
        char perm[4];
        perm[0] = (map.flags & PF_R) ? 'r' : '-';
        perm[1] = (map.flags & PF_W) ? 'w' : '-';
        perm[2] = (map.flags & PF_X) ? 'x' : '-';
        perm[3] = '\0';
        std::cerr << "  Start: 0x" << std::hex << map.paddr
                  << " End: 0x" << (map.paddr + map.size)
                  << " Size: 0x" << map.size
                  << " Flags: " << perm << std::dec << std::endl;
    }
}

int vm::wait_for(const struct timespec* timeout) {
    // 阻塞在 wait_cv 上等待, timeout是相对时间 
    bool has_deadline = timeout != nullptr;
    struct timespec deadline{};
    if(has_deadline) {
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += timeout->tv_sec;
        deadline.tv_nsec += timeout->tv_nsec;
        if(deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
    }
    int rc;
    pthread_mutex_lock(&wait_mutex);
    while(true) {
        uint32_t f = flags.load(std::memory_order_acquire);
        if(!(f & VM_BLOCKED)) {                 // 被 wakeup(true) 清位
            rc = 0;
            break;
        }
        if(f & (VM_KILLED | VM_SIGNAL_PENDING | VM_STOPPED)) {
            rc = -EINTR;                        // 交回 safepoint：投递信号 / 退出 / 停止阻塞
            break;
        }
        if(has_deadline) {
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            if(now.tv_sec > deadline.tv_sec ||
               (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
                rc = -ETIMEDOUT;
                break;
            }
            pthread_cond_timedwait(&wait_cv, &wait_mutex, &deadline);
        } else {
            // 无 deadline：wakeup() 持锁 broadcast，理论上不丢唤醒；仍保留 1s 滚动超时作
            // spurious-wakeup 兜底（condvar 语义允许假唤醒），每轮重判 flag。
            struct timespec backstop;
            clock_gettime(CLOCK_REALTIME, &backstop);
            backstop.tv_sec += 1;
            pthread_cond_timedwait(&wait_cv, &wait_mutex, &backstop);
        }
    }
    pthread_mutex_unlock(&wait_mutex);
    return rc;
}

void vm::wakeup(bool clear_blocked) {
    pthread_mutex_lock(&wait_mutex);
    if(clear_blocked) {
        flags.fetch_and(~VM_BLOCKED, std::memory_order_release);
    }
    pthread_cond_broadcast(&wait_cv);
    pthread_mutex_unlock(&wait_mutex);
}

bool vm::ld(const bpf_insn* cur) {
    if(cur->dst_reg >= 10) {
        return false;
    }
    // lddw 是宽指令（占 2 个 bpf_insn 槽），第二个槽也必须在合法映射内
    if(!mmu(pc + 2 * sizeof(bpf_insn))) {
        log_mem_violation("lddw second slot", pc + 2 * sizeof(bpf_insn));
        return false;
    }
    r(cur->dst_reg) = (uint64_t)(cur+1)->imm << 32 | (uint32_t)cur->imm;
    pc += sizeof(bpf_insn);  // 跳过第二槽；run() 循环再 +=sizeof(bpf_insn)，共两槽
    return true;
}

bool vm::ldx(const bpf_insn* cur) {
    if(cur->dst_reg >= 10) {
        return false;
    }
    uint64_t target_addr = r(cur->src_reg) + cur->off;
    void* addr = mmu(target_addr);
    if (addr == nullptr) {
        log_mem_violation("read", target_addr);
        return false;
    }
    if((cur->code & 0xe0) == BPF_MEM) {
        switch(cur->code & 0x18) {
        case BPF_DW:
            r(cur->dst_reg) = *(uint64_t*)addr;
            break;
        case BPF_W:
            r(cur->dst_reg) = *(uint32_t*)addr;
            break;
        case BPF_H:
            r(cur->dst_reg) = *(uint16_t*)addr;
            break;
        case BPF_B:
            r(cur->dst_reg) = *(uint8_t*)addr;
            break;
        }
    }else if((cur->code & 0xe0) == BPF_MEMSX) {
        switch(cur->code & 0x18) {
        case BPF_DW:
            return false;
        case BPF_W:
            r(cur->dst_reg) = *(int32_t*)addr;
            break;
        case BPF_H:
            r(cur->dst_reg) = *(int16_t*)addr;
            break;
        case BPF_B:
            r(cur->dst_reg) = *(int8_t*)addr;
            break;
        }
    }else {
        return false;
    }
    return true;
}

bool vm::st(const bpf_insn* cur) {
    uint64_t target_addr = r(cur->dst_reg) + cur->off;
    void* addr = mmu_w(target_addr);
    if (addr == nullptr) {
        log_mem_violation("write", target_addr);
        return false;
    }
    switch (cur->code & 0x18) {
    case BPF_DW:
        *(uint64_t*)addr = cur->imm;
        break;
    case BPF_W:
        *(uint32_t*)addr = cur->imm;
        break;
    case BPF_H:
        *(uint16_t*)addr = cur->imm;
        break;
    case BPF_B:
        *(uint8_t*)addr = cur->imm;
        break;
    }
    return true;
}

template<typename T>
static bool do_atomic(T* p, int32_t op, uint64_t& src_reg, uint64_t& r0) {
    T src = (T)src_reg;
    switch(op) {
    case BPF_ADD:                __atomic_fetch_add(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_OR:                 __atomic_fetch_or(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_AND:                __atomic_fetch_and(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_XOR:                __atomic_fetch_xor(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_ADD | BPF_FETCH:    src_reg = __atomic_fetch_add(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_OR  | BPF_FETCH:    src_reg = __atomic_fetch_or(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_AND | BPF_FETCH:    src_reg = __atomic_fetch_and(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_XOR | BPF_FETCH:    src_reg = __atomic_fetch_xor(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_XCHG:               src_reg = __atomic_exchange_n(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_CMPXCHG: {
        T expected = (T)r0;
        T old = expected;
        __atomic_compare_exchange_n(p, &old, src, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        r0 = old;
        break;
    }
    default: return false;
    }
    return true;
}

bool vm::stx(const bpf_insn* cur) {
    if((cur->code & 0xe0) == BPF_ATOMIC) {
        uint64_t target_addr = r(cur->dst_reg) + cur->off;
        void* addr = mmu_w(target_addr);
        if(addr == nullptr) {
            log_mem_violation("atomic", target_addr);
            return false;
        }
        switch(cur->code & 0x18) {
        case BPF_DW: return do_atomic((uint64_t*)addr, cur->imm, r(cur->src_reg), r(0));
        case BPF_W:  return do_atomic((uint32_t*)addr, cur->imm, r(cur->src_reg), r(0));
        default:     return false;
        }
    }
    uint64_t target_addr = r(cur->dst_reg) + cur->off;
    void* addr = mmu_w(target_addr);
    if (addr == nullptr) {
        log_mem_violation("write", target_addr);
        return false;
    }
    switch (cur->code & 0x18) {
    case BPF_DW:
        *(uint64_t*)addr = r(cur->src_reg);
        break;
    case BPF_W:
        *(uint32_t*)addr = r(cur->src_reg);
        break;
    case BPF_H:
        *(uint16_t*)addr = r(cur->src_reg);
        break;
    case BPF_B:
        *(uint8_t*)addr = r(cur->src_reg);
        break;
    }
    return true;
}

bool vm::alu64(const bpf_insn* cur) {
    if(cur->dst_reg >= 10) {
        return false;
    }
    uint64_t src = (cur->code & 0x08) == BPF_X ? r(cur->src_reg) : (uint64_t)(int64_t)cur->imm;
    int64_t signed_src = static_cast<int64_t>(src);
    auto& dst = r(cur->dst_reg);
    switch (cur->code & 0xf0) {
    case BPF_ADD:
        dst += src;
        break;
    case BPF_SUB:
        dst -= src;
        break;
    case BPF_MUL:
        dst *= src;
        break;
    case BPF_DIV:
        if(cur->off == 0) {
            dst = (src != 0) ? (dst / src) : 0;
        }else {
            dst = (src == 0) ? 0 : ((signed_src == -1 && (int64_t)dst == INT64_MIN) ? INT64_MIN : ((int64_t)dst / signed_src));
        }
        break;
    case BPF_OR:
        dst |= src;
        break;
    case BPF_AND:
        dst &= src;
        break;
    case BPF_LSH:
        dst <<= (src & 0x3f);
        break;
    case BPF_RSH:
        dst >>= (src & 0x3f);
        break;
    case BPF_NEG:
        dst = -(int64_t)dst;
        break;
    case BPF_MOD:
        if(cur->off == 0) {
            dst = (src != 0) ? (dst % src) : dst;
        } else {
            dst = (src == 0) ? dst : ((signed_src == -1 && (int64_t)dst == INT64_MIN) ? 0 : ((int64_t)dst % signed_src));
        }
        break;
    case BPF_XOR:
        dst ^= src;
        break;
    case BPF_MOV:
        if(cur->off == 0) {
            dst = src;
        }else if(cur->off == 8) {
            dst = (int8_t)src;
        }else if(cur->off == 16) {
            dst = (int16_t)src;
        }else if(cur->off == 32) {
            dst = (int32_t)src;
        }
        break;
    case BPF_ARSH:
        dst = (int64_t)dst >> (src & 0x3f);
        break;
    case BPF_END:
        switch(cur->imm) {
        case 16:
            dst = __builtin_bswap16((uint16_t)dst);
            break;
        case 32:
            dst = __builtin_bswap32((uint32_t)dst);
            break;
        case 64:
            dst = __builtin_bswap64(dst);
            break;
        default:
            return false;
        }
        break;
    }
    return true;
}

bool vm::alu(const bpf_insn* cur) {
    if(cur->dst_reg >= 10) {
        return false;
    }
    uint32_t src = (cur->code & 0x08) == BPF_X ? (uint32_t)r(cur->src_reg) : cur->imm;
    int32_t signed_src = static_cast<int32_t>(src);
    auto dst = (uint32_t)r(cur->dst_reg);
    switch (cur->code & 0xf0) {
    case BPF_ADD:
        dst += src;
        break;
    case BPF_SUB:
        dst -= src;
        break;
    case BPF_MUL:
        dst *= src;
        break;
    case BPF_DIV:
        if(cur->off == 0) {
            dst = (src != 0) ? ((uint32_t)dst / src) : 0;
        }else {
            dst = (src == 0) ? 0 : ((signed_src == -1 && (int32_t)dst == INT32_MIN) ? INT32_MIN : ((int32_t)dst / signed_src));
        }
        break;
    case BPF_OR:
        dst |= src;
        break;
    case BPF_AND:
        dst &= src;
        break;
    case BPF_LSH:
        dst <<= (src & 0x1f);
        break;
    case BPF_RSH:
        dst >>= (src & 0x1f);
        break;
    case BPF_NEG:
        dst = -(int32_t)dst;
        break;
    case BPF_MOD:
        if(cur->off == 0) {
            dst = (src != 0) ? ((uint32_t)dst % src) : (uint32_t)dst;
        } else {
            dst = (src == 0) ? (uint32_t)dst : ((signed_src == -1 && (int32_t)dst == INT32_MIN) ? 0 : ((int32_t)dst % signed_src));
        }
        break;
    case BPF_XOR:
        dst ^= src;
        break;
    case BPF_MOV:
        if(cur->off == 0) {
            dst = src;
        }else if(cur->off == 8) {
            dst = (int8_t)src;
        }else if(cur->off == 16) {
            dst = (int16_t)src;
        }
        break;
    case BPF_ARSH:
        dst = (int32_t)dst >> (src & 0x1f);
        break;
    case BPF_END:
        if((cur->code & 0x08) == BPF_X) {
            // BE: host byte order -> big endian (byte swap on little-endian host)
            switch(cur->imm) {
            case 16: r(cur->dst_reg) = __builtin_bswap16((uint16_t)dst); return true;
            case 32: r(cur->dst_reg) = __builtin_bswap32(dst); return true;
            case 64: r(cur->dst_reg) = __builtin_bswap64(r(cur->dst_reg)); return true;
            default: return false;
            }
        } else {
            // LE: host byte order -> little endian (no-op on little-endian host, just zero-extend)
            switch(cur->imm) {
            case 16: r(cur->dst_reg) = (uint16_t)dst; return true;
            case 32: r(cur->dst_reg) = (uint32_t)dst; return true;
            case 64: return true;
            default: return false;
            }
        }
    }
    // clear high 32 bits
    r(cur->dst_reg) = (uint64_t)dst;
    return true;
}



bool vm::safepoint() {
    // 仅在非信号上下文中处理新信号，避免信号处理嵌套
    if(signal_depth == 0) {
        if(!options.sys->handle_signals(this)) {
            //be killed
            return false;
        }
    }

    // 停止等待：VM_STOPPED 由 stop_process（SIGSTOP/SIGTSTP/...）设置。
    pthread_mutex_lock(&wait_mutex);
    while(true) {
        uint32_t f = flags.load(std::memory_order_acquire);
        if(f & (VM_EXITED | VM_KILLED | VM_BUDGET_EXCEEDED)) {
            pthread_mutex_unlock(&wait_mutex);
            if (f & VM_KILLED) {
                r(0) = 128 + SIGKILL;
            }
            return false;
        }
        if(!(f & VM_STOPPED)) break;
        pthread_cond_wait(&wait_cv, &wait_mutex);
    }
    pthread_mutex_unlock(&wait_mutex);
    // 唤醒后投递停止期间挂起的信号（POSIX：SIGCONT 恢复运行时在返回用户态前 get_signal
    // 投递 pending）。否则停止态收到的 SIGTERM 滞留队列，子进程已先执行到阻塞系统调用
    // （nanosleep），就会卡死。
    return options.sys->handle_signals(this);
}

bool vm::step() {
    // JIT hot path: keep executing compiled functions in a tight loop
    for(;;) {
        auto* func = jit_->compile(this, pc);
        if(!func) break;
        jit_->stats.jit_func_runs++;
        uint64_t pc_before = pc;
        ((void(*)(vm*))func->code)(this);
        // JIT 函数返回后，检查是真正的 VM 退出还是可恢复的中断
        // (safepoint, syscall, pc changed, etc.)
        uint32_t f = flags.load(std::memory_order_acquire);
        if(f && !safepoint()) {
            return false;
        }
        // safepoint 已处理信号/stop 等可恢复事件且未请求退出。若期间 pc 被改
        // (longjmp、信号处理、BPF CALL/EXIT 等)，则继续 JIT 循环；否则说明 JIT
        // 在无 flag 的情况下中止（如内存违例），落到解释器单步以报告错误。
        if(pc != pc_before) {
            continue;
        }
        break;
    }
    // 解释器执行一条指令
    interp_insns++;
    // 指令计数递增 + 预算检查
    uint64_t cnt = ++insn_count;
    if(options.insn_limit != 0 && cnt >= options.insn_limit) {
        flags.fetch_or(VM_BUDGET_EXCEEDED, std::memory_order_release);
        std::cerr << "Instruction budget exceeded (" << cnt
                  << " >= " << options.insn_limit << ") at PC 0x"
                  << std::hex << pc << std::dec << std::endl;
        return false;
    }
    // Safepoint check: flags 非零即需要处理
    uint32_t f = flags.load(std::memory_order_acquire);
    if(f && !safepoint()) {
        return false;
    }
    const bpf_insn* cur = (const bpf_insn*)mmu(pc);
    if(!cur) {
        log_mem_violation("exec", pc);
        return false;
    }
    if(options.verbose) {
        std::lock_guard<std::mutex> lock(log_mutex);
        printf("[#%d] ", options.sys->id());
        dump(pc, cur);
    }
    if(options.step_run || (options.breakpoint && options.breakpoint == pc)) {
#if defined(__x86_64__) || defined(__i386__)
        asm volatile("int3");
#elif defined(__aarch64__)
        asm volatile("brk #0");
#endif
    }
    bool ok = false;
    switch(cur->code & 0x07) {
    case BPF_LD:   ok = ld(cur); break;
    case BPF_LDX:  ok = ldx(cur); break;
    case BPF_ST:   ok = st(cur); break;
    case BPF_STX:  ok = stx(cur); break;
    case BPF_ALU:  ok = alu(cur); break;
    case BPF_ALU64: ok = alu64(cur); break;
    case BPF_JMP:  ok = jmp(cur); break;
    case BPF_JMP32: ok = jmp32(cur); break;
    }
    return ok;
}

void vm::addmem(memmap&& memmap) {
    //add by sorted order
    std::lock_guard<std::mutex> lock(*maps_mutex);
    auto it = maps->begin();
    while(it != maps->end() && it->paddr < memmap.paddr) {
        it++;
    }
    maps->insert(it, std::move(memmap));
    flush_tlb();
}

bool vm::unmap(uint64_t addr) {
    std::lock_guard<std::mutex> lock(*maps_mutex);
    for(auto it = maps->begin(); it != maps->end(); ++it) {
        if(addr == it->paddr) {
            maps->erase(it); // unique_ptr destructor handles munmap if owned
            flush_tlb();
            return true;
        }
    }
    return false;
}

void vm::flush_tlb() {
    memset(tlb, 0, sizeof(tlb));
}

void vm::clear_jit_cache() {
    if(jit_) jit_->clear();
}

void* vm::mmu(uint64_t addr, size_t size) {
    uint64_t end = addr + size;
    if(end < addr) return nullptr; // overflow
    // TLB fast path (1MB granularity)
    auto& entry = tlb[(addr >> 20) & (TLB_SIZE - 1)];
    if(addr >= entry.guest_base && end <= entry.guest_end) {
        return entry.host_base + (addr - entry.guest_base);
    }
    return mmu_slow(addr, size);
}

void* vm::mmu_slow(uint64_t addr, size_t size) {
    uint64_t end = addr + size;
    auto& entry = tlb[(addr >> 20) & (TLB_SIZE - 1)];
    std::lock_guard<std::mutex> lock(*maps_mutex);
    for(const auto& map: *maps) {
        if(addr >= map.paddr && end <= map.paddr + map.size) {
            entry = {map.paddr, map.paddr + map.size, map.data.get(), map.flags, !!map.cow_data};
            return map.data.get() + (addr - map.paddr);
        }
    }
    return nullptr;
}

void* vm::mmu_w(uint64_t addr, size_t size) {
    uint64_t end = addr + size;
    if(end < addr) return nullptr; // overflow
    // TLB fast path (1MB granularity, only when writable and no CoW pending)
    auto& entry = tlb[(addr >> 20) & (TLB_SIZE - 1)];
    if(addr >= entry.guest_base && end <= entry.guest_end
       && (entry.flags & PF_W) && !entry.cow) {
        return entry.host_base + (addr - entry.guest_base);
    }
    return mmu_w_slow(addr, size);
}

void* vm::mmu_w_slow(uint64_t addr, size_t size) {
    uint64_t end = addr + size;
    auto& entry = tlb[(addr >> 20) & (TLB_SIZE - 1)];
    std::lock_guard<std::mutex> lock(*maps_mutex);
    for(auto& map: *maps) {
        if(addr >= map.paddr && end <= map.paddr + map.size) {
            if(!(map.flags & PF_W)) return nullptr;
            if(map.cow_data) { // CoW triggered: copy on write
                if(map.cow_data.use_count() == 1) {
                    // 唯一引用，直接偷：解除 cow_data 的所有权，unique_ptr 接管
                    std::get_deleter<DataDeleter>(map.cow_data)->owned = false;
                    map.cow_data.reset();
                    map.data.get_deleter().owned = true;
                } else {
                    int prot = PROT_READ | PROT_WRITE;
                    if(map.flags & PF_X) prot |= PROT_EXEC;
                    auto* p = (unsigned char*)mmap(nullptr, map.size, prot,
                                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                    if(p == MAP_FAILED) return nullptr;
                    memcpy(p, map.data.get(), map.size);
                    map.cow_data.reset();
                    map.set_data(p, map.size);
                }
                flush_tlb();
            }
            // Fill TLB after CoW is resolved
            entry = {map.paddr, map.paddr + map.size, map.data.get(), map.flags, !!map.cow_data};
            return map.data.get() + (addr - map.paddr);
        }
    }
    return nullptr;
}

void vm::dump_stats() const {
    if (!getenv("BPF_DEBUG")) return;
    fprintf(stderr, "[BPF] 执行指令数: %" PRIu64 "\n", insn_count);
    fprintf(stderr, "[BPF] 解释器执行指令数: %" PRIu64 "\n", interp_insns);
    auto& s = jit_->stats;
    if (s.jit_compiles) {
        fprintf(stderr, "[BPF] JIT编译函数数: %" PRIu64 "\n", s.jit_compiles);
        fprintf(stderr, "[BPF] JIT编译指令数: %" PRIu64 "\n", s.jit_compiled_insns);
        fprintf(stderr, "[BPF] JIT执行函数次数: %" PRIu64 "\n", s.jit_func_runs);
        fprintf(stderr, "[BPF] 编译时平均函数大小: %.1f条\n",
                (double)s.jit_compiled_insns / s.jit_compiles);
        fprintf(stderr, "[BPF] 编译耗时: %.1fms\n", s.compile_ns / 1e6);
    }
}

uint64_t vm::run() {
    if(!jit_) jit_ = std::make_unique<JitCompilerImpl>();
    if(options.sys) options.sys->init(shared_from_this());
    while(step()) {
        pc += sizeof(bpf_insn);
    }
    if(options.sys) options.sys->fini(shared_from_this());
    dump_stats();
    if(flags.load(std::memory_order_acquire) & VM_BUDGET_EXCEEDED) {
        r(0) = 255;
    }
    flags.fetch_or(VM_EXITED, std::memory_order_release);
    pthread_cond_broadcast(&wait_cv);
    return r(0);
}

uint64_t vm::run(const vmOptions* options, const ElfLoadInfo& info) {
    this->options = *options;
    insn_count = 0;
    interp_insns = 0;
    if(options->verbose) {
        printf("entry: 0x%lx\n", options->entry);
    }

    if(!setup_stack(options->argv, options->envp, info)) {
        return 0;
    }
    flags.fetch_and(~(VM_EXITED | VM_KILLED), std::memory_order_release);
    pc = options->entry;
    if(!mmu(pc)) {
        std::cerr << "[run] pc is null after mmu(entry)\n";
        return 0;
    }
    push_frame(0);
    return run();
}

bool vm::setup_stack(const std::vector<std::string>& argv, const std::vector<std::string>& envp,
                     const ElfLoadInfo& info) {
    unsigned char* stack_base = (unsigned char*)mmu(STACK_BASE);
    if(stack_base == nullptr) {
        unsigned char* data = (unsigned char*)mmap(nullptr, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(data == MAP_FAILED) {
            std::cerr << "Failed to allocate stack" << std::endl;
            return false;
        }
        memmap stack_memmap;
        stack_memmap.set_data(data, STACK_SIZE);
        stack_memmap.size = STACK_SIZE;
        stack_memmap.paddr = STACK_BASE;
        stack_memmap.flags = PF_W;
        addmem(std::move(stack_memmap));
        stack_base = data;
    }

    reg[10] = STACK_BASE + STACK_SIZE - 8;

    // 哨兵：在初始 r10 处写一个合法 frame[0]，模拟"调用者帧"，给_start的局部变量用
    *(uint64_t*)mmu_w(reg[10]) = frame_flags_make(false, options.stack_limit);

    if(options.raw_stack) {
        return true;
    }

    size_t strings_bytes = 0;
    for(const auto& arg : argv) {
        strings_bytes += arg.size() + 1;
    }
    for(const auto& env : envp) {
        strings_bytes += env.size() + 1;
    }

    // 附加 auxv 载荷字符串：
    //   - AT_PLATFORM 指向的 "bpf"（含 '\0'）
    //   - AT_RANDOM 指向的 16 字节随机数据
    static const char kPlatform[] = "bpf";
    const size_t platform_bytes = sizeof(kPlatform); // 含 '\0'
    constexpr size_t kRandomBytes = 16;

    // auxv 条目（type/val 成对的 uint64）；指针型字段稍后回填。
    struct AuxEntry { uint64_t type; uint64_t val; };
    AuxEntry auxv[] = {
        {AT_PAGESZ,   4096},
        {AT_CLKTCK,   100},
        {AT_UID,      0},
        {AT_EUID,     0},
        {AT_GID,      0},
        {AT_EGID,     0},
        {AT_SECURE,   0},
        {AT_BASE,     info.ldso_base},  // 动态链接器加载基址（ldso 自举用）；静态为 0
        {AT_PHDR,     info.phdr},   // 主程序 program header table 运行时地址
        {AT_PHENT,    info.phent},  // 单个 phdr 大小
        {AT_PHNUM,    info.phnum},  // phdr 个数
        {AT_ENTRY, info.app_entry ? info.app_entry : info.entry},  // 入口点（ldso 模式为主程序入口，否则=info.entry）
        {AT_PLATFORM, 0},   // 回填
        {AT_EXECFN,   0},   // 回填
        {AT_RANDOM,   0},   // 回填
        {AT_NULL,     0},
    };
    const size_t aux_qwords = sizeof(auxv) / sizeof(*auxv) * 2;

    // Stack layout at STACK_BASE (low to high)：
    //   argc
    //   argv[0..argc-1] 指针
    //   NULL
    //   envp[0..envc-1] 指针
    //   NULL
    //   auxv[]  （每个条目 2×uint64，以 {AT_NULL,0} 结尾）
    //   argv/env 字符串
    //   "bpf\0" 平台串
    //   16 字节随机数据（AT_RANDOM）
    size_t header_qwords = 1 + (argv.size() + 1) + (envp.size() + 1) + aux_qwords;
    size_t header_bytes = header_qwords * sizeof(uint64_t);
    size_t total_bytes = header_bytes + strings_bytes + platform_bytes + kRandomBytes;
    if(total_bytes > STACK_SIZE) {
        std::cerr << "Stack arguments exceed stack size" << std::endl;
        return false;
    }

    uint64_t* header = (uint64_t*)stack_base;
    header[0] = argv.size();
    size_t cursor = header_bytes;

    for(size_t i = 0; i < argv.size(); i++) {
        size_t len = argv[i].size() + 1;
        memcpy(stack_base + cursor, argv[i].c_str(), len);
        header[1 + i] = STACK_BASE + cursor;
        cursor += len;
    }
    header[1 + argv.size()] = 0;

    size_t env_base = 1 + (argv.size() + 1);
    for(size_t i = 0; i < envp.size(); i++) {
        size_t len = envp[i].size() + 1;
        memcpy(stack_base + cursor, envp[i].c_str(), len);
        header[env_base + i] = STACK_BASE + cursor;
        cursor += len;
    }
    header[env_base + envp.size()] = 0;

    // auxv 紧跟在 envp 的 NULL 之后。
    size_t aux_base = env_base + envp.size() + 1;

    // AT_PLATFORM 指向的 "bpf\0"
    size_t platform_off = cursor;
    memcpy(stack_base + cursor, kPlatform, platform_bytes);
    cursor += platform_bytes;

    // AT_EXECFN：复用 argv[0] 的指针；无 argv 时回退到 AT_PLATFORM 串。
    uint64_t execfn_ptr = (!argv.empty()) ? header[1] : (STACK_BASE + platform_off);

    // AT_RANDOM 指向的 16 字节随机数据
    ssize_t got = ::syscall(SYS_getrandom, stack_base + cursor, kRandomBytes, 0);
    if(got != (ssize_t)kRandomBytes) {
        std::cerr << "Failed to get random bytes for AT_RANDOM" << std::endl;
        return false;
    }

    // 写入 auxv 条目并回填指针型字段
    for(size_t i = 0; i < sizeof(auxv) / sizeof(*auxv); ++i) {
        uint64_t type = auxv[i].type;
        uint64_t val  = auxv[i].val;
        switch(type) {
        case AT_PLATFORM:
            val = STACK_BASE + platform_off;
            break;
        case AT_EXECFN:
            val = execfn_ptr;
            break;
        case AT_RANDOM:
            val = STACK_BASE + cursor;
            break;
        default:
            break;
        }
        header[aux_base + i * 2]     = type;
        header[aux_base + i * 2 + 1] = val;
    }

    reg[1] = STACK_BASE;
    return true;
}
