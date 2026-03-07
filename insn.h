//
// Created by chouryzhou on 24-10-28.
//

#ifndef INSN_H
#define INSN_H
#include <list>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <atomic>
#include <array>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <string>
#include <unordered_map>
#include <vector>

#ifndef NSIG
#define NSIG 32
#endif

#define STACK_SIZE (8 * 1024 * 1024)
#define STACK_BASE 0x10000000ULL
#define STACK_LIMIT 4096

#ifndef PF_X
#define PF_X		0x1
#endif
#ifndef PF_W
#define PF_W		0x2
#endif
#ifndef PF_R
#define PF_R		0x4
#endif

struct bpf_insn {
    uint8_t	code;		/* opcode */
    uint8_t	dst_reg:4;	/* dest register */
    uint8_t	src_reg:4;	/* source register */
    int16_t	off;		/* signed offset */
    int32_t	imm;		/* signed immediate constant */
};

/*
For arithmetic and jump instructions the 8-bit 'code'
field is divided into three parts:
  +----------------+--------+--------------------+
  |   4 bits       |  1 bit |   3 bits           |
  | operation code | source | instruction class  |
  +----------------+--------+--------------------+
  (MSB)                                      (LSB)
 */

// classes
#define BPF_LD    0x00
#define BPF_LDX   0x01
#define BPF_ST    0x02
#define BPF_STX   0x03
#define BPF_ALU   0x04
#define BPF_JMP   0x05
#define BPF_JMP32 0x06
#define BPF_ALU64 0x07

// source operands
#define BPF_K     0x00 //use 32-bit immediate as source operand
#define BPF_X     0x08 //use 'src_reg' register as source operand

// op for BPF_ALU and BPF_ALU64
#define BPF_ADD   0x00
#define BPF_SUB   0x10
#define BPF_MUL   0x20
#define BPF_DIV   0x30
#define BPF_OR    0x40
#define BPF_AND   0x50
#define BPF_LSH   0x60
#define BPF_RSH   0x70
#define BPF_NEG   0x80
#define BPF_MOD   0x90
#define BPF_XOR   0xa0
#define BPF_MOV   0xb0  /* eBPF only: mov reg to reg */
#define BPF_ARSH  0xc0  /* eBPF only: sign extending shift right */
#define BPF_END   0xd0  /* eBPF only: endianness conversion */

//op for BPF_JMP and BPF_JMP32
#define BPF_JA    0x00  /* BPF_JMP only */
#define BPF_JEQ   0x10
#define BPF_JGT   0x20
#define BPF_JGE   0x30
#define BPF_JSET  0x40
#define BPF_JNE   0x50  /* eBPF only: jump != */
#define BPF_JSGT  0x60  /* eBPF only: signed '>' */
#define BPF_JSGE  0x70  /* eBPF only: signed '>=' */
#define BPF_CALL  0x80  /* eBPF BPF_JMP only: function call */
#define BPF_EXIT  0x90  /* eBPF BPF_JMP only: function return */
#define BPF_JLT   0xa0  /* eBPF only: unsigned '<' */
#define BPF_JLE   0xb0  /* eBPF only: unsigned '<=' */
#define BPF_JSLT  0xc0  /* eBPF only: signed '<' */
#define BPF_JSLE  0xd0  /* eBPF only: signed '<=' */

/*
For load and store instructions the 8-bit 'code' field is divided as:
  +--------+--------+-------------------+
  | 3 bits | 2 bits |   3 bits          |
  |  mode  |  size  | instruction class |
  +--------+--------+-------------------+
  (MSB)                             (LSB)
*/
// Size modifier for load and store
#define BPF_W   0x00    /* word */
#define BPF_H   0x08    /* half word */
#define BPF_B   0x10    /* byte */
#define BPF_DW  0x18    /* eBPF only, double word */

// Mode modifier for load and store
#define BPF_IMM  0x00  /* used for 32-bit mov in classic BPF and 64-bit in eBPF */
#define BPF_ABS  0x20  /* legacy BPF packet access (absolute)*/
#define BPF_IND  0x40  /* legacy BPF packet access (indirect)*/
#define BPF_MEM  0x60  /* regular load and store operations */
#define BPF_MEMSX  0x80  /* sign-extension load operations */
#define BPF_ATOMIC 0xc0  /*atomic operations*/

// Atomic operation codes (encoded in imm field of BPF_ATOMIC instructions)
#define BPF_FETCH   0x01
#define BPF_XCHG    0xe0 | BPF_FETCH
#define BPF_CMPXCHG 0xf0 | BPF_FETCH

struct memmap {
    unsigned char* data = nullptr;
    size_t size = 0;
    uint64_t paddr = 0;
    uint32_t flags = 0;
    memmap() = default;
    memmap(memmap&& other) {
        data = other.data;
        size = other.size;
        paddr = other.paddr;
        flags = other.flags;
        other.data = nullptr;
        other.size = 0;
        other.flags = 0;
    }
    ~memmap();
};

class vm;
class SyscallHandler{
public:
    virtual ~SyscallHandler() = default;
    virtual void init(const std::shared_ptr<vm>& v) = 0;
    virtual bool dispatch(uint32_t call) = 0;
    virtual int id() = 0;
};

struct vmOptions {
    uint64_t entry;
    bool verbose;
    uint64_t breakpoint;
    bool step_run;
    std::vector<std::string> argv;
    std::vector<std::string> envp;
    std::shared_ptr<SyscallHandler> sys;
};

class MpscQueue {
    struct slot {
        std::atomic<uint64_t> seq;
        int value = 0;
    };
    static constexpr size_t k_capacity = 1024;
    static constexpr size_t k_mask = k_capacity - 1;
    static_assert((k_capacity & (k_capacity - 1)) == 0, "k_capacity must be power of two");
    std::array<slot, k_capacity> slots{};
    std::atomic<uint64_t> head{0};
    std::atomic<uint64_t> tail{0};
public:
    MpscQueue();
    bool try_push(int value);
    bool try_pop(int& value);
    bool empty() const {
        return head.load(std::memory_order_relaxed) == tail.load(std::memory_order_relaxed);
    }
};

struct signal_action {
    uint64_t handler = 0;
    uint64_t mask = 0;
    int flags = 0;
};

class vm: public std::enable_shared_from_this<vm> {
    vmOptions options;
    const bpf_insn* pc;
    uint64_t reg[11];
    std::list<memmap> maps;
    pthread_mutex_t exit_mutex;
    pthread_cond_t exit_cv;
    std::atomic<bool> exited{false};
    std::atomic<bool> stopped{false};
    std::array<signal_action, NSIG> signal_actions{};
    MpscQueue pending_signals;
    size_t signal_depth = 0;
    pthread_t tid = 0;


    bool ld();
    bool ldx();
    bool st();
    bool stx();
    bool alu();
    bool alu64();
    bool jmp();
    bool jmp32();
    bool step();

    bool do_syscall(uint32_t call) {
        if(options.sys) {
            return options.sys->dispatch(call);
        }
        return true;
    }

    friend class SyscallAccessor;

    void log_mem_violation(const char* type, uint64_t addr);
    bool handle_pending_signals();
    struct Token { explicit Token() = default; };
public:
    vm(Token);
    ~vm();

    static std::shared_ptr<vm> create();
    void* mmu(uint64_t addr, size_t size = 1);
    uint64_t unmmu(const void* addr);
    void* unmap(uint64_t addr);
    bool setup_stack(const std::vector<std::string>& argv, const std::vector<std::string>& envp);
    bool push_frame(uint64_t return_addr, bool is_signal = false);
    uint64_t pop_frame();
    bool wait_for_exit(int timeout_ms);
    uint64_t load_elf(const char* elf_file_path);
    void addmem(memmap&& memmap);
    void queue_signal(int sig);
    uint64_t& r(int n) {
        return reg[n];
    }

    uint64_t run();
    uint64_t run(const vmOptions* options);
};


class SyscallAccessor {
protected:
    static auto& maps(vm* v) { return v->maps; }
    static auto& options(vm* v) { return v->options; }
    static auto& exited(vm* v) { return v->exited; }
    static auto& signal_actions(vm* v) { return v->signal_actions; }
    static auto& pending_signals(vm* v) { return v->pending_signals; }
    static auto& signal_depth(vm* v) { return v->signal_depth; }
    static auto& pc(vm* v) { return v->pc; }
};


#endif //INSN_H
