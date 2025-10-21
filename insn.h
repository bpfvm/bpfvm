//
// Created by chouryzhou on 24-10-28.
//

#ifndef INSN_H
#define INSN_H
#include <list>
#include <stack>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>

#define STACK_SIZE (1024 * 1024)
#define STACK_BASE STACK_SIZE
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

struct frame {
    const bpf_insn* pc;
    uint64_t r6,r7,r8,r9,r10;
    frame(const bpf_insn* pc, uint64_t reg[10]) {
        this->pc = pc;
        r6 = reg[6];
        r7 = reg[7];
        r8 = reg[8];
        r9 = reg[9];
        r10 = reg[10];
    }
};

struct vmOptions {
    uint64_t entry;
    bool verbose;
    uint64_t breakpoint;
    bool step_run;
};

class vm {
    vmOptions options;
    const bpf_insn* pc;
    uint64_t reg[11];
    std::stack<frame> frames;
    std::list<memmap> maps;
    void* mmu(uint64_t addr);
    uint64_t unmmu(const void* addr);
    void* unmap(uint64_t addr);
    bool ld();
    bool ldx();
    bool st();
    bool stx();
    bool alu();
    bool alu64();
    bool jmp();
    bool jmp32();
    bool step();

public:
    vm();
    void addmem(memmap&& memmap);
    uint64_t& r(int n) {
        return reg[n];
    }
    void push_frame() {
        frames.emplace(pc, reg);
        reg[10] -= STACK_LIMIT;
    }
    void pop_frame() {
        assert(!frames.empty());
        pc = frames.top().pc;
        reg[6] = frames.top().r6;
        reg[7] = frames.top().r7;
        reg[8] = frames.top().r8;
        reg[9] = frames.top().r9;
        reg[10] = frames.top().r10;
        frames.pop();
    }
    uint64_t run(const vmOptions* options);
};


#endif //INSN_H
