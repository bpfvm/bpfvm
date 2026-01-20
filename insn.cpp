//
// Created by chouryzhou on 24-10-28.
//

#include "insn.h"
#include "bpf_call.h"
#include <iostream>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/syscall.h>


memmap::~memmap() {
    if(data == nullptr || data == MAP_FAILED) {
        return;
    }
    munmap(data, size);
}


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
    printf("%x: 0x%02x %d %d %d 0x%x: ", addr, insn->code, insn->dst_reg, insn->src_reg, insn->off, insn->imm);
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
                printf("sys %d\n", insn->imm);
            }else if(insn->src_reg == 1) {
                printf("%d\n", insn->imm);
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

vm::vm() {
    memmap stack_memmap;
    stack_memmap.data = (unsigned char *)mmap(nullptr, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    stack_memmap.size = STACK_SIZE;
    stack_memmap.paddr = STACK_BASE;
    stack_memmap.flags = PF_W;
    addmem(std::move(stack_memmap));
    reg[10] = STACK_BASE + STACK_SIZE - 8;
}

bool vm::jmp() {
    uint64_t src = (pc->code & 0x08) == BPF_X ? r(pc->src_reg) : pc->imm;
    switch (pc->code & 0xf0) {
    case BPF_JA:
        pc += pc->off;
        break;
    case BPF_JEQ:
        if (r(pc->dst_reg) == src) {
            pc += pc->off;
        }
        break;
    case BPF_JGT:
        if (r(pc->dst_reg) > src) {
            pc += pc->off;
        }
        break;
    case BPF_JGE:
        if (r(pc->dst_reg) >= src) {
            pc += pc->off;
        }
        break;
    case BPF_JSET:
        if (r(pc->dst_reg) & src) {
            pc += pc->off;
        }
        break;
    case BPF_JNE:
        if (r(pc->dst_reg) != src) {
            pc += pc->off;
        }
        break;
    case BPF_JSGT:
        if ((int64_t)r(pc->dst_reg) > (int64_t)src) {
            pc += pc->off;
        }
        break;
    case BPF_JSGE:
        if ((int64_t)r(pc->dst_reg) >= (int64_t)src) {
            pc += pc->off;
        }
        break;
    case BPF_CALL:
        if((pc->code & 0x08) == BPF_X) {
            push_frame();
            pc = (const bpf_insn*)mmu(r(pc->dst_reg));
            pc--;
        }else if(pc->src_reg == 0) {
            switch(pc->imm){
            case BPF_CALL_MMAP: {
                void* addr = mmap(nullptr, r(1), r(2), r(3), r(4), r(5));
                if(addr == MAP_FAILED) {
                    r(0) = -errno;
                    break;
                }
                memmap mem;
                mem.data = (unsigned char*)addr;
                mem.paddr = maps.back().paddr + maps.back().size;
                mem.flags = r(3);
                mem.size = r(1);
                r(0) = mem.paddr;
                addmem(std::move(mem));
                break;
            }
            case BPF_CALL_MUNMAP: {
                auto addr = unmap(r(1));
                if(addr == nullptr) {
                    r(0) = -EINVAL;
                    break;
                }
                if(munmap(addr, r(2)) == -1) {
                    r(0) = -errno;
                    break;
                }
                r(0) = 0;
                break;
            }
            case BPF_CALL_EXIT:
                r(0) = r(1);
                return false;
            case BPF_CALL_GETTIMEOFDAY: {
                struct timeval* tv = (struct timeval*)mmu(r(1));
                struct timezone* tz = (struct timezone*)mmu(r(2));
                if(gettimeofday(tv, tz) == -1) {
                    r(0) = -errno;
                    break;
                }
                r(0) = 0;
                break;
            }
            case BPF_CALL_OPEN:{
                const char* path = (const char*)mmu(r(1));
                int fd = open(path, r(2), r(3));
                if(fd == -1) {
                    r(0) = -errno;
                    break;
                }
                r(0) = fd;
                break;
            }
            case BPF_CALL_READ: {
                int rc = read(r(1), mmu(r(2)), r(3));
                if(rc == -1) {
                    r(0) = -errno;
                    break;
                }
                r(0) = rc;
                break;
            }
            case BPF_CALL_WRITE: {
                int rc = write(r(1), mmu(r(2)), r(3));
                if(rc == -1) {
                    r(0) = -errno;
                    break;
                }
                r(0) = rc;
                break;
            }
            case BPF_CALL_LSEEK: {
                int rc = lseek64(r(1), r(2), r(3));
                if(rc == -1) {
                    r(0) = -errno;
                    break;
                }
                break;
            }
            case BPF_CALL_CLOSE: {
                int rc = close(r(1));
                if(rc == -1) {
                    r(0) = -errno;
                    break;
                }
                r(0) = 0;
                break;
            }
            case BPF_CALL_UNLINK: {
                int rc = unlink((const char*)mmu(r(1)));
                if(rc == -1) {
                    r(0) = -errno;
                    break;
                }
                r(0) = 0;
                break;
            }
            case BPF_CALL_RENAMEAT: {
                int rc = renameat(r(1), (const char*)mmu(r(2)), r(3), (const char*)mmu(r(4)));
                if(rc == -1) {
                    r(0) = -errno;
                    break;
                }
                r(0) = 0;
                break;
            }
            case BPF_CALL_READLINK: {
                int rc = readlink((const char*)mmu(r(1)), (char*)mmu(r(2)), r(3));
                if(rc == -1) {
                    r(0) = -errno;
                    break;
                }
                r(0) = rc;
                break;
            }
            default:
                fprintf(stderr, "unsupported func: 0x%x\n", pc->imm);
                r(0) = -ENOSYS;
                break;
            }
        }else if(pc->src_reg == 1) {
            push_frame();
            pc += pc->imm;
        }
        break;
    case BPF_EXIT:
        pop_frame();
        if (frames.empty()) {
            return false;
        }
        break;
    case BPF_JLT:
        if (r(pc->dst_reg) < src) {
            pc += pc->off;
        }
        break;
    case BPF_JLE:
        if (r(pc->dst_reg) <= src) {
            pc += pc->off;
        }
        break;
    case BPF_JSLT:
        if ((int64_t)r(pc->dst_reg) < (int64_t)src) {
            pc += pc->off;
        }
        break;
    case BPF_JSLE:
        if ((int64_t)r(pc->dst_reg) <= (int64_t)src) {
            pc += pc->off;
        }
        break;
    }
    return true;
}

bool vm::jmp32() {
    uint32_t src = (pc->code & 0x08) == BPF_X ? (uint32_t)r(pc->src_reg) : pc->imm;
    auto dst = (uint32_t)r(pc->dst_reg);
    switch (pc->code & 0xf0) {
    case BPF_JA:
        pc += pc->imm;
        break;
    case BPF_JEQ:
        if (dst == src) {
            pc += pc->off;
        }
        break;
    case BPF_JGT:
        if (dst > src) {
            pc += pc->off;
        }
        break;
    case BPF_JGE:
        if (dst >= src) {
            pc += pc->off;
        }
        break;
    case BPF_JSET:
        if (dst & src) {
            pc += pc->off;
        }
        break;
    case BPF_JNE:
        if (dst != src) {
            pc += pc->off;
        }
        break;
    case BPF_JSGT:
        if ((int32_t)dst > (int32_t)src) {
            pc += pc->off;
        }
        break;
    case BPF_JSGE:
        if ((int32_t)dst >= (int32_t)src) {
            pc += pc->off;
        }
        break;
    case BPF_CALL:
    case BPF_EXIT:
        return false;
    case BPF_JLT:
        if (dst < src) {
            pc += pc->off;
        }
        break;
    case BPF_JLE:
        if (dst <= src) {
            pc += pc->off;
        }
        break;
    case BPF_JSLT:
        if ((int32_t)dst < (int32_t)src) {
            pc += pc->off;
        }
        break;
    case BPF_JSLE:
        if ((int32_t)dst <= (int32_t)src) {
            pc += pc->off;
        }
        break;
    }
    return true;
}


void vm::log_mem_violation(const char* type, uint64_t addr) {
    std::cerr << "Memory access violation at PC 0x" << std::hex << unmmu(pc)
              << ": invalid " << type << " at address 0x" << addr << std::dec << std::endl;
    std::cerr << "Current memory maps:" << std::endl;
    for(const auto& map : maps) {
        std::cerr << "  Start: 0x" << std::hex << map.paddr 
                  << " End: 0x" << (map.paddr + map.size) 
                  << " Size: 0x" << map.size 
                  << " Flags: " << map.flags << std::dec << std::endl;
    }
}

bool vm::ld() {
    if(pc->dst_reg >= 10) {
        return false;
    }
    r(pc->dst_reg) = (uint64_t)(pc+1)->imm << 32 | (uint32_t)pc->imm;
    pc++;
    return true;
}

bool vm::ldx() {
    if(pc->dst_reg >= 10) {
        return false;
    }
    uint64_t target_addr = r(pc->src_reg) + pc->off;
    void* addr = mmu(target_addr);
    if (addr == nullptr) {
        log_mem_violation("read", target_addr);
        return false;
    }
    if((pc->code & 0xe0) == BPF_MEM) {
        switch(pc->code & 0x18) {
        case BPF_DW:
            r(pc->dst_reg) = *(uint64_t*)addr;
            break;
        case BPF_W:
            r(pc->dst_reg) = *(uint32_t*)addr;
            break;
        case BPF_H:
            r(pc->dst_reg) = *(uint16_t*)addr;
            break;
        case BPF_B:
            r(pc->dst_reg) = *(uint8_t*)addr;
            break;
        }
    }else if((pc->code & 0xe0) == BPF_MEMSX) {
        switch(pc->code & 0x18) {
        case BPF_DW:
            return false;
        case BPF_W:
            r(pc->dst_reg) = *(int32_t*)addr;
            break;
        case BPF_H:
            r(pc->dst_reg) = *(int16_t*)addr;
            break;
        case BPF_B:
            r(pc->dst_reg) = *(int8_t*)addr;
            break;
        }
    }else {
        return false;
    }
    return true;
}

bool vm::st() {
    uint64_t target_addr = r(pc->dst_reg) + pc->off;
    void* addr = mmu(target_addr);
    if (addr == nullptr) {
        log_mem_violation("write", target_addr);
        return false;
    }
    switch (pc->code & 0x18) {
    case BPF_DW:
        *(uint64_t*)addr = pc->imm;
        break;
    case BPF_W:
        *(uint32_t*)addr = pc->imm;
        break;
    case BPF_H:
        *(uint16_t*)addr = pc->imm;
        break;
    case BPF_B:
        *(uint8_t*)addr = pc->imm;
        break;
    }
    return true;
}

bool vm::stx() {
    if((pc->code & 0xe0) == BPF_ATOMIC) {
        return false;
    }
    uint64_t target_addr = r(pc->dst_reg) + pc->off;
    void* addr = mmu(target_addr);
    if (addr == nullptr) {
        log_mem_violation("write", target_addr);
        return false;
    }
    switch (pc->code & 0x18) {
    case BPF_DW:
        *(uint64_t*)addr = r(pc->src_reg);
        break;
    case BPF_W:
        *(uint32_t*)addr = r(pc->src_reg);
        break;
    case BPF_H:
        *(uint16_t*)addr = r(pc->src_reg);
        break;
    case BPF_B:
        *(uint8_t*)addr = r(pc->src_reg);
        break;
    }
    return true;
}

bool vm::alu64() {
    if(pc->dst_reg >= 10) {
        return false;
    }
    uint64_t src = (pc->code & 0x08) == BPF_X ? r(pc->src_reg) : (uint64_t)(int64_t)pc->imm;
    auto& dst = r(pc->dst_reg);
    switch (pc->code & 0xf0) {
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
        if(pc->off == 0) {
            dst = (src != 0) ? (dst / src) : 0;
        }else {
            dst = (src == 0) ? 0 : ((src == -1 && (int64_t)dst == INT64_MIN) ? INT64_MIN : ((int64_t)dst/(int64_t)src));
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
        if(pc->off == 0) {
            dst = (src != 0) ? (dst % src) : dst;
        } else {
            dst = (src == 0) ? dst : ((src == -1 && (int64_t)dst == INT64_MIN) ? 0: ((int64_t)dst % (int64_t)src));
        }
        break;
    case BPF_XOR:
        dst ^= src;
        break;
    case BPF_MOV:
        if(pc->off == 0) {
            dst = src;
        }else if(pc->off == 8) {
            dst = (int8_t)src;
        }else if(pc->off == 16) {
            dst = (int16_t)src;
        }else if(pc->off == 32) {
            dst = (int32_t)src;
        }
        break;
    case BPF_ARSH:
        dst = (int64_t)dst >> (src & 0x3f);
        break;
    case BPF_END:
        //TODO
        abort();
    }
    return true;
}

bool vm::alu() {
    if(pc->dst_reg >= 10) {
        return false;
    }
    uint32_t src = (pc->code & 0x08) == BPF_X ? (uint32_t)r(pc->src_reg) : pc->imm;
    auto dst = (uint32_t)r(pc->dst_reg);
    switch (pc->code & 0xf0) {
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
        if(pc->off == 0) {
            dst = (src != 0) ? ((uint32_t)dst / src) : 0;
        }else {
            dst = (src == 0) ? 0 : ((src == -1 && (int32_t)dst == INT32_MIN) ? INT32_MIN : ((int32_t)dst/(int32_t)src));
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
        if(pc->off == 0) {
            dst = (src != 0) ? ((uint32_t)dst % src) : (uint32_t)dst;
        } else {
            dst = (src == 0) ? (uint32_t)dst : ((src == -1 && (int32_t)dst == INT32_MIN) ? 0: ((int32_t)dst % (int32_t)src));
        }
        break;
    case BPF_XOR:
        dst ^= src;
        break;
    case BPF_MOV:
        if(pc->off == 0) {
            dst = src;
        }else if(pc->off == 8) {
            dst = (int8_t)src;
        }else if(pc->off == 16) {
            dst = (int16_t)src;
        }
        break;
    case BPF_ARSH:
        dst = (int32_t)dst >> (src & 0x1f);
        break;
    case BPF_END:
        //TODO
        abort();
    }
    // clear high 32 bits
    r(pc->dst_reg) = (uint64_t)dst;
    return true;
}



bool vm::step() {
    uint64_t addr = unmmu(pc);
    if(options.verbose) {
        dump(addr, pc);
    }
    if(options.step_run || (options.breakpoint && options.breakpoint == addr)) {
        asm volatile (
            "syscall"
            : /* no output operands */
            : "a" (SYS_kill), // 输入: rax = SYS_kill
                "D" (0),        // 输入: rdi = 0
                "S" (SIGTRAP)   // 输入: rsi = SIGTRAP
            : "rcx", "r11", "memory" // 被破坏的寄存器
        );
    }
    switch(pc->code & 0x07) {
    case BPF_LD:
        return ld();
    case BPF_LDX:
        return ldx();
    case BPF_ST:
        return st();
    case BPF_STX:
        return stx();
    case BPF_ALU:
        return alu();
    case BPF_ALU64:
        return alu64();
    case BPF_JMP:
        return jmp();
    case BPF_JMP32:
        return jmp32();
    }
    return false;
}

void vm::addmem(memmap&& memmap) {
    //add by sorted order
    auto it = maps.begin();
    while(it != maps.end() && it->paddr < memmap.paddr) {
        it++;
    }
    maps.insert(it, std::move(memmap));
}

void* vm::mmu(uint64_t addr) {
    for(const auto& map: maps) {
        if(addr >= map.paddr && addr < map.paddr + map.size) {
            return map.data + (addr - map.paddr);
        }
    }
    return nullptr;
}

uint64_t vm::unmmu(const void* addr) {
    for(const auto& map: maps) {
        if(addr >= map.data && addr < map.data + map.size) {
            return map.paddr + ((unsigned char*)addr - map.data);
        }
    }
    return 0;
}

void* vm::unmap(uint64_t addr) {
    for(auto it = maps.begin(); it != maps.end(); ++it) {
        if(addr == it->paddr) {
            auto addr = it->data;
            maps.erase(it);
            return it->data;
        }
    }
    return nullptr;
}


uint64_t vm::run(const vmOptions* options) {
    this->options = *options;
    if(options->verbose) {
        printf("entry: 0x%lx\n", options->entry);
    }
    pc = (const bpf_insn*)mmu(options->entry);
    frames.emplace(nullptr, reg);
    while(step()) {
        pc++;
    }
    frames = {};
    return r(0);
}