//
// Created by chouryzhou on 24-10-28.
//

#include "insn.h"
#include "include/bpf_call.h"
#include <iostream>

#include <libelf.h>
#include <gelf.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>
#include <mutex>


std::atomic<uint64_t> vm::next_pid{1};
std::unordered_map<uint64_t, std::shared_ptr<vm>> vm::pid_map{};
std::mutex vm::pid_map_mutex;
static std::mutex log_mutex;

memmap::~memmap() {
    if(data == nullptr || data == MAP_FAILED) {
        return;
    }
    munmap(data, size);
}

fd_handle::~fd_handle() {
    if(fd >= 0) {
        close(fd);
    }
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
                printf("sys 0x%X\n", insn->imm);
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

vm::vm(Token, uint64_t ppid, const std::unordered_map<int, std::shared_ptr<fd_handle>>& opened) {
    pid = next_pid.fetch_add(1);
    this->ppid = ppid;
    fds = opened;
}

vm::~vm() {
    if(!worker.joinable()) {
        return;
    }
    if(worker.get_id() == std::this_thread::get_id()) {
        worker.detach();
    } else {
        worker.join();
    }
}

std::shared_ptr<vm> vm::create(uint64_t ppid, const std::unordered_map<int, std::shared_ptr<fd_handle>>& opened) {
    auto v = std::make_shared<vm>(Token{}, ppid, opened);
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        pid_map[v->pid] = v;
    }
    return v;
}

uint64_t vm::load_elf(const char* elf_file_path) {
    uint64_t entry = 0;
    int fd = -1;
    Elf* elf = nullptr;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        std::cerr << "Failed to initialize libelf: " << elf_errmsg(-1) << std::endl;
        goto out;
    }

    fd = open(elf_file_path, O_RDONLY);
    if(fd < 0) {
        std::cerr << "Failed to open: "<<elf_file_path<<": " << strerror(errno) << std::endl;
        goto out;
    }

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if(elf == NULL) {
        std::cerr << "Failed to open ELF file: " << elf_errmsg(-1) << std::endl;
        goto out;
    }

    if(elf_kind(elf) != ELF_K_ELF) {
        std::cerr << "Not an ELF file" << std::endl;
        goto out;
    }

    GElf_Ehdr ehdr;
    if(gelf_getehdr(elf, &ehdr) != &ehdr) {
        std::cerr << "Failed to get ELF header: " << elf_errmsg(-1) << std::endl;
        goto out;
    }

    if(ehdr.e_type != ET_EXEC) {
        std::cerr << "Not an executable ELF file: " << ehdr.e_type << std::endl;
        goto out;
    }

    if(ehdr.e_machine != 0xf7) {
        std::cerr << "Not an bpf ELF file: "<<ehdr.e_machine << std::endl;
        goto out;
    }

    for(size_t i = 0; i < ehdr.e_phnum; i++) {
        GElf_Phdr phdr;
        if(gelf_getphdr(elf, i, &phdr) != &phdr) {
            std::cerr << "Failed to get program header: " << elf_errmsg(-1) << std::endl;
            goto out;
        }
        if(phdr.p_type != PT_LOAD) {
            continue;
        }

        memmap map;
        map.paddr = phdr.p_vaddr;
        map.size = phdr.p_memsz;
        if(phdr.p_flags & PF_W) {
            map.data = (unsigned char*)mmap(nullptr, map.size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if(map.data == MAP_FAILED) {
                std::cerr << "Failed to mmap section: " << strerror(errno) << std::endl;
                goto out;
            }
            if(pread(fd, map.data, phdr.p_filesz, phdr.p_offset) != (ssize_t)phdr.p_filesz) {
                std::cerr << "Failed to read section: " << strerror(errno) << std::endl;
                goto out;
            }
        }else {
            map.data = (unsigned char*)mmap(nullptr, map.size, PROT_READ, MAP_PRIVATE, fd, phdr.p_offset);
            if(map.data == MAP_FAILED) {
                std::cerr << "Failed to mmap section: " << strerror(errno) << std::endl;
                goto out;
            }
        }
        map.flags = phdr.p_flags;
        addmem(std::move(map));
    }

    entry = ehdr.e_entry;

out:
    if(elf != nullptr) {
        elf_end(elf);
    }
    if(fd >= 0) {
        close(fd);
    }
    return entry;
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
            return do_syscall(pc->imm);
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

bool vm::read_c_string(uint64_t addr, std::string& out, size_t max_len) {
    out.clear();
    if(addr == 0) {
        return false;
    }
    for(size_t i = 0; i < max_len; i++) {
        void* p = mmu(addr + i);
        if(p == nullptr) {
            return false;
        }
        char c = *(char*)p;
        if(c == '\0') {
            return true;
        }
        out.push_back(c);
    }
    return false;
}

bool vm::read_c_string_array(uint64_t addr, std::vector<std::string>& out, size_t max_count, size_t max_str_len) {
    out.clear();
    if(addr == 0) {
        return true;
    }
    for(size_t i = 0; i < max_count; i++) {
        void* p = mmu(addr + i * sizeof(uint64_t));
        if(p == nullptr) {
            return false;
        }
        uint64_t str_addr = *(uint64_t*)p;
        if(str_addr == 0) {
            return true;
        }
        std::string value;
        if(!read_c_string(str_addr, value, max_str_len)) {
            return false;
        }
        out.push_back(std::move(value));
    }
    return false;
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
        std::lock_guard<std::mutex> lock(log_mutex);
        printf("[#%lu] ", pid);
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
            maps.erase(it);
            return it->data;
        }
    }
    return nullptr;
}

uint64_t vm::run() {
    while(step()) {
        pc++;
    }
    frames.clear();
    exited.store(true, std::memory_order_release);
    return r(0);
}

uint64_t vm::run(const vmOptions* options) {
    this->options = *options;
    if(options->verbose) {
        printf("entry: 0x%lx\n", options->entry);
    }

    if(!setup_stack(options->argv, options->envp)) {
        return 0;
    }
    pc = (const bpf_insn*)mmu(options->entry);
    frames.emplace_back(nullptr, reg);
    while(step()) {
        pc++;
    }
    frames.clear();
    exited.store(true, std::memory_order_release);
    return r(0);
}

uint64_t vm::wait() {
    if(worker.joinable()) {
        worker.join();
    }
    return r(0);
}

bool vm::setup_stack(const std::vector<std::string>& argv, const std::vector<std::string>& envp) {
    unsigned char* stack_base = (unsigned char*)mmu(STACK_BASE);
    if(stack_base == nullptr) {
        unsigned char* data = (unsigned char*)mmap(nullptr, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(data == MAP_FAILED) {
            std::cerr << "Failed to allocate stack" << std::endl;
            return false;
        }
        memmap stack_memmap;
        stack_memmap.data = data;
        stack_memmap.size = STACK_SIZE;
        stack_memmap.paddr = STACK_BASE;
        stack_memmap.flags = PF_W;
        addmem(std::move(stack_memmap));
        stack_base = data;
    }

    size_t strings_bytes = 0;
    for(const auto& arg : argv) {
        strings_bytes += arg.size() + 1;
    }
    for(const auto& env : envp) {
        strings_bytes += env.size() + 1;
    }

    // Stack layout at STACK_BASE (low to high):
    // +------------------+
    // | argc             |
    // +------------------+
    // | argv[0] ptr       |
    // | argv[1] ptr       |
    // | ...               |
    // | argv[argc-1] ptr  |
    // | NULL              |
    // +------------------+
    // | envp[0] ptr       |
    // | envp[1] ptr       |
    // | ...               |
    // | envp[envc-1] ptr  |
    // | NULL              |
    // +------------------+
    // | argv/env strings  |
    // +------------------+
    size_t header_qwords = 1 + (argv.size() + 1) + (envp.size() + 1);
    size_t header_bytes = header_qwords * sizeof(uint64_t);
    size_t total_bytes = header_bytes + strings_bytes;
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

    reg[1] = STACK_BASE;
    reg[10] = STACK_BASE + STACK_SIZE - 8;
    return true;
}
