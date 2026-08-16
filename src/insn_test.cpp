#include "insn.h"
#include "include/bpf_syscall.h"
#include <iostream>
#include <cassert>
#include <cstdio>
#include <cstring> // For memcpy
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include "posix/posix_syscall.h"
#include "empty_syscall.h"

// Helper function to print test results
void print_test_result(const std::string& test_name, bool success) {
    std::cout << "Test: " << test_name << " - " << (success ? "PASSED" : "FAILED") << std::endl;
}

struct vmOptions option = {
    .verbose = true,
    .raw_stack = true,
    .argv = {},
    .envp = {},
    .sys = std::make_shared<EmptySyscall>(),
    .root = {},
};

struct vmOptions posix_option = {
    .verbose = true,
    .raw_stack = true,
    .argv = {},
    .envp = {},
    .sys = std::make_shared<PosixSyscall>(),
    .root = {},
};

// Helper function to load BPF program code into the VM's memory
// Allocates memory for the code, copies it, and adds it to the VM.
// Sets PF_W flag in memmap to ensure free() is called by memmap's destructor,
// as per current memmap destructor logic for malloc'd data.
bool load_program_to_vm(std::shared_ptr<vm> ebpf_vm, const bpf_insn* instructions, size_t num_instructions, uint64_t paddr = 0x1000) {
    if (instructions == nullptr || num_instructions == 0) {
        std::cerr << "Error: No instructions provided to load_program_to_vm." << std::endl;
        return false;
    }

    size_t code_size = num_instructions * sizeof(bpf_insn);
    // Align code_size to a reasonable boundary if necessary, e.g., page size for mmap later if used directly
    // For now, simple malloc is used as in the original code.

    unsigned char* prog_data = (unsigned char*)mmap(nullptr, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!prog_data) {
        std::cerr << "Error: Failed to allocate memory for program code in load_program_to_vm. Size: " << code_size << std::endl;
        perror("malloc failed");
        return false;
    }
    memcpy(prog_data, instructions, code_size);

    memmap prog_mem;
    prog_mem.paddr = paddr; // Use a non-zero base address for program memory to avoid conflict with nullptr or other special addresses
    prog_mem.size = code_size;  // VM 地址范围检查用
    prog_mem.set_data(prog_data, sysconf(_SC_PAGESIZE));  // DataDeleter 用整页大小做 munmap
    prog_mem.flags = PF_R | PF_X | PF_W; // PF_W for free() by memmap destructor, PF_R | PF_X for execution
    ebpf_vm->addmem(std::move(prog_mem));
    // 测试不经 load_elf，程序加载地址即入口。仅首次加载（image 未设）时构造 image；
    // 多段加载（如主程序+helper）不覆盖入口——入口恒为主程序（首次）加载地址。
    // fd=-1：手搓 vm 无 exe 文件，~vmImage 不关任何 fd。
    if(!ebpf_vm->image()) {
        ebpf_vm->set_image(std::make_shared<vmImage>(paddr, 0, "", -1));
    }
    return true;
}

bool add_data_mem(vm& ebpf_vm, uint64_t paddr, size_t size, unsigned char** out_ptr) {
    if(size == 0) {
        return false;
    }
    long page_size = sysconf(_SC_PAGESIZE);
    size_t map_size = (size + page_size - 1) / page_size * page_size;
    unsigned char* data = (unsigned char*)mmap(nullptr, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (data == MAP_FAILED) {
        std::cerr << "Error: Failed to allocate memory for data memmap." << std::endl;
        return false;
    }
    memmap data_mem;
    data_mem.paddr = paddr;
    data_mem.size = map_size;
    data_mem.set_data(data, map_size);
    data_mem.flags = PF_R | PF_W;
    ebpf_vm.addmem(std::move(data_mem));
    if(out_ptr != nullptr) {
        *out_ptr = data;
    }
    return true;
}

// --- ALU64 Tests ---
void test_alu64_add_imm() {
    std::cout << "--- Running Test: test_alu64_add_imm ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 100 }, // mov r1, 100
        { BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 50 },  // add r1, 50
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },   // mov r0, r1 (for exit value)
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }             // exit
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option); // Program loaded at 0x1000
    bool success = (ebpf_vm->r(1) == 150 && ret == 150);
    print_test_result("test_alu64_add_imm", success);
    assert(success);
}

void test_alu64_sub_reg() {
    std::cout << "--- Running Test: test_alu64_sub_reg ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 200 }, // mov r1, 200
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 75 },  // mov r2, 75
        { BPF_ALU64 | BPF_SUB | BPF_X, 1, 2, 0, 0 },   // sub r1, r2
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },   // mov r0, r1
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 125 && ret == 125);
    print_test_result("test_alu64_sub_reg", success);
    assert(success);
}

void test_alu64_mul_imm() {
    std::cout << "--- Running Test: test_alu64_mul_imm ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 12 },  // mov r1, 12
        { BPF_ALU64 | BPF_MUL | BPF_K, 1, 0, 0, 10 },  // mul r1, 10
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 120 && ret == 120);
    print_test_result("test_alu64_mul_imm", success);
    assert(success);
}

void test_alu64_div_imm() {
    std::cout << "--- Running Test: test_alu64_div_imm ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 100 }, // mov r1, 100
        { BPF_ALU64 | BPF_DIV | BPF_K, 1, 0, 0, 5 },   // div r1, 5
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 20 && ret == 20);
    print_test_result("test_alu64_div_imm", success);
    assert(success);
}

void test_alu64_div_by_zero_imm() {
    std::cout << "--- Running Test: test_alu64_div_by_zero_imm ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 100 }, // mov r1, 100
        { BPF_ALU64 | BPF_DIV | BPF_K, 1, 0, 0, 0 },   // div r1, 0
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    // According to BPF spec, division by zero result is 0.
    bool success = (ebpf_vm->r(1) == 0 && ret == 0);
    print_test_result("test_alu64_div_by_zero_imm", success);
    assert(success);
}


void test_alu64_mod_imm() {
    std::cout << "--- Running Test: test_alu64_mod_imm ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 100 }, // mov r1, 100
        { BPF_ALU64 | BPF_MOD | BPF_K, 1, 0, 0, 7 },   // mod r1, 7
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 2 && ret == 2); // 100 % 7 = 2
    print_test_result("test_alu64_mod_imm", success);
    assert(success);
}

void test_alu64_mod_by_zero_imm() {
    std::cout << "--- Running Test: test_alu64_mod_by_zero_imm ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 100 }, // mov r1, 100
        { BPF_ALU64 | BPF_MOD | BPF_K, 1, 0, 0, 0 },   // mod r1, 0
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    // According to BPF spec, modulo by zero result is dst.
    bool success = (ebpf_vm->r(1) == 100 && ret == 100);
    print_test_result("test_alu64_mod_by_zero_imm", success);
    assert(success);
}

// --- DIV/MOD register source tests ---

void test_alu64_div_reg() {
    std::cout << "--- Running Test: test_alu64_div_reg ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = 100;
    ebpf_vm->r(2) = 5;
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_DIV | BPF_X, 1, 2, 0, 0 },   // div r1, r2
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 20 && ret == 20);
    print_test_result("test_alu64_div_reg", success);
    assert(success);
}

void test_alu64_mod_reg() {
    std::cout << "--- Running Test: test_alu64_mod_reg ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = 100;
    ebpf_vm->r(2) = 7;
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOD | BPF_X, 1, 2, 0, 0 },   // mod r1, r2
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 2 && ret == 2);
    print_test_result("test_alu64_mod_reg", success);
    assert(success);
}

void test_alu64_div_by_zero_reg() {
    std::cout << "--- Running Test: test_alu64_div_by_zero_reg ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = 100;
    ebpf_vm->r(2) = 0;
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_DIV | BPF_X, 1, 2, 0, 0 },   // div r1, r2 (r2=0)
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 0 && ret == 0);
    print_test_result("test_alu64_div_by_zero_reg", success);
    assert(success);
}

void test_alu64_mod_by_zero_reg() {
    std::cout << "--- Running Test: test_alu64_mod_by_zero_reg ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = 100;
    ebpf_vm->r(2) = 0;
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOD | BPF_X, 1, 2, 0, 0 },   // mod r1, r2 (r2=0)
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 100 && ret == 100);
    print_test_result("test_alu64_mod_by_zero_reg", success);
    assert(success);
}

// --- Signed DIV/MOD tests (off != 0) ---

void test_alu64_div_signed_reg() {
    std::cout << "--- Running Test: test_alu64_div_signed_reg ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = (uint64_t)(int64_t)-10;
    ebpf_vm->r(2) = 3;
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_DIV | BPF_X, 1, 2, 1, 0 },   // signed div r1, r2 (off=1)
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == (uint64_t)(int64_t)-3 && ret == (uint64_t)(int64_t)-3);
    print_test_result("test_alu64_div_signed_reg", success);
    assert(success);
}

void test_alu64_mod_signed_reg() {
    std::cout << "--- Running Test: test_alu64_mod_signed_reg ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = (uint64_t)(int64_t)-10;
    ebpf_vm->r(2) = 3;
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOD | BPF_X, 1, 2, 1, 0 },   // signed mod r1, r2 (off=1)
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == (uint64_t)(int64_t)-1 && ret == (uint64_t)(int64_t)-1);
    print_test_result("test_alu64_mod_signed_reg", success);
    assert(success);
}

void test_alu64_div_signed_by_zero_reg() {
    std::cout << "--- Running Test: test_alu64_div_signed_by_zero_reg ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = 42;
    ebpf_vm->r(2) = 0;
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_DIV | BPF_X, 1, 2, 1, 0 },   // signed div r1, 0 -> 0
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 0 && ret == 0);
    print_test_result("test_alu64_div_signed_by_zero_reg", success);
    assert(success);
}

void test_alu64_mod_signed_by_zero_reg() {
    std::cout << "--- Running Test: test_alu64_mod_signed_by_zero_reg ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = 42;
    ebpf_vm->r(2) = 0;
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOD | BPF_X, 1, 2, 1, 0 },   // signed mod r1, 0 -> r1
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 42 && ret == 42);
    print_test_result("test_alu64_mod_signed_by_zero_reg", success);
    assert(success);
}

// --- INT_MIN / -1 edge case tests ---

void test_alu64_div_intmin_neg1() {
    std::cout << "--- Running Test: test_alu64_div_intmin_neg1 ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = (uint64_t)INT64_MIN;
    ebpf_vm->r(2) = (uint64_t)(int64_t)-1;
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_DIV | BPF_X, 1, 2, 1, 0 },   // signed div INT64_MIN, -1 -> INT64_MIN
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == (uint64_t)INT64_MIN && ret == (uint64_t)INT64_MIN);
    print_test_result("test_alu64_div_intmin_neg1", success);
    assert(success);
}

void test_alu64_mod_intmin_neg1() {
    std::cout << "--- Running Test: test_alu64_mod_intmin_neg1 ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = (uint64_t)INT64_MIN;
    ebpf_vm->r(2) = (uint64_t)(int64_t)-1;
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOD | BPF_X, 1, 2, 1, 0 },   // signed mod INT64_MIN, -1 -> 0
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 0 && ret == 0);
    print_test_result("test_alu64_mod_intmin_neg1", success);
    assert(success);
}

void test_alu32_div_intmin_neg1() {
    std::cout << "--- Running Test: test_alu32_div_intmin_neg1 ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = (uint64_t)(uint32_t)INT32_MIN;
    ebpf_vm->r(2) = (uint64_t)(uint32_t)(uint32_t)-1;
    bpf_insn instructions[] = {
        { BPF_ALU | BPF_DIV | BPF_X, 1, 2, 1, 0 },     // 32-bit signed div INT32_MIN, -1 -> INT32_MIN
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = ((uint32_t)ebpf_vm->r(1) == (uint32_t)INT32_MIN && (uint32_t)ret == (uint32_t)INT32_MIN);
    print_test_result("test_alu32_div_intmin_neg1", success);
    assert(success);
}

void test_alu32_mod_intmin_neg1() {
    std::cout << "--- Running Test: test_alu32_mod_intmin_neg1 ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = (uint64_t)(uint32_t)INT32_MIN;
    ebpf_vm->r(2) = (uint64_t)(uint32_t)(uint32_t)-1;
    bpf_insn instructions[] = {
        { BPF_ALU | BPF_MOD | BPF_X, 1, 2, 1, 0 },     // 32-bit signed mod INT32_MIN, -1 -> 0
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = ((uint32_t)ebpf_vm->r(1) == 0 && (uint32_t)ret == 0);
    print_test_result("test_alu32_mod_intmin_neg1", success);
    assert(success);
}

// --- r5 (RDX on x86) preservation test ---

void test_alu64_div_preserves_r5() {
    std::cout << "--- Running Test: test_alu64_div_preserves_r5 ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = 100;
    ebpf_vm->r(5) = 0xDEADBEEFCAFE1234ULL;  // r5 = RDX on x86
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_DIV | BPF_K, 1, 0, 0, 5 },   // div r1, 5
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 20 && ret == 20 &&
                    ebpf_vm->r(5) == 0xDEADBEEFCAFE1234ULL);
    print_test_result("test_alu64_div_preserves_r5", success);
    assert(success);
}

void test_alu64_mod_preserves_r5() {
    std::cout << "--- Running Test: test_alu64_mod_preserves_r5 ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = 100;
    ebpf_vm->r(5) = 0xDEADBEEFCAFE1234ULL;
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOD | BPF_K, 1, 0, 0, 7 },   // mod r1, 7
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 2 && ret == 2 &&
                    ebpf_vm->r(5) == 0xDEADBEEFCAFE1234ULL);
    print_test_result("test_alu64_mod_preserves_r5", success);
    assert(success);
}

// --- INT32_MIN power-of-2 optimization bug reproduction ---

void test_alu64_div_imm_intmin() {
    // imm = INT32_MIN (0x80000000) 是 2 的幂，会触发位移优化
    // 但无符号除法的实际除数是符号扩展后的 0xFFFFFFFF80000000
    // 正确: 0x100000000 / 0xFFFFFFFF80000000 = 0
    // Bug:  0x100000000 >> 31 = 2
    std::cout << "--- Running Test: test_alu64_div_imm_intmin ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = 0x100000000ULL;
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_DIV | BPF_K, 1, 0, 0, INT32_MIN },  // unsigned div r1, INT32_MIN
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 0 && ret == 0);
    print_test_result("test_alu64_div_imm_intmin", success);
    assert(success);
}

void test_alu64_mod_imm_intmin() {
    // MOD 的 2 的幂优化: and64_imm(imm - 1) = and64_imm(0x7FFFFFFF)
    // 正确: 0x100000000 % 0xFFFFFFFF80000000 = 0x100000000 (被除数 < 除数)
    // Bug:  0x100000000 & 0x7FFFFFFF = 0
    std::cout << "--- Running Test: test_alu64_mod_imm_intmin ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(1) = 0x100000000ULL;
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOD | BPF_K, 1, 0, 0, INT32_MIN },  // unsigned mod r1, INT32_MIN
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 0x100000000ULL && ret == 0x100000000ULL);
    print_test_result("test_alu64_mod_imm_intmin", success);
    assert(success);
}

void test_alu64_and_imm() {
    std::cout << "--- Running Test: test_alu64_and_imm ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0xF0F0 },  // mov r1, 0xF0F0
        { BPF_ALU64 | BPF_AND | BPF_K, 1, 0, 0, 0x0FF0 },  // and r1, 0x0FF0
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 0x00F0 && ret == 0x00F0);
    print_test_result("test_alu64_and_imm", success);
    assert(success);
}

void test_alu64_or_reg() {
    std::cout << "--- Running Test: test_alu64_or_reg ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0xF0F0 }, // mov r1, 0xF0F0
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0x0FF0 }, // mov r2, 0x0FF0
        { BPF_ALU64 | BPF_OR  | BPF_X, 1, 2, 0, 0 },      // or r1, r2
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 0xFFF0 && ret == 0xFFF0);
    print_test_result("test_alu64_or_reg", success);
    assert(success);
}


void test_alu64_lsh_imm() {
    std::cout << "--- Running Test: test_alu64_lsh_imm ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0x123 },// mov r1, 0x123
        { BPF_ALU64 | BPF_LSH | BPF_K, 1, 0, 0, 4 },    // lsh r1, 4
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == (0x123ULL << 4) && ret == (0x123ULL << 4));
    print_test_result("test_alu64_lsh_imm", success);
    assert(success);
}

void test_alu64_rsh_imm() {
    std::cout << "--- Running Test: test_alu64_rsh_imm ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0x1230 }, // mov r1, 0x1230
        { BPF_ALU64 | BPF_RSH | BPF_K, 1, 0, 0, 4 },      // rsh r1, 4 (logical)
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == (0x1230ULL >> 4) && ret == (0x1230ULL >> 4));
    print_test_result("test_alu64_rsh_imm", success);
    assert(success);
}

void test_alu64_arsh_imm() {
    std::cout << "--- Running Test: test_alu64_arsh_imm ---" << std::endl;
    auto ebpf_vm = vm::create();
    uint64_t val = 0xF000000000000000; // Negative number if treated as signed
    bpf_insn instructions[] = {
        { BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, (int32_t)(val & 0xFFFFFFFF) }, // mov r1, val (lower 32 bits)
        { 0, 0, 0, 0, (int32_t)(val >> 32) },                                // (upper 32 bits)
        { BPF_ALU64 | BPF_ARSH | BPF_K, 1, 0, 0, 4 },                        // arsh r1, 4 (arithmetic)
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    uint64_t expected = static_cast<uint64_t>((int64_t)val >> 4);
    bool success = (ebpf_vm->r(1) == expected && ret == expected);
    print_test_result("test_alu64_arsh_imm", success);
    assert(success);
}

void test_alu64_neg() {
    std::cout << "--- Running Test: test_alu64_neg ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 100 }, // mov r1, 100
        { BPF_ALU64 | BPF_NEG, 1, 0, 0, 0 },           // neg r1
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == (uint64_t)(-(int64_t)100) && ret == (uint64_t)(-(int64_t)100));
    print_test_result("test_alu64_neg", success);
    assert(success);
}

// --- Byte Swap Tests ---
void test_alu_end_le16() {
    std::cout << "--- Running Test: test_alu_end_le16 ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0x0102 }, // mov r1, 0x0102
        { BPF_ALU | BPF_END | BPF_K, 1, 0, 0, 16 },        // le16 r1 (zero-extend to 16 bits)
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    // LE on little-endian host: just zero-extend, so 0x0102 & 0xFFFF = 0x0102
    bool success = (ret == 0x0102);
    print_test_result("test_alu_end_le16", success);
    assert(success);
}

void test_alu_end_le32() {
    std::cout << "--- Running Test: test_alu_end_le32 ---" << std::endl;
    auto ebpf_vm = vm::create();
    uint64_t val = 0xAABBCCDD11223344ULL;
    bpf_insn instructions[] = {
        { BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, (int32_t)(val & 0xFFFFFFFF) },
        { 0, 0, 0, 0, (int32_t)(val >> 32) },
        { BPF_ALU | BPF_END | BPF_K, 1, 0, 0, 32 },        // le32 r1
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    // LE on little-endian host: zero-extend low 32 bits -> 0x11223344
    bool success = (ret == 0x11223344);
    print_test_result("test_alu_end_le32", success);
    assert(success);
}

void test_alu_end_le64() {
    std::cout << "--- Running Test: test_alu_end_le64 ---" << std::endl;
    auto ebpf_vm = vm::create();
    uint64_t val = 0x0102030405060708ULL;
    bpf_insn instructions[] = {
        { BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, (int32_t)(val & 0xFFFFFFFF) },
        { 0, 0, 0, 0, (int32_t)(val >> 32) },
        { BPF_ALU | BPF_END | BPF_K, 1, 0, 0, 64 },        // le64 r1 (no-op on LE host)
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ret == val);
    print_test_result("test_alu_end_le64", success);
    assert(success);
}

void test_alu_end_be16() {
    std::cout << "--- Running Test: test_alu_end_be16 ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0x0102 }, // mov r1, 0x0102
        { BPF_ALU | BPF_END | BPF_X, 1, 0, 0, 16 },        // be16 r1
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    // BE on little-endian host: bswap16(0x0102) = 0x0201
    bool success = (ret == 0x0201);
    print_test_result("test_alu_end_be16", success);
    assert(success);
}

// Regression test: BPF_ALU END BE16 with non-zero upper 16 bits.
// REV16 Wd, Wn swaps bytes in BOTH 16-bit halves. The JIT must mask
// the result to 16 bits (AND #0xFFFF). Without the mask, bits [31:16]
// contain the swapped upper half instead of zero.
// Input:  r1 = 0xAABBCCDD
// BE16:   should produce 0x000000000000DDCC (byte-swap lower 16 bits, zero-extend)
// Bug:    produces       0x00000000BB AADDCC (upper half also swapped, not cleared)
void test_alu_end_be16_upper_bits() {
    std::cout << "--- Running Test: test_alu_end_be16_upper_bits ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, (int32_t)0xAABBCCDD }, // mov r1, 0xAABBCCDD
        { BPF_ALU | BPF_END | BPF_X, 1, 0, 0, 16 },                     // be16 r1
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    // be16 takes lower 16 bits (0xCCDD), byte-swaps -> 0xDDCC, zero-extends to 64 bits
    bool success = (ret == 0xDDCC);
    print_test_result("test_alu_end_be16_upper_bits", success);
    assert(success);
}

void test_alu_end_be32() {
    std::cout << "--- Running Test: test_alu_end_be32 ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0x01020304 }, // mov r1, 0x01020304
        { BPF_ALU | BPF_END | BPF_X, 1, 0, 0, 32 },            // be32 r1
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    // BE on little-endian host: bswap32(0x01020304) = 0x04030201
    bool success = (ret == 0x04030201);
    print_test_result("test_alu_end_be32", success);
    assert(success);
}

void test_alu_end_be64() {
    std::cout << "--- Running Test: test_alu_end_be64 ---" << std::endl;
    auto ebpf_vm = vm::create();
    uint64_t val = 0x0102030405060708ULL;
    bpf_insn instructions[] = {
        { BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, (int32_t)(val & 0xFFFFFFFF) },
        { 0, 0, 0, 0, (int32_t)(val >> 32) },
        { BPF_ALU | BPF_END | BPF_X, 1, 0, 0, 64 },        // be64 r1
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    // bswap64(0x0102030405060708) = 0x0807060504030201
    bool success = (ret == 0x0807060504030201ULL);
    print_test_result("test_alu_end_be64", success);
    assert(success);
}

void test_alu64_end_bswap16() {
    std::cout << "--- Running Test: test_alu64_end_bswap16 ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0x0102 }, // mov r1, 0x0102
        { BPF_ALU64 | BPF_END | BPF_K, 1, 0, 0, 16 },      // bswap16 r1
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ret == 0x0201);
    print_test_result("test_alu64_end_bswap16", success);
    assert(success);
}

void test_alu64_end_bswap32() {
    std::cout << "--- Running Test: test_alu64_end_bswap32 ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0x01020304 }, // mov r1, 0x01020304
        { BPF_ALU64 | BPF_END | BPF_K, 1, 0, 0, 32 },          // bswap32 r1
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ret == 0x04030201);
    print_test_result("test_alu64_end_bswap32", success);
    assert(success);
}

void test_alu64_end_bswap64() {
    std::cout << "--- Running Test: test_alu64_end_bswap64 ---" << std::endl;
    auto ebpf_vm = vm::create();
    uint64_t val = 0x0102030405060708ULL;
    bpf_insn instructions[] = {
        { BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, (int32_t)(val & 0xFFFFFFFF) },
        { 0, 0, 0, 0, (int32_t)(val >> 32) },
        { BPF_ALU64 | BPF_END | BPF_K, 1, 0, 0, 64 },      // bswap64 r1
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ret == 0x0807060504030201ULL);
    print_test_result("test_alu64_end_bswap64", success);
    assert(success);
}

// --- ALU32 Tests ---
void test_alu32_add_imm() {
    std::cout << "--- Running Test: test_alu32_add_imm ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(2) = 0xFFFFFFFF000000AA; // Set r2 with high bits set
    bpf_insn instructions[] = {
        // r2 is pre-set
        { BPF_ALU | BPF_ADD | BPF_K, 2, 0, 0, 0x55 },  // add r2, 0x55 (32-bit) ; r2 = 0xAA + 0x55 = 0xFF
                                                       // High bits of r2 should be cleared
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 2, 0, 0 },   // mov r0, r2
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(2) == 0xFF && ret == 0xFF); // High bits cleared
    print_test_result("test_alu32_add_imm", success);
    assert(success);
}

void test_alu32_sub_reg() {
    std::cout << "--- Running Test: test_alu32_sub_reg ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(2) = 0xFFFFFFFF000000C8; // 200
    ebpf_vm->r(3) = 0x000000000000004B; // 75
    bpf_insn instructions[] = {
        { BPF_ALU | BPF_SUB | BPF_X, 2, 3, 0, 0 },   // sub r2, r3 (32-bit) ; r2 = 200 - 75 = 125
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 2, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(2) == 125 && ret == 125);
    print_test_result("test_alu32_sub_reg", success);
    assert(success);
}


void test_alu32_movsx8_reg() {
    std::cout << "--- Running Test: test_alu32_movsx8_reg ---" << std::endl;
    auto ebpf_vm = vm::create();
    // r2: high 32 bits set (dirty), low byte has bit 7 set (0x80 = negative in int8)
    ebpf_vm->r(2) = 0xFFFFFFFFABCDEF80ULL;
    bpf_insn instructions[] = {
        // movsx r1, r2 (8-bit): r1 = sign_extend_8_to_32((uint32_t)r2), upper 32 bits zero
        { BPF_ALU | BPF_MOV | BPF_X, 1, 2, 8, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    // 0x80 sign-extended to 32 bits = 0xFFFFFF80; upper 32 bits must be zero
    bool success = (ebpf_vm->r(1) == 0x00000000FFFFFF80ULL && ret == 0x00000000FFFFFF80ULL);
    print_test_result("test_alu32_movsx8_reg", success);
    assert(success);
}

void test_alu32_movsx16_reg() {
    std::cout << "--- Running Test: test_alu32_movsx16_reg ---" << std::endl;
    auto ebpf_vm = vm::create();
    // r2: high 32 bits set (dirty), low 16 bits have bit 15 set (0x8000 = negative in int16)
    ebpf_vm->r(2) = 0xFFFFFFFFABCD8000ULL;
    bpf_insn instructions[] = {
        // movsx r1, r2 (16-bit): r1 = sign_extend_16_to_32((uint32_t)r2), upper 32 bits zero
        { BPF_ALU | BPF_MOV | BPF_X, 1, 2, 16, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    // 0x8000 sign-extended to 32 bits = 0xFFFF8000; upper 32 bits must be zero
    bool success = (ebpf_vm->r(1) == 0x00000000FFFF8000ULL && ret == 0x00000000FFFF8000ULL);
    print_test_result("test_alu32_movsx16_reg", success);
    assert(success);
}

// Test: MOV32 X must not clobber the source register's upper 32 bits
void test_alu32_mov_reg_preserves_src() {
    std::cout << "--- Running Test: test_alu32_mov_reg_preserves_src ---" << std::endl;
    auto ebpf_vm = vm::create();
    // Pre-set r1 with a 64-bit value whose upper 32 bits are non-zero
    ebpf_vm->r(1) = 0xDEADBEEF12345678ULL;
    // Pre-set r2 with a different 64-bit value (will be overwritten)
    ebpf_vm->r(2) = 0xAAAAAAAABBBBBBBBULL;
    bpf_insn instructions[] = {
        // mov32 r2, r1  — should: r2 = zero_extend(low32(r1)) = 0x12345678
        //                  must NOT touch r1
        { BPF_ALU | BPF_MOV | BPF_X, 2, 1, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 2, 0, 0 },   // mov r0, r2 (return dst)
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);

    bool dst_ok = (ebpf_vm->r(2) == 0x12345678ULL);
    bool src_ok = (ebpf_vm->r(1) == 0xDEADBEEF12345678ULL);
    bool ret_ok = (ret == 0x12345678ULL);

    if (!dst_ok) fprintf(stderr, "  r2 expected 0x12345678, got 0x%lx\n", ebpf_vm->r(2));
    if (!src_ok) fprintf(stderr, "  r1 expected 0xDEADBEEF12345678, got 0x%lx (SOURCE CLOBBERED!)\n", ebpf_vm->r(1));

    bool success = dst_ok && src_ok && ret_ok;
    print_test_result("test_alu32_mov_reg_preserves_src", success);
    assert(success);
}

// --- JMP Tests ---
void test_jmp_ja() {
    std::cout << "--- Running Test: test_jmp_ja ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 10 }, // mov r1, 10
        { BPF_JMP | BPF_JA, 0, 0, 2, 0 },             // ja +2 (skip next 2 insns)
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 20 }, // Should be skipped
        { BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 5 },  // Should be skipped
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 100 },// Target of jump
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },  // r0 = r1 (should be 10)
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 10 && ebpf_vm->r(2) == 100 && ret == 10);
    print_test_result("test_jmp_ja", success);
    assert(success);
}

void test_jmp_jeq_imm_true() {
    std::cout << "--- Running Test: test_jmp_jeq_imm_true ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 50 }, // mov r1, 50
        { BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1, 50 },   // jeq r1, 50, +1 (jump to ADD)
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 100 },// Should be skipped if jump taken
        { BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 10 }, // r1 = r1 + 10 (target of jump)
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 60 && ret == 60); // 50 + 10
    print_test_result("test_jmp_jeq_imm_true", success);
    assert(success);
}

void test_jmp_jeq_imm_false() {
    std::cout << "--- Running Test: test_jmp_jeq_imm_false ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 50 }, // mov r1, 50
        { BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1, 55 },   // jeq r1, 55, +1 (no jump)
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 100 },// r2 = 100 (executed)
        { BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 10 }, // r1 = r1 + 10 (executed, not jumped over)
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 60 && ebpf_vm->r(2) == 100 && ret == 60); // 50+10
    print_test_result("test_jmp_jeq_imm_false", success);
    assert(success);
}

void test_jmp_jsgt_reg_true() {
    std::cout << "--- Running Test: test_jmp_jsgt_reg_true ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 100 }, // mov r1, 100
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 50 },  // mov r2, 50
        { BPF_JMP | BPF_JSGT | BPF_X, 1, 2, 1, 0 },    // jsgt r1, r2, +1 (jump)
        { BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, 999 }, // skipped
        { BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 5 },   // r1 += 5
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == 105 && ret == 105);
    print_test_result("test_jmp_jsgt_reg_true", success);
    assert(success);
}

void test_jmp_jslt_imm_false_signed() {
    std::cout << "--- Running Test: test_jmp_jslt_imm_false_signed ---" << std::endl;
    auto ebpf_vm = vm::create();
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, -5 }, // mov r1, -5
        { BPF_JMP | BPF_JSLT | BPF_K, 1, 0, 1, -10 }, // jslt r1 (signed -5), -10 (false)
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 111 },// r2 = 111 (executed)
        { BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 1 },  // r1 += 1 (-5 + 1 = -4)
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == (uint64_t)-4 && ebpf_vm->r(2) == 111 && ret == (uint64_t)-4);
    print_test_result("test_jmp_jslt_imm_false_signed", success);
    assert(success);
}


// --- JMP32 Tests ---
void test_jmp32_jeq_imm_true() {
    std::cout << "--- Running Test: test_jmp32_jeq_imm_true ---" << std::endl;
    auto ebpf_vm = vm::create();
    ebpf_vm->r(2) = 0xFFFFFFFF000A000A; // r2 = 0xA000A (high bits will be ignored by jmp32)
    bpf_insn instructions[] = {
        { BPF_JMP32 | BPF_JEQ | BPF_K, 2, 0, 1, 0x000A000A }, // jeq (u32)r2, 0xA000A, +1
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 100 },        // skipped
        { BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, 1 },          // r2 = r2 + 1
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 2, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(2) == 0xFFFFFFFF000A000B && ret == 0xFFFFFFFF000A000B);
    print_test_result("test_jmp32_jeq_imm_true", success);
    assert(success);
}

// --- Load/Store Tests ---
void test_ldx_stx_stack() {
    std::cout << "--- Running Test: test_ldx_stx_stack ---" << std::endl;
    auto ebpf_vm = vm::create();
    uint64_t val_to_store = 0xABCDEF0123456789;
    bpf_insn instructions[] = {
        // Store a 64-bit value onto the stack
        { BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, (int32_t)(val_to_store & 0xFFFFFFFF) },
        { 0, 0, 0, 0, (int32_t)(val_to_store >> 32) },
        { BPF_STX | BPF_MEM | BPF_DW, 10, 1, -8, 0 }, // *(u64 *)(r10 - 8) = r1

        // Store a 32-bit value
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, (int32_t)0xCAFEBABE }, // mov r2, 0xCAFEBABE
        { BPF_STX | BPF_MEM | BPF_W, 10, 2, -12, 0 }, // *(u32 *)(r10 - 12) = r2

        // Load the 64-bit value back
        { BPF_LDX | BPF_MEM | BPF_DW, 3, 10, -8, 0 }, // r3 = *(u64 *)(r10 - 8)

        // Load the 32-bit value back (zero-extended to 64-bit)
        { BPF_LDX | BPF_MEM | BPF_W, 4, 10, -12, 0 }, // r4 = *(u32 *)(r10 - 12)

        // Store immediate byte
        { BPF_ST | BPF_MEM | BPF_B, 10, 0, -13, 0xEE },// *(u8 *)(r10 - 13) = 0xEE
        // Load immediate byte
        { BPF_LDX | BPF_MEM | BPF_B, 5, 10, -13, 0 },  // r5 = *(u8 *)(r10 - 13)


        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 3, 0, 0 },   // r0 = r3 (for checking the 64-bit value)
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);

    bool success = (ret == val_to_store &&
                    ebpf_vm->r(3) == val_to_store &&
                    ebpf_vm->r(4) == 0xCAFEBABE && // Loaded 32-bit, zero extended
                    ebpf_vm->r(5) == 0xEE);
    print_test_result("test_ldx_stx_stack", success);
    assert(success);
}

// --- Load Immediate 64-bit ---
void test_ld_imm64() {
    std::cout << "--- Running Test: test_ld_imm64 ---" << std::endl;
    auto ebpf_vm = vm::create();
    uint64_t immediate_val = 0x11223344AABBCCDD;
    bpf_insn instructions[] = {
        { BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, (int32_t)(immediate_val & 0xFFFFFFFF) }, // lddw r1, immediate_val (low 32 bits)
        { 0, 0, 0, 0, (int32_t)(immediate_val >> 32) },                                // (high 32 bits)
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);
    bool success = (ebpf_vm->r(1) == immediate_val && ret == immediate_val);
    print_test_result("test_ld_imm64", success);
    assert(success);
}


void test_call_relative() {
    std::cout << "--- Running Test: test_call_relative ---" << std::endl;
    auto ebpf_vm = vm::create();

    // Main function code
    bpf_insn main_instructions[] = {
        // Main func: insn 0, 1 (CALL), 2, 3, 4 (EXIT)
        // Helper func starts at insn 5
        // CALL at insn 1. Target is insn 5. Offset = 5 - (1+1) = 3.
        // The immediate in BPF_CALL (src_reg=1) is relative to PC of *next* instruction.
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 10 }, // main: mov r1, 10 (pc=0)
        { BPF_JMP | BPF_CALL, 0, 1, 0, 3 },           // main: call +3 (pc=1) -> target is pc+1+3 = 5
        { BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 100}, // main: r1 += 100 (after call) (pc=2)
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },  // main: mov r0, r1 (pc=3)
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 },           // main: exit (pc=4)
        // helper_start: (at index 5 from start of this combined block)
        { BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 5 },  // helper: add r1, 5 (pc=5)
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }            // helper: return (pc=6)
    };

    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, main_instructions, sizeof(main_instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option); // Main starts at 0x1000

    // Expected: r1 = 10 (initial) -> helper adds 5 (r1=15) -> returns -> main adds 100 (r1=115)
    bool success = (ebpf_vm->r(1) == 115 && ret == 115);
    print_test_result("test_call_relative", success);
    assert(success);
}


void test_call_pseudo_func() {
    std::cout << "--- Running Test: test_call_pseudo_func ---" << std::endl;
    auto ebpf_vm = vm::create();
    uint64_t helper_paddr = 0x2000;

    // Main function code
    bpf_insn main_instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 20 },  // mov r1, 20 (arg for helper)
        // For BPF_CALL | BPF_X, dst_reg contains the target address.
        // We need to load helper_paddr into a register, say r6.
        // This requires a 64-bit immediate load (lddw).
        { BPF_LD | BPF_IMM | BPF_DW, 6, 0, 0, (int32_t)(helper_paddr & 0xFFFFFFFF) },
        { 0, 0, 0, 0, (int32_t)(helper_paddr >> 32) },
        // Now r6 holds helper_paddr
        { BPF_JMP | BPF_CALL | BPF_X, 6, 0, 0, 0 },    // call r6 (dst_reg is 6, src_reg is ignored)
        { BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 200},  // r1 += 200 (after call returns)
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },   // mov r0, r1
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }             // exit from main
    };

    // Simple helper function (add 5 to r1)
    bpf_insn helper_func_code[] = {
        { BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 5 }, // add r1, 5
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }           // return from helper (effectively BPF_JA to caller's pc+1)
    };

    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, main_instructions, sizeof(main_instructions) / sizeof(bpf_insn)); assert(ok); } // Loads at 0x1000
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, helper_func_code, sizeof(helper_func_code) / sizeof(bpf_insn), helper_paddr); assert(ok); }

    uint64_t ret = ebpf_vm->run(&option); // Main starts at 0x1000

    // Expected: r1 = 20 (initial) -> helper adds 5 (r1=25) -> returns -> main adds 200 (r1=225)
    bool success = (ebpf_vm->r(1) == 225 && ret == 225);
    print_test_result("test_call_pseudo_func", success);
    assert(success);
}

// Test: BPF_CALL | BPF_X with r5 as target register.
// This catches a JIT bug where emit_call_indirect loads the target addr
// into RDX (which is mapped to BPF r5), then flush_to_vm() writes that
// clobbered RDX back into vm->reg[5], corrupting r5's original value.
// The callee reads r5 via vm->reg[5], so if the flush overwrote it with
// the call target address, the callee will see the wrong value.
void test_call_indirect_r5() {
    std::cout << "--- Running Test: test_call_indirect_r5 ---" << std::endl;
    auto ebpf_vm = vm::create();
    uint64_t helper_paddr = 0x2000;

    // Main: set r1=100, r5=42, load helper addr into r5... wait—
    // We need r5 to hold both the call target AND a meaningful value
    // that the callee should NOT see. The bug is: when dst_reg != 5,
    // load_bpf(dst_reg, RDX) clobbers r5. So use a different register
    // (e.g., r3) as the call target, and set r5 to a known value that
    // the callee should be able to read correctly.
    //
    // Scenario: r5 = 42, r3 = helper_paddr, call r3.
    // The callee adds r5 to r1 and returns. If r5 was clobbered to
    // helper_paddr by the JIT bug, the result will be wrong.

    bpf_insn main_instructions[] = {
        // r1 = 100
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 100 },
        // r5 = 42
        { BPF_ALU64 | BPF_MOV | BPF_K, 5, 0, 0, 42 },
        // r3 = helper_paddr (lddw)
        { BPF_LD | BPF_IMM | BPF_DW, 3, 0, 0, (int32_t)(helper_paddr & 0xFFFFFFFF) },
        { 0, 0, 0, 0, (int32_t)(helper_paddr >> 32) },
        // call r3 (indirect call, dst_reg=3)
        { BPF_JMP | BPF_CALL | BPF_X, 3, 0, 0, 0 },
        // After return: r0 should be r1+r5 = 100+42 = 142 (set by callee)
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    // Callee: r0 = r1 + r5, then exit
    bpf_insn helper_func_code[] = {
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0 },   // mov r0, r1
        { BPF_ALU64 | BPF_ADD | BPF_X, 0, 5, 0, 0 },   // add r0, r5
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, main_instructions, sizeof(main_instructions) / sizeof(bpf_insn)); assert(ok); }
    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, helper_func_code, sizeof(helper_func_code) / sizeof(bpf_insn), helper_paddr); assert(ok); }

    uint64_t ret = ebpf_vm->run(&option);

    // Expected: 100 + 42 = 142
    // Bug would produce: 100 + 0x2000 = 8292 (r5 clobbered to helper_paddr)
    bool success = (ret == 142);
    if (!success) {
        fprintf(stderr, "  expected 142, got %lu (r5 may have been clobbered to call target)\n", ret);
    }
    print_test_result("test_call_indirect_r5", success);
    assert(success);
}

void test_syscall_clock_gettime() {
    std::cout << "--- Running Test: test_syscall_clock_gettime ---" << std::endl;
    auto ebpf_vm = vm::create();
    unsigned char* data = nullptr;
    uint64_t data_paddr = 0x3000;
    size_t data_size = 128;
    { [[maybe_unused]] bool ok = add_data_mem(*ebpf_vm, data_paddr, data_size, &data); assert(ok); }
    memset(data, 0, data_size);

    uint64_t tp_addr = data_paddr;
    bpf_insn instructions[] = {
        { BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, (int32_t)CLOCK_REALTIME },
        { 0, 0, 0, 0, 0 },
        { BPF_LD | BPF_IMM | BPF_DW, 2, 0, 0, (int32_t)(tp_addr & 0xFFFFFFFF) },
        { 0, 0, 0, 0, (int32_t)(tp_addr >> 32) },
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_CLOCK_GETTIME },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&posix_option);
    struct timespec* tp = (struct timespec*)data;
    bool success = (ret == 0 && tp->tv_sec > 0);
    print_test_result("test_syscall_clock_gettime", success);
    assert(success);
}

void test_syscall_mmap_readonly_rejects_write() {
    std::cout << "--- Running Test: test_syscall_mmap_readonly_rejects_write ---" << std::endl;
    auto ebpf_vm = vm::create();
    const uint64_t map_size = 4096;
    const uint32_t write_value = 0x12345678;
    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, 0},
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, (int32_t)map_size },
        { BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, PROT_READ },
        { BPF_ALU64 | BPF_MOV | BPF_K, 4, 0, 0, MAP_PRIVATE | MAP_ANONYMOUS },
        { BPF_ALU64 | BPF_MOV | BPF_K, 5, 0, 0, -1 },
        { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0 },
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_MMAP },
        { BPF_ALU64 | BPF_MOV | BPF_X, 6, 0, 0, 0 },
        { BPF_ST | BPF_MEM | BPF_W, 6, 0, 0, (int32_t)write_value },
        { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&posix_option);
    uint64_t mapped_addr = ebpf_vm->r(6);
    auto mapped = static_cast<const uint32_t*>(ebpf_vm->mmu(mapped_addr, sizeof(uint32_t)));
    bool success = (mapped_addr != 0 &&
                    mapped != nullptr &&
                    ret == 137 &&
                    *mapped == 0);
    print_test_result("test_syscall_mmap_readonly_rejects_write", success);
    assert(success);
}

void test_syscall_mmap_map_fixed() {
    std::cout << "--- Running Test: test_syscall_mmap_map_fixed ---" << std::endl;
    auto ebpf_vm = vm::create();
    // 选一个不与栈(0x10000000)/加载基址(0x40000000)冲突的页对齐固定地址。
    const uint64_t fixed_addr = 0x50000000;
    const uint64_t map_size = 4096;
    const uint32_t magic = 0xCAFEBABE;
    // mmap(fixed_addr, map_size, RW, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0)
    bpf_insn instructions[] = {
        { BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, (int32_t)(fixed_addr & 0xFFFFFFFF) },
        { 0, 0, 0, 0, (int32_t)(fixed_addr >> 32) },
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, (int32_t)map_size },
        { BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, PROT_READ | PROT_WRITE },
        { BPF_ALU64 | BPF_MOV | BPF_K, 4, 0, 0, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED },
        { BPF_ALU64 | BPF_MOV | BPF_K, 5, 0, 0, -1 },
        { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0 },
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_MMAP },
        // mmap 返回值在 r0。用 r1 暂存返回地址（r1 在顶层 exit 不被恢复，可安全作中转），
        // 写入 magic 再读回，验证地址正确且可写可读。最后 r0 = 读回的值，exit 返回它。
        { BPF_ALU64 | BPF_MOV | BPF_X, 1, 0, 0, 0 },   // r1 = r0 (mapped addr)
        { BPF_ST | BPF_MEM | BPF_W, 1, 0, 0, (int32_t)magic },  // *(u32*)(r1+0) = magic
        { BPF_LDX | BPF_MEM | BPF_W, 0, 1, 0, 0 },     // r0 = *(u32*)(r1+0)
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&posix_option);
    uint64_t mapped_addr = ebpf_vm->r(1);
    auto mapped = static_cast<const uint32_t*>(ebpf_vm->mmu(mapped_addr, sizeof(uint32_t)));
    // ret == magic 验证「写入 + 读回」成功；mapped_addr == fixed_addr 验证 MAP_FIXED 生效。
    bool success = (ret == magic &&
                    mapped_addr == fixed_addr &&
                    mapped != nullptr &&
                    *mapped == magic);
    print_test_result("test_syscall_mmap_map_fixed", success);
    assert(success);
}

void test_static_memmap_does_not_unmap_external_memory() {
    std::cout << "--- Running Test: test_static_memmap_does_not_unmap_external_memory ---" << std::endl;
    long page_size = sysconf(_SC_PAGESIZE);
    assert(page_size > 0);
    void* external = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(external != MAP_FAILED);

    {
        auto ebpf_vm = vm::create();
        ebpf_vm->addmem(memmap::static_map(external, page_size, 0x9000));
    }

    int rc = munmap(external, page_size);
    bool success = (rc == 0);
    print_test_result("test_static_memmap_does_not_unmap_external_memory", success);
    assert(success);
}

void test_syscall_file_io() {
    std::cout << "--- Running Test: test_syscall_file_io ---" << std::endl;
    auto ebpf_vm = vm::create();
    unsigned char* data = nullptr;
    uint64_t data_paddr = 0x4000;
    size_t data_size = 256;
    { [[maybe_unused]] bool ok = add_data_mem(*ebpf_vm, data_paddr, data_size, &data); assert(ok); }
    memset(data, 0, data_size);

    char path[128];
    snprintf(path, sizeof(path), "bpfvm_syscall_test_%d.txt", getpid());
    unlink(path);

    size_t path_len = strlen(path) + 1;
    uint64_t path_addr = data_paddr;
    memcpy(data, path, path_len);

    const char* payload = "hello";
    size_t payload_len = strlen(payload);
    uint64_t write_buf_addr = data_paddr + 64;
    uint64_t read_buf_addr = data_paddr + 96;
    memcpy(data + 64, payload, payload_len);

    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, (int32_t)AT_FDCWD },
        { BPF_LD | BPF_IMM | BPF_DW, 2, 0, 0, (int32_t)(path_addr & 0xFFFFFFFF) },
        { 0, 0, 0, 0, (int32_t)(path_addr >> 32) },
        { BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, O_CREAT | O_TRUNC | O_RDWR },
        { BPF_ALU64 | BPF_MOV | BPF_K, 4, 0, 0, 0644 },
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_OPENAT },
        { BPF_ALU64 | BPF_MOV | BPF_X, 6, 0, 0, 0 }, // r6 = fd

        { BPF_LD | BPF_IMM | BPF_DW, 2, 0, 0, (int32_t)(write_buf_addr & 0xFFFFFFFF) },
        { 0, 0, 0, 0, (int32_t)(write_buf_addr >> 32) },
        { BPF_ALU64 | BPF_MOV | BPF_X, 1, 6, 0, 0 }, // r1 = fd
        { BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, (int)payload_len },
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_WRITE },
        { BPF_ALU64 | BPF_MOV | BPF_X, 7, 0, 0, 0 }, // r7 = write rc

        { BPF_ALU64 | BPF_MOV | BPF_X, 1, 6, 0, 0 }, // r1 = fd
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, 0 }, // SEEK_SET
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_LSEEK },

        { BPF_LD | BPF_IMM | BPF_DW, 2, 0, 0, (int32_t)(read_buf_addr & 0xFFFFFFFF) },
        { 0, 0, 0, 0, (int32_t)(read_buf_addr >> 32) },
        { BPF_ALU64 | BPF_MOV | BPF_X, 1, 6, 0, 0 }, // r1 = fd
        { BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, (int)payload_len },
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_READ },
        { BPF_ALU64 | BPF_MOV | BPF_X, 8, 0, 0, 0 }, // r8 = read rc

        { BPF_ALU64 | BPF_MOV | BPF_X, 1, 6, 0, 0 }, // r1 = fd
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_CLOSE },
        { BPF_ALU64 | BPF_MOV | BPF_X, 5, 0, 0, 0 }, // r5 = close rc

        { BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, (int32_t)(path_addr & 0xFFFFFFFF) },
        { 0, 0, 0, 0, (int32_t)(path_addr >> 32) },
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, (int32_t)AT_FDCWD },
        { BPF_ALU64 | BPF_MOV | BPF_X, 3, 1, 0, 0 }, // r3 = path_addr
        { BPF_ALU64 | BPF_MOV | BPF_X, 1, 2, 0, 0 }, // r1 = AT_FDCWD
        { BPF_ALU64 | BPF_MOV | BPF_X, 2, 3, 0, 0 }, // r2 = path_addr
        { BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, 0 }, // flags = 0
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_UNLINKAT },
        { BPF_ALU64 | BPF_MOV | BPF_X, 9, 0, 0, 0 }, // r9 = unlink rc

        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 8, 0, 0 }, // r0 = read rc
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&posix_option);
    bool unlinked = (access(path, F_OK) == -1 && errno == ENOENT);
    bool success = (ret == payload_len &&
                    memcmp(data + 96, payload, payload_len) == 0 &&
                    unlinked);
    if(!success) {
        std::cout << "  debug: ret=" << (long long)ret
                  << " fd=" << (long long)ebpf_vm->r(6)
                  << " write_rc=" << (long long)ebpf_vm->r(7)
                  << " read_rc=" << (long long)ebpf_vm->r(8)
                  << " close_rc=" << (long long)ebpf_vm->r(5)
                  << " unlink_rc=" << (long long)ebpf_vm->r(9)
                  << " unlinked=" << unlinked
                  << " read_buf=\"" << std::string((char*)(data + 96), payload_len) << "\""
                  << std::endl;
    }
    print_test_result("test_syscall_file_io", success);
    assert(success);
}

void test_syscall_fork_waitpid() {
    std::cout << "--- Running Test: test_syscall_fork_waitpid ---" << std::endl;
    auto ebpf_vm = vm::create();

    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_X, 1, 0, 0, SIGCHLD },
        { BPF_ALU64 | BPF_MOV | BPF_X, 2, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_X, 3, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_X, 4, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_X, 5, 0, 0, 0 },
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_CLONE },          // r0 = pid (parent) or 0 (child)
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 8, 0 },               // if r0 == 0 jump to child
        { BPF_ALU64 | BPF_MOV | BPF_X, 6, 0, 0, 0 },             // r6 = child pid
        { BPF_ALU64 | BPF_MOV | BPF_X, 1, 6, 0, 0 },             // r1 = pid
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0 },             // r2 = status = NULL
        { BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, 0 },             // r3 = options = 0
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_WAIT4 },         // r0 = waited pid
        { BPF_JMP | BPF_JNE | BPF_X, 0, 6, 4, 0 },               // if r0 != r6 jump to fail
        { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1 },             // success
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 11 },            // child: return 11
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0 },             // fail
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&posix_option);
    bool success = (ret == 1);
    print_test_result("test_syscall_fork_waitpid", success);
    assert(success);
}

void test_syscall_waitpid_self() {
    std::cout << "--- Running Test: test_syscall_waitpid_self ---" << std::endl;
    auto ebpf_vm = vm::create();

    bpf_insn instructions[] = {
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_GETPID },         // r0 = pid
        { BPF_ALU64 | BPF_MOV | BPF_X, 1, 0, 0, 0 },              // r1 = pid (self)
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0 },              // r2 = status = NULL
        { BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, 0 },              // r3 = options = 0
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_WAIT4 },          // r0 = -EINVAL
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2, -EINVAL },          // if r0 == -EINVAL jump to success
        { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0 },              // fail
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1 },              // success
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&posix_option);
    bool success = (ret == 1);
    print_test_result("test_syscall_waitpid_self", success);
    assert(success);
}

void test_syscall_waitpid_any_twice() {
    std::cout << "--- Running Test: test_syscall_waitpid_any_twice ---" << std::endl;
    auto ebpf_vm = vm::create();

    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_X, 1, 0, 0, SIGCHLD },
        { BPF_ALU64 | BPF_MOV | BPF_X, 2, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_X, 3, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_X, 4, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_X, 5, 0, 0, 0 },
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_CLONE },          // r0 = pid (parent) or 0 (child)
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 10, 0 },              // if r0 == 0 jump to child
        { BPF_ALU64 | BPF_MOV | BPF_X, 6, 0, 0, 0 },             // r6 = child pid
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, -1 },            // r1 = -1 (any child)
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0 },             // r2 = status = NULL
        { BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, 0 },             // r3 = options = 0
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_WAIT4 },         // r0 = waited pid (first)
        { BPF_JMP | BPF_JNE | BPF_X, 0, 6, 6, 0 },               // if r0 != r6 jump to fail
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, -1 },            // r1 = -1 (any child)
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0 },             // r2 = status = NULL
        { BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, 0 },             // r3 = options = 0
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_WAIT4 },         // r0 = -ECHILD (second)
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2, -ECHILD },         // if r0 == -ECHILD jump to success
        { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0 },             // fail
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1 },             // success
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 11 },            // child: return 11
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&posix_option);
    bool success = (ret == 1);
    print_test_result("test_syscall_waitpid_any_twice", success);
    assert(success);
}

void test_syscall_waitpid_any_no_child_wnohang() {
    std::cout << "--- Running Test: test_syscall_waitpid_any_no_child_wnohang ---" << std::endl;
    auto ebpf_vm = vm::create();

    bpf_insn instructions[] = {
        { BPF_ALU64 | BPF_MOV | BPF_K, 1, 0, 0, -1 },            // r1 = -1 (any child)
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0 },             // r2 = status = NULL
        { BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, WNOHANG },       // r3 = options = WNOHANG
        { BPF_JMP | BPF_CALL, 0, 0, 0, BPF_CALL_WAIT4 },         // r0 = -ECHILD (no children)
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2, -ECHILD },         // if r0 == -ECHILD jump to success
        { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0 },             // fail
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 1 },             // success
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&posix_option);
    bool success = (ret == 1);
    print_test_result("test_syscall_waitpid_any_no_child_wnohang", success);
    assert(success);
}


// Test atomic64 OR with FETCH:
// Memory = 0xFF00, r2 = 0x0F0F -> mem becomes 0xFF0F, r2 gets old value 0xFF00
void test_atomic64_or_fetch() {
    std::cout << "--- Running Test: test_atomic64_or_fetch ---" << std::endl;
    auto ebpf_vm = vm::create();
    unsigned char* data_mem = nullptr;
    add_data_mem(*ebpf_vm, 0x2000, 16, &data_mem);

    *(uint64_t*)data_mem = 0xFF00;

    bpf_insn instructions[] = {
        { BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, 0x2000 },
        { 0, 0, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0x0F0F },
        { BPF_STX | BPF_ATOMIC | BPF_DW, 1, 2, 0, BPF_OR | BPF_FETCH },
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 2, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);

    bool success = (ret == 0xFF00) && (*(uint64_t*)data_mem == 0xFF0F);
    if (!success) {
        fprintf(stderr, "  FAIL: ret=0x%lx (expected 0xFF00), mem=0x%lx (expected 0xFF0F)\n",
                ret, *(uint64_t*)data_mem);
    }
    print_test_result("test_atomic64_or_fetch", success);
    assert(success);
}

// Test atomic64 AND with FETCH:
// Memory = 0xFF0F, r2 = 0x0FFF -> mem becomes 0x0F0F, r2 gets old value 0xFF0F
void test_atomic64_and_fetch() {
    std::cout << "--- Running Test: test_atomic64_and_fetch ---" << std::endl;
    auto ebpf_vm = vm::create();
    unsigned char* data_mem = nullptr;
    add_data_mem(*ebpf_vm, 0x2000, 16, &data_mem);

    *(uint64_t*)data_mem = 0xFF0F;

    bpf_insn instructions[] = {
        { BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, 0x2000 },
        { 0, 0, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0x0FFF },
        { BPF_STX | BPF_ATOMIC | BPF_DW, 1, 2, 0, BPF_AND | BPF_FETCH },
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 2, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);

    bool success = (ret == 0xFF0F) && (*(uint64_t*)data_mem == 0x0F0F);
    if (!success) {
        fprintf(stderr, "  FAIL: ret=0x%lx (expected 0xFF0F), mem=0x%lx (expected 0x0F0F)\n",
                ret, *(uint64_t*)data_mem);
    }
    print_test_result("test_atomic64_and_fetch", success);
    assert(success);
}

// Test atomic64 XOR with FETCH:
// Memory = 0xFF00, r2 = 0x0FF0 -> mem becomes 0xF0F0, r2 gets old value 0xFF00
void test_atomic64_xor_fetch() {
    std::cout << "--- Running Test: test_atomic64_xor_fetch ---" << std::endl;
    auto ebpf_vm = vm::create();
    unsigned char* data_mem = nullptr;
    add_data_mem(*ebpf_vm, 0x2000, 16, &data_mem);

    *(uint64_t*)data_mem = 0xFF00;

    bpf_insn instructions[] = {
        { BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, 0x2000 },
        { 0, 0, 0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_K, 2, 0, 0, 0x0FF0 },
        { BPF_STX | BPF_ATOMIC | BPF_DW, 1, 2, 0, BPF_XOR | BPF_FETCH },
        { BPF_ALU64 | BPF_MOV | BPF_X, 0, 2, 0, 0 },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };

    { [[maybe_unused]] bool ok = load_program_to_vm(ebpf_vm, instructions, sizeof(instructions) / sizeof(bpf_insn)); assert(ok); }
    uint64_t ret = ebpf_vm->run(&option);

    bool success = (ret == 0xFF00) && (*(uint64_t*)data_mem == 0xF0F0);
    if (!success) {
        fprintf(stderr, "  FAIL: ret=0x%lx (expected 0xFF00), mem=0x%lx (expected 0xF0F0)\n",
                ret, *(uint64_t*)data_mem);
    }
    print_test_result("test_atomic64_xor_fetch", success);
    assert(success);
}

int main() {
    std::cout << "Starting eBPF VM Tests..." << std::endl;
    setenv("BPF_TEST_NO_CLEAN_MMAP", "1", 1);

    // PosixSyscall 契约：跨线程/跨 vm 投递信号（fork 子退出给父投 SIGCHLD、queue_signal
    // 唤醒阻塞线程等）会用 pthread_kill(tid, SIGUSR1) 打断目标线程。SIGUSR1 默认动作是
    // 终止进程，故宿主程序必须为其设空 handler（bpfvm main.cpp 已设）。本测试跑
    // fork/clone/signal 用例，同样必须设，否则子进程退出投 SIGCHLD 时 SIGUSR1 会杀掉
    // 整个测试进程。
    struct sigaction sa{};
    sa.sa_handler = [](int){};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, nullptr);

    // ALU64 Tests
    test_alu64_add_imm();
    test_alu64_sub_reg();
    test_alu64_mul_imm();
    test_alu64_div_imm();
    test_alu64_div_by_zero_imm();
    test_alu64_mod_imm();
    test_alu64_mod_by_zero_imm();
    test_alu64_div_reg();
    test_alu64_mod_reg();
    test_alu64_div_by_zero_reg();
    test_alu64_mod_by_zero_reg();
    test_alu64_div_signed_reg();
    test_alu64_mod_signed_reg();
    test_alu64_div_signed_by_zero_reg();
    test_alu64_mod_signed_by_zero_reg();
    test_alu64_div_intmin_neg1();
    test_alu64_mod_intmin_neg1();
    test_alu32_div_intmin_neg1();
    test_alu32_mod_intmin_neg1();
    test_alu64_div_preserves_r5();
    test_alu64_mod_preserves_r5();
    test_alu64_div_imm_intmin();
    test_alu64_mod_imm_intmin();
    test_alu64_and_imm();
    test_alu64_or_reg();
    test_alu64_lsh_imm();
    test_alu64_rsh_imm();
    test_alu64_arsh_imm();
    test_alu64_neg();

    // Byte Swap Tests (ALU LE/BE, ALU64 bswap)
    test_alu_end_le16();
    test_alu_end_le32();
    test_alu_end_le64();
    test_alu_end_be16();
    test_alu_end_be16_upper_bits();  // AArch64 JIT bug: REV16 must clear upper 16 bits
    test_alu_end_be32();
    test_alu_end_be64();
    test_alu64_end_bswap16();
    test_alu64_end_bswap32();
    test_alu64_end_bswap64();

    // ALU32 Tests
    test_alu32_add_imm();
    test_alu32_sub_reg();
    test_alu32_movsx8_reg();
    test_alu32_movsx16_reg();
    test_alu32_mov_reg_preserves_src();

    // JMP Tests
    test_jmp_ja();
    test_jmp_jeq_imm_true();
    test_jmp_jeq_imm_false();
    test_jmp_jsgt_reg_true();
    test_jmp_jslt_imm_false_signed();

    // JMP32 Tests
    test_jmp32_jeq_imm_true();

    // Load/Store Tests
    test_ldx_stx_stack();

    // Load Immediate 64-bit
    test_ld_imm64();

    // Function Call Tests
    test_call_relative();
    test_call_pseudo_func();
    test_call_indirect_r5();

    // Syscall Tests
    test_syscall_clock_gettime();
    test_syscall_mmap_readonly_rejects_write();
    test_syscall_mmap_map_fixed();
    test_static_memmap_does_not_unmap_external_memory();
    test_syscall_file_io();
    test_syscall_fork_waitpid();
    test_syscall_waitpid_self();
    test_syscall_waitpid_any_twice();
    test_syscall_waitpid_any_no_child_wnohang();

    // Atomic FETCH OR/AND/XOR Tests
    test_atomic64_or_fetch();
    test_atomic64_and_fetch();
    test_atomic64_xor_fetch();

    std::cout << "All eBPF VM Tests completed." << std::endl;
    return 0;
}
