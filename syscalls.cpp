//
// Created by chouryzhou on 24-10-28.
//

#include "insn.h"
#include "bpf_call.h"

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>

bool vm::do_syscall(uint32_t call) {
    switch (call) {
    case BPF_CALL_MMAP:
        return do_mmap();
    case BPF_CALL_MUNMAP:
        return do_munmap();
    case BPF_CALL_EXIT:
        return do_exit();
    case BPF_CALL_GETTIMEOFDAY:
        return do_gettimeofday();
    case BPF_CALL_OPEN:
        return do_open();
    case BPF_CALL_READ:
        return do_read();
    case BPF_CALL_WRITE:
        return do_write();
    case BPF_CALL_LSEEK:
        return do_lseek();
    case BPF_CALL_CLOSE:
        return do_close();
    case BPF_CALL_UNLINK:
        return do_unlink();
    case BPF_CALL_RENAMEAT:
        return do_renameat();
    case BPF_CALL_READLINK:
        return do_readlink();
    case BPF_CALL_EXECVE:
        return do_execve();
    default:
        fprintf(stderr, "unsupported func: 0x%x\n", call);
        r(0) = -ENOSYS;
        return true;
    }
}

bool vm::do_mmap() {
    void* addr = mmap(nullptr, r(1), r(2), r(3), r(4), r(5));
    if(addr == MAP_FAILED) {
        r(0) = -errno;
        return true;
    }
    memmap mem;
    mem.data = (unsigned char*)addr;
    mem.paddr = maps.back().paddr + maps.back().size;
    mem.flags = r(3);
    mem.size = r(1);
    r(0) = mem.paddr;
    addmem(std::move(mem));
    return true;
}

bool vm::do_munmap() {
    auto addr = unmap(r(1));
    if(addr == nullptr) {
        r(0) = -EINVAL;
        return true;
    }
    if(munmap(addr, r(2)) == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = 0;
    return true;
}

bool vm::do_exit() {
    r(0) = r(1);
    return false;
}

bool vm::do_gettimeofday() {
    struct timeval* tv = (struct timeval*)mmu(r(1));
    struct timezone* tz = (struct timezone*)mmu(r(2));
    if(gettimeofday(tv, tz) == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = 0;
    return true;
}

bool vm::do_open() {
    std::string path;
    if(!read_c_string(r(1), path, 4096)) {
        r(0) = -EFAULT;
        return true;
    }
    int fd = open(path.c_str(), r(2), r(3));
    if(fd == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = fd;
    return true;
}

bool vm::do_read() {
    int rc = read(r(1), mmu(r(2)), r(3));
    if(rc == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = rc;
    return true;
}

bool vm::do_write() {
    int rc = write(r(1), mmu(r(2)), r(3));
    if(rc == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = rc;
    return true;
}

bool vm::do_lseek() {
    int rc = lseek64(r(1), r(2), r(3));
    if(rc == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = rc;
    return true;
}

bool vm::do_close() {
    int rc = close(r(1));
    if(rc == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = 0;
    return true;
}

bool vm::do_unlink() {
    std::string path;
    if(!read_c_string(r(1), path, 4096)) {
        r(0) = -EFAULT;
        return true;
    }
    int rc = unlink(path.c_str());
    if(rc == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = 0;
    return true;
}

bool vm::do_renameat() {
    std::string old_path;
    std::string new_path;
    if(!read_c_string(r(2), old_path, 4096) || !read_c_string(r(4), new_path, 4096)) {
        r(0) = -EFAULT;
        return true;
    }
    int rc = renameat(r(1), old_path.c_str(), r(3), new_path.c_str());
    if(rc == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = 0;
    return true;
}

bool vm::do_readlink() {
    std::string path;
    if(!read_c_string(r(1), path, 4096)) {
        r(0) = -EFAULT;
        return true;
    }
    int rc = readlink(path.c_str(), (char*)mmu(r(2)), r(3));
    if(rc == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = rc;
    return true;
}

bool vm::do_execve() {
    std::string path;
    std::vector<std::string> argv_strings;
    std::vector<std::string> envp_strings;
    if(!read_c_string(r(1), path, 4096)) {
        r(0) = -EFAULT;
        return true;
    }
    if(!read_c_string_array(r(2), argv_strings, 1024, 4096)) {
        r(0) = -EFAULT;
        return true;
    }
    if(!read_c_string_array(r(3), envp_strings, 1024, 4096)) {
        r(0) = -EFAULT;
        return true;
    }

    vm fresh;
    uint64_t entry = fresh.load_elf(path.c_str());
    if(entry == 0) {
        r(0) = -ENOEXEC;
        return true;
    }

    for(size_t i = 0; i < 11; i++) {
        fresh.reg[i] = 0;
    }
    fresh.reg[10] = STACK_BASE + STACK_SIZE - 8;
    if(!fresh.setup_stack(argv_strings, envp_strings)) {
        r(0) = -E2BIG;
        return true;
    }
    const bpf_insn* new_pc = (const bpf_insn*)fresh.mmu(entry);
    if(new_pc == nullptr) {
        r(0) = -ENOEXEC;
        return true;
    }

    maps.swap(fresh.maps);
    while(!frames.empty()) {
        frames.pop();
    }
    for(size_t i = 0; i < 11; i++) {
        reg[i] = fresh.reg[i];
    }
    frames.emplace(nullptr, reg);
    pc = new_pc;
    pc--;
    r(0) = 0;
    return true;
}
