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
#include <memory>
#include <thread>
#include <string.h>
#include <unistd.h>

static inline int32_t arg_s32(uint64_t v) {
    return static_cast<int32_t>(v);
}

static inline uint32_t arg_u32(uint64_t v) {
    return static_cast<uint32_t>(v);
}

static inline size_t arg_size(uint64_t v) {
    return static_cast<size_t>(v);
}

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
    case BPF_CALL_FORK:
        return do_fork();
    case BPF_CALL_GETPID:
        return do_getpid();
    case BPF_CALL_WAITPID:
        return do_waitpid();
    case BPF_CALL_DUP2:
        return do_dup2();
    case BPF_CALL_PIPE2:
        return do_pipe2();
    default:
        fprintf(stderr, "unsupported func: 0x%x\n", call);
        r(0) = -ENOSYS;
        return true;
    }
}

bool vm::do_mmap() {
    void* addr = mmap(nullptr, arg_size(r(1)), arg_s32(r(2)), arg_s32(r(3)), arg_s32(r(4)), (off_t)r(5));
    if(addr == MAP_FAILED) {
        r(0) = -errno;
        return true;
    }
    memmap mem;
    mem.data = (unsigned char*)addr;
    mem.paddr = maps.back().paddr + maps.back().size;
    mem.flags = arg_u32(r(3));
    mem.size = arg_size(r(1));
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
    if(munmap(addr, arg_size(r(2))) == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = 0;
    return true;
}

bool vm::do_exit() {
    if(pid != 1) {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        for(auto& entry : pid_map) {
            if(entry.second->ppid.load() == pid) {
                entry.second->ppid.store(1);
            }
        }
    }
    r(0) = (uint64_t)arg_s32(r(1));
    maps.clear();
    frames.clear();
    fds.clear();
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
    int fd = open(path.c_str(), arg_s32(r(2)), (mode_t)arg_u32(r(3)));
    if(fd == -1) {
        r(0) = -errno;
        return true;
    }
    fds[fd] = std::make_shared<fd_handle>(fd);
    r(0) = fd;
    return true;
}

bool vm::do_read() {
    auto it = fds.find(arg_s32(r(1)));
    if(it == fds.end()) {
        r(0) = -EBADF;
        return true;
    }
    int rc = read(it->second->fd, mmu(r(2)), arg_size(r(3)));
    if(rc == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = rc;
    return true;
}

bool vm::do_write() {
    auto it = fds.find(arg_s32(r(1)));
    if(it == fds.end()) {
        r(0) = -EBADF;
        return true;
    }
    int rc = write(it->second->fd, mmu(r(2)), arg_size(r(3)));
    if(rc == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = rc;
    return true;
}

bool vm::do_lseek() {
    auto it = fds.find(arg_s32(r(1)));
    if(it == fds.end()) {
        r(0) = -EBADF;
        return true;
    }
    int rc = lseek64(it->second->fd, (off_t)r(2), arg_s32(r(3)));
    if(rc == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = rc;
    return true;
}

bool vm::do_close() {
    auto it = fds.find(arg_s32(r(1)));
    if(it == fds.end()) {
        r(0) = -EBADF;
        return true;
    }
    fds.erase(it);
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
    int rc = renameat(arg_s32(r(1)), old_path.c_str(), arg_s32(r(3)), new_path.c_str());
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
    int rc = readlink(path.c_str(), (char*)mmu(r(2)), arg_size(r(3)));
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

    auto fresh = std::shared_ptr<vm>(new vm(Token{}, ppid.load(), fds)); // temporary use, avoid pid_map pollution
    uint64_t entry = fresh->load_elf(path.c_str());
    if(entry == 0) {
        r(0) = -ENOEXEC;
        return true;
    }

    for(size_t i = 0; i < 11; i++) {
        fresh->reg[i] = 0;
    }
    if(!fresh->setup_stack(argv_strings, envp_strings)) {
        r(0) = -E2BIG;
        return true;
    }
    const bpf_insn* new_pc = (const bpf_insn*)fresh->mmu(entry);
    if(new_pc == nullptr) {
        r(0) = -ENOEXEC;
        return true;
    }

    fresh->pid = pid;
    fresh->ppid = ppid.load();
    maps.swap(fresh->maps);
    frames.clear();
    for(size_t i = 0; i < 11; i++) {
        reg[i] = fresh->reg[i];
    }
    frames.emplace_back(nullptr, reg);
    pc = new_pc;
    pc--;
    r(0) = 0;
    return true;
}

bool vm::do_fork() {
    auto child = std::shared_ptr<vm>(new vm(Token{}, pid, fds));
    child->options = options;
    for(const auto& map : maps) {
        memmap cloned;
        cloned.size = map.size;
        cloned.paddr = map.paddr;
        cloned.flags = map.flags;

        int prot = PROT_READ;
        if(map.flags & PF_W) {
            prot |= PROT_WRITE;
        }
        if(map.flags & PF_X) {
            prot |= PROT_EXEC;
        }

        int copy_prot = prot | PROT_WRITE;
        cloned.data = (unsigned char*)mmap(nullptr, cloned.size, copy_prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(cloned.data == MAP_FAILED) {
            r(0) = -ENOMEM;
            return true;
        }
        memcpy(cloned.data, map.data, cloned.size);
        if((prot & PROT_WRITE) == 0) {
            mprotect(cloned.data, cloned.size, prot);
        }
        child->addmem(std::move(cloned));
    }

    for(size_t i = 0; i < 11; i++) {
        child->reg[i] = reg[i];
    }
    child->r(0) = 0;

    for(const auto& entry : frames) {
        const bpf_insn* parent_pc = entry.pc;
        const bpf_insn* child_pc = nullptr;
        if(parent_pc != nullptr) {
            uint64_t addr = unmmu(parent_pc);
            child_pc = (const bpf_insn*)child->mmu(addr);
        }
        uint64_t scratch[11] = {};
        scratch[6] = entry.r6;
        scratch[7] = entry.r7;
        scratch[8] = entry.r8;
        scratch[9] = entry.r9;
        scratch[10] = entry.r10;
        child->frames.emplace_back(child_pc, scratch);
    }

    uint64_t pc_addr = unmmu(pc);
    const bpf_insn* child_pc = (const bpf_insn*)child->mmu(pc_addr);
    if(child_pc == nullptr) {
        r(0) = -EFAULT;
        return true;
    }
    child->pc = child_pc + 1;
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        pid_map[child->pid] = child;
    }
    child->worker = std::thread([child]() {
        child->run();
    });
    r(0) = child->pid;
    return true;
}

bool vm::do_getpid() {
    r(0) = pid;
    return true;
}

bool vm::do_waitpid() {
    int64_t target_pid = static_cast<int64_t>(arg_s32(r(1)));
    uint64_t status_addr = r(2);
    int32_t options = arg_s32(r(3));

    if((options & ~WNOHANG) != 0) {
        r(0) = -EINVAL;
        return true;
    }

    if(target_pid == pid || target_pid == 0) {
        r(0) = -EINVAL;
        return true;
    }

    int* status_ptr = nullptr;
    if(status_addr != 0) {
        status_ptr = static_cast<int*>(mmu(status_addr));
        if(status_ptr == nullptr) {
            r(0) = -EFAULT;
            return true;
        }
    }


    std::shared_ptr<vm> child;
    bool has_child = false;
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        if(target_pid == -1) {
            for(const auto& entry : pid_map) {
                if(entry.second->ppid.load() != pid) {
                    continue;
                }
                has_child = true;
                if((options & WNOHANG) == 0) {
                    child = entry.second;
                    break;
                }
                if(entry.second->exited.load(std::memory_order_acquire)) {
                    child = entry.second;
                    break;
                }
            }
        } else if(target_pid > 0) {
            auto it = pid_map.find(static_cast<uint64_t>(target_pid));
            if(it == pid_map.end()) {
                r(0) = -ECHILD;
                return true;
            }
            if(it->second->ppid.load() != pid) {
                r(0) = -ECHILD;
                return true;
            }
            has_child = true;
            if((options & WNOHANG) == 0 || it->second->exited.load(std::memory_order_acquire)) {
                child = it->second;
            }
        } else {
            r(0) = -EINVAL;
            return true;
        }
    }

    if(child == nullptr) {
        if(has_child) {
            //all child processes are still running
            assert(options & WNOHANG);
            r(0) = 0;
            return true;
        } else {
            r(0) = -ECHILD;
            return true;
        }
    }

    //wait不能加锁，否则会死锁
    uint64_t exit_code = child->wait();
    if(status_ptr != nullptr) {
        int status = (static_cast<int>(exit_code) & 0xff) << 8;
        *status_ptr = status;
    }

    uint64_t child_pid = child->pid;
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        pid_map.erase(child_pid);
    }
    r(0) = child_pid;
    return true;
}

bool vm::do_dup2() {
    int old_fd = arg_s32(r(1));
    int new_fd = arg_s32(r(2));
    if(old_fd < 0 || new_fd < 0) {
        r(0) = -EBADF;
        return true;
    }

    auto it = fds.find(old_fd);
    if(it == fds.end()) {
        r(0) = -EBADF;
        return true;
    }

    if(old_fd == new_fd) {
        r(0) = new_fd;
        return true;
    }

    fds[new_fd] = it->second;
    r(0) = new_fd;
    return true;
}

bool vm::do_pipe2() {
    int* pipefd = static_cast<int*>(mmu(r(1)));
    if(pipefd == nullptr) {
        r(0) = -EFAULT;
        return true;
    }

    int flags = arg_s32(r(2));
    int host_fds[2] = {-1, -1};

    int rc = pipe2(host_fds, flags);
    if(rc == -1) {
        r(0) = -errno;
        return true;
    }

    pipefd[0] = host_fds[0];
    pipefd[1] = host_fds[1];
    fds[host_fds[0]] = std::make_shared<fd_handle>(host_fds[0]);
    fds[host_fds[1]] = std::make_shared<fd_handle>(host_fds[1]);
    r(0) = 0;
    return true;
}
