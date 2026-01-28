//
// Created by chouryzhou on 24-10-28.
//
#include "insn.h"

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <memory>
#include <thread>
#include <string.h>
#include <unistd.h>
#include <filesystem>

static void fill_bpf_stat64(const struct stat& st, bpf::stat& out) {
    out.st_dev = static_cast<decltype(out.st_dev)>(st.st_dev);
    out.st_ino = static_cast<decltype(out.st_ino)>(st.st_ino);
    out.st_mode = static_cast<decltype(out.st_mode)>(st.st_mode);
    out.st_nlink = static_cast<decltype(out.st_nlink)>(st.st_nlink);
    out.st_uid = static_cast<decltype(out.st_uid)>(st.st_uid);
    out.st_gid = static_cast<decltype(out.st_gid)>(st.st_gid);
    out.st_rdev = static_cast<decltype(out.st_rdev)>(st.st_rdev);
    out.st_size = static_cast<decltype(out.st_size)>(st.st_size);
    out.st_blksize = static_cast<decltype(out.st_blksize)>(st.st_blksize);
    out.st_blocks = static_cast<decltype(out.st_blocks)>(st.st_blocks);
#pragma push_macro("st_atime")
#undef st_atime
#if defined(__linux__)
    out.st_atime = static_cast<decltype(out.st_atime)>(st.st_atim.tv_sec);
#else
    out.st_atime = static_cast<decltype(out.st_atime)>(st.st_atime);
#endif
#pragma pop_macro("st_atime")

#pragma push_macro("st_mtime")
#undef st_mtime
#if defined(__linux__)
    out.st_mtime = static_cast<decltype(out.st_mtime)>(st.st_mtim.tv_sec);
#else
    out.st_mtime = static_cast<decltype(out.st_mtime)>(st.st_mtime);
#endif
#pragma pop_macro("st_mtime")

#pragma push_macro("st_ctime")
#undef st_ctime
#if defined(__linux__)
    out.st_ctime = static_cast<decltype(out.st_ctime)>(st.st_ctim.tv_sec);
#else
    out.st_ctime = static_cast<decltype(out.st_ctime)>(st.st_ctime);
#endif
#pragma pop_macro("st_ctime")
}


static inline int32_t arg_s32(uint64_t v) {
    return static_cast<int32_t>(v);
}

static inline uint32_t arg_u32(uint64_t v) {
    return static_cast<uint32_t>(v);
}

static inline size_t arg_size(uint64_t v) {
    return static_cast<size_t>(v);
}

std::string vm::resolve_path(const std::string& path) const {
    if(path.empty()) {
        return path;
    }
    std::filesystem::path input(path);
    if(input.is_absolute()) {
        return input.lexically_normal().string();
    }
    std::filesystem::path base = cwd.empty() ? std::filesystem::path("/") : std::filesystem::path(cwd);
    return (base / input).lexically_normal().string();
}

bool vm::do_syscall(uint32_t call) {
    uint32_t sys_id = call;
    if(call >= BPF_CALL_BASE) {
        sys_id = BPF_CALL_TO_ID(call);
    }
    switch (sys_id) {
    case BPF_SYS_MMAP:
        return do_mmap();
    case BPF_SYS_MUNMAP:
        return do_munmap();
    case BPF_SYS_EXIT:
        return do_exit();
    case BPF_SYS_GETTIMEOFDAY:
        return do_gettimeofday();
    case BPF_SYS_OPEN:
        return do_open();
    case BPF_SYS_READ:
        return do_read();
    case BPF_SYS_WRITE:
        return do_write();
    case BPF_SYS_LSEEK:
        return do_lseek();
    case BPF_SYS_CLOSE:
        return do_close();
    case BPF_SYS_UNLINK:
        return do_unlink();
    case BPF_SYS_MKDIR:
        return do_mkdir();
    case BPF_SYS_RMDIR:
        return do_rmdir();
    case BPF_SYS_RENAMEAT:
        return do_renameat();
    case BPF_SYS_READLINK:
        return do_readlink();
    case BPF_SYS_EXECVE:
        return do_execve();
    case BPF_SYS_FORK:
        return do_fork();
    case BPF_SYS_GETPID:
        return do_getpid();
    case BPF_SYS_GETPPID:
        return do_getppid();
    case BPF_SYS_WAITPID:
        return do_waitpid();
    case BPF_SYS_DUP2:
        return do_dup2();
    case BPF_SYS_PIPE2:
        return do_pipe2();
    case BPF_SYS_CHDIR:
        return do_chdir();
    case BPF_SYS_GETCWD:
        return do_getcwd();
    case BPF_SYS_STAT:
        return do_stat();
    case BPF_SYS_LSTAT:
        return do_lstat();
    case BPF_SYS_FSTAT:
        return do_fstat();
    case BPF_SYS_KILL:
        return do_kill();
    case BPF_SYS_SIGACTION:
        return do_sigaction();
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
    signal_return_pc = nullptr;
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
    int fd = open(resolve_path(path).c_str(), arg_s32(r(2)), (mode_t)arg_u32(r(3)));
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
    int rc = unlink(resolve_path(path).c_str());
    if(rc == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = 0;
    return true;
}

bool vm::do_mkdir() {
    std::string path;
    if(!read_c_string(r(1), path, 4096)) {
        r(0) = -EFAULT;
        return true;
    }
    int rc = mkdir(resolve_path(path).c_str(), (mode_t)arg_u32(r(2)));
    if(rc == -1) {
        r(0) = -errno;
        return true;
    }
    r(0) = 0;
    return true;
}

bool vm::do_rmdir() {
    std::string path;
    if(!read_c_string(r(1), path, 4096)) {
        r(0) = -EFAULT;
        return true;
    }
    int rc = rmdir(resolve_path(path).c_str());
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
    int old_dirfd = arg_s32(r(1));
    int new_dirfd = arg_s32(r(3));
    std::string resolved_old = old_path;
    std::string resolved_new = new_path;
    if(old_dirfd == AT_FDCWD) {
        resolved_old = resolve_path(old_path);
    }
    if(new_dirfd == AT_FDCWD) {
        resolved_new = resolve_path(new_path);
    }
    int rc = renameat(old_dirfd, resolved_old.c_str(), new_dirfd, resolved_new.c_str());
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
    int rc = readlink(resolve_path(path).c_str(), (char*)mmu(r(2)), arg_size(r(3)));
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
    fresh->cwd = cwd;
    uint64_t entry = fresh->load_elf(resolve_path(path).c_str());
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
    child->signal_actions = signal_actions;
    child->signal_return_pc = nullptr;
    child->cwd = cwd;
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

bool vm::do_getppid() {
    r(0) = ppid.load();
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

bool vm::do_chdir() {
    std::string path;
    if(!read_c_string(r(1), path, 4096)) {
        r(0) = -EFAULT;
        return true;
    }
    std::string resolved = resolve_path(path);
    struct stat st = {};
    if(stat(resolved.c_str(), &st) == -1) {
        r(0) = -errno;
        return true;
    }
    if(!S_ISDIR(st.st_mode)) {
        r(0) = -ENOTDIR;
        return true;
    }
    cwd = resolved.empty() ? std::string("/") : resolved;
    r(0) = 0;
    return true;
}

bool vm::do_getcwd() {
    uint64_t buf_addr = r(1);
    size_t size = arg_size(r(2));
    if(buf_addr == 0) {
        r(0) = -EFAULT;
        return true;
    }
    char* buf = static_cast<char*>(mmu(buf_addr));
    if(buf == nullptr) {
        r(0) = -EFAULT;
        return true;
    }
    std::string path = cwd.empty() ? "/" : cwd;
    if(size == 0 || size <= path.size()) {
        r(0) = -ERANGE;
        return true;
    }
    memcpy(buf, path.c_str(), path.size() + 1);
    r(0) = buf_addr;
    return true;
}

bool vm::do_stat() {
    std::string path;
    if(!read_c_string(r(1), path, 4096)) {
        r(0) = -EFAULT;
        return true;
    }
    auto out = static_cast<bpf::stat*>(mmu(r(2)));
    if(out == nullptr) {
        r(0) = -EFAULT;
        return true;
    }
    struct stat st = {};
    if(stat(resolve_path(path).c_str(), &st) == -1) {
        r(0) = -errno;
        return true;
    }
    fill_bpf_stat64(st, *out);
    r(0) = 0;
    return true;
}

bool vm::do_lstat() {
    std::string path;
    if(!read_c_string(r(1), path, 4096)) {
        r(0) = -EFAULT;
        return true;
    }
    auto out = static_cast<bpf::stat*>(mmu(r(2)));
    if(out == nullptr) {
        r(0) = -EFAULT;
        return true;
    }
    struct stat st = {};
    if(lstat(resolve_path(path).c_str(), &st) == -1) {
        r(0) = -errno;
        return true;
    }
    fill_bpf_stat64(st, *out);
    r(0) = 0;
    return true;
}

bool vm::do_fstat() {
    auto it = fds.find(arg_s32(r(1)));
    if(it == fds.end()) {
        r(0) = -EBADF;
        return true;
    }
    auto out = static_cast<bpf::stat*>(mmu(r(2)));
    if(out == nullptr) {
        r(0) = -EFAULT;
        return true;
    }
    struct stat st = {};
    if(fstat(it->second->fd, &st) == -1) {
        r(0) = -errno;
        return true;
    }
    fill_bpf_stat64(st, *out);
    r(0) = 0;
    return true;
}

bool vm::do_kill() {
    int target_pid = arg_s32(r(1));
    int sig = arg_s32(r(2));
    if(sig < 0 || sig >= NSIG || target_pid <= 0) {
        r(0) = -EINVAL;
        return true;
    }
    if(sig == 0) {
        if(static_cast<uint64_t>(target_pid) == pid) {
            r(0) = 0;
            return true;
        }
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        r(0) = (pid_map.count(static_cast<uint64_t>(target_pid)) > 0) ? 0 : -ESRCH;
        return true;
    }
    if(static_cast<uint64_t>(target_pid) == pid) {
        queue_signal(sig);
        r(0) = 0;
        return true;
    }
    std::shared_ptr<vm> target;
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        auto it = pid_map.find(static_cast<uint64_t>(target_pid));
        if(it != pid_map.end()) {
            target = it->second;
        }
    }
    if(target == nullptr) {
        r(0) = -ESRCH;
        return true;
    }
    target->queue_signal(sig);
    r(0) = 0;
    return true;
}

bool vm::do_sigaction() {
    int signo = arg_s32(r(1));
    uint64_t act_addr = r(2);
    uint64_t oldact_addr = r(3);

    if(signo <= 0 || signo >= NSIG || signo == SIGKILL) {
        r(0) = -EINVAL;
        return true;
    }

    if(oldact_addr != 0) {
        auto oldact = static_cast<struct bpf::sigaction*>(mmu(oldact_addr));
        if(oldact == nullptr) {
            r(0) = -EFAULT;
            return true;
        }
        const auto& current = signal_actions[static_cast<size_t>(signo)];
        oldact->sa_handler = reinterpret_cast<void (*)(int)>(static_cast<uintptr_t>(current.handler));
        oldact->sa_mask = static_cast<bpf::sigset_t>(current.mask);
        oldact->sa_flags = current.flags;
    }

    if(act_addr != 0) {
        auto action = static_cast<const struct bpf::sigaction*>(mmu(act_addr));
        if(action == nullptr) {
            r(0) = -EFAULT;
            return true;
        }
        if(reinterpret_cast<uintptr_t>(action->sa_handler) == reinterpret_cast<uintptr_t>(SIG_ERR)) {
            r(0) = -EINVAL;
            return true;
        }
        auto& current = signal_actions[static_cast<size_t>(signo)];
        current.handler = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(action->sa_handler));
        current.mask = static_cast<uint64_t>(action->sa_mask);
        current.flags = action->sa_flags;
    }

    r(0) = 0;
    return true;
}
