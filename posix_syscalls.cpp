//
// Created by chouryzhou on 24-10-28.
//
#include "insn.h"
#include "include/bpf_call.h"
namespace bpf{
    #define BPF_NO_SYSCALL
    #include "include/signal.h"
    #include "include/sys/stat.h"
    #include "include/dirent.h"
    //#include "include/sys/times.h"
    #include "include/termios.h"
}

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <dirent.h>
#include <memory>
#include <time.h>
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

#if defined(__linux__)
    out.st_atim.tv_sec = static_cast<decltype(out.st_atim.tv_sec)>(st.st_atim.tv_sec);
    out.st_atim.tv_nsec = static_cast<decltype(out.st_atim.tv_nsec)>(st.st_atim.tv_nsec);
#else
    out.st_atim.tv_sec = static_cast<decltype(out.st_atim.tv_sec)>(st.st_atime);
    out.st_atim.tv_nsec = 0;
#endif


#if defined(__linux__)
    out.st_mtim.tv_sec = static_cast<decltype(out.st_mtim.tv_sec)>(st.st_mtim.tv_sec);
    out.st_mtim.tv_nsec = static_cast<decltype(out.st_mtim.tv_nsec)>(st.st_mtim.tv_nsec);
#else
    out.st_mtim.tv_sec = static_cast<decltype(out.st_mtim.tv_sec)>(st.st_mtime);
    out.st_mtim.tv_nsec = 0;
#endif


#if defined(__linux__)
    out.st_ctim.tv_sec = static_cast<decltype(out.st_ctim.tv_sec)>(st.st_ctim.tv_sec);
    out.st_ctim.tv_nsec = static_cast<decltype(out.st_ctim.tv_nsec)>(st.st_ctim.tv_nsec);
#else
    out.st_ctim.tv_sec = static_cast<decltype(out.st_ctim.tv_sec)>(st.st_ctime);
    out.st_ctim.tv_nsec = 0;
#endif
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

struct PosixSyscalls : SyscallAccessor {
    explicit PosixSyscalls(vm& v) : SyscallAccessor(v) {}

    int allocate_fd(int min_fd = 0) {
        int fd = min_fd;
        while(fds().count(fd)) {
            fd++;
        }
        return fd;
    }

    bool read_c_string(uint64_t addr, std::string& out, size_t max_len) {
        out.clear();
        if(addr == 0) {
            return false;
        }
        for(size_t i = 0; i < max_len; i++) {
            void* p = v_.mmu(addr + i);
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

    bool read_c_string_array(uint64_t addr, std::vector<std::string>& out, size_t max_count, size_t max_str_len) {
        out.clear();
        if(addr == 0) {
            return true;
        }
        for(size_t i = 0; i < max_count; i++) {
            void* p = v_.mmu(addr + i * sizeof(uint64_t));
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

    std::string resolve_path(const std::string& path) {
        if(path.empty()) {
            return path;
        }
        std::filesystem::path input(path);
        if(input.is_absolute()) {
            return input.lexically_normal().string();
        }
        std::filesystem::path base = cwd().empty() ? std::filesystem::path("/") : std::filesystem::path(cwd());
        return (base / input).lexically_normal().string();
    }

    bool do_clock_gettime() {
        clockid_t clock_id = (clockid_t)arg_s32(v_.r(1));
        struct timespec* tp = (struct timespec*)v_.mmu(v_.r(2));
        if(tp == nullptr) {
            v_.r(0) = -EFAULT;
            return true;
        }
        if(clock_gettime(clock_id, tp) == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = 0;
        return true;
    }

    bool do_mmap() {
        int flags = arg_s32(v_.r(3));
        int fd = arg_s32(v_.r(4));
        int host_fd = -1;

        if (!(flags & MAP_ANONYMOUS)) {
            auto it = fds().find(fd);
            if (it == fds().end()) {
                v_.r(0) = -EBADF;
                return true;
            }
            host_fd = it->second->fd;
        }

        void* addr = mmap(nullptr, arg_size(v_.r(1)), arg_s32(v_.r(2)), flags, host_fd, (off_t)v_.r(5));
        if(addr == MAP_FAILED) {
            v_.r(0) = -errno;
            return true;
        }
        memmap mem;
        mem.data = (unsigned char*)addr;
        mem.paddr = maps().back().paddr + maps().back().size;
        mem.flags = arg_u32(v_.r(3));
        mem.size = arg_size(v_.r(1));
        v_.r(0) = mem.paddr;
        v_.addmem(std::move(mem));
        return true;
    }

    bool do_munmap() {
        auto addr = v_.unmap(v_.r(1));
        if(addr == nullptr) {
            v_.r(0) = -EINVAL;
            return true;
        }
        if(munmap(addr, arg_size(v_.r(2))) == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = 0;
        return true;
    }

    bool do_exit() {
        if(pid() != 1) {
            std::lock_guard<std::mutex> lock(pid_map_mutex());
            for(auto& entry : pid_map()) {
                PosixSyscalls child(*entry.second);
                if(child.ppid().load() == pid()) {
                    child.ppid().store(1);
                }
            }
        }
        v_.r(0) = (uint64_t)arg_s32(v_.r(1));
        maps().clear();
        fds().clear();
        signal_depth() = 0;
        return false;
    }

    bool do_nanosleep() {
        const struct timespec* req = static_cast<const struct timespec*>(v_.mmu(v_.r(1)));
        if(req == nullptr) {
            v_.r(0) = -EFAULT;
            return true;
        }

        struct timespec* rem = nullptr;
        if(v_.r(2) != 0) {
            rem = static_cast<struct timespec*>(v_.mmu(v_.r(2)));
            if(rem == nullptr) {
                v_.r(0) = -EFAULT;
                return true;
            }
        }

        struct timespec host_req = {};
        if(req != nullptr) {
            host_req = *req;
        }

        struct timespec host_rem = {};
        int rc = nanosleep(&host_req, rem != nullptr ? &host_rem : nullptr);
        if(rc == -1) {
            if(rem != nullptr) {
                *rem = host_rem;
            }
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = 0;
        return true;
    }

    bool do_openat() {
        int dirfd = arg_s32(v_.r(1));
        std::string path;
        if(!read_c_string(v_.r(2), path, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }
        int flags = arg_s32(v_.r(3));
        mode_t mode = (mode_t)(arg_u32(v_.r(4)) & ~umask_val());
        int fd = -1;
        std::string resolved;
        if(dirfd == AT_FDCWD) {
            resolved = resolve_path(path);
            fd = openat(AT_FDCWD, resolved.c_str(), flags, mode);
        } else {
            auto it = fds().find(dirfd);
            if(it == fds().end()) {
                v_.r(0) = -EBADF;
                return true;
            }
            fd = openat(it->second->fd, path.c_str(), flags, mode);
            if(!it->second->path.empty()) {
                resolved = (std::filesystem::path(it->second->path) / path).lexically_normal().string();
            }
        }
        if(fd == -1) {
            v_.r(0) = -errno;
            return true;
        }
        auto handle = std::make_shared<fd_handle>(fd, std::move(resolved));
        if(flags & O_CLOEXEC) {
            handle->cloexec = true;
        }
        int guest_fd = allocate_fd();
        fds()[guest_fd] = handle;
        v_.r(0) = guest_fd;
        return true;
    }

    bool do_read() {
        auto it = fds().find(arg_s32(v_.r(1)));
        if(it == fds().end()) {
            v_.r(0) = -EBADF;
            return true;
        }
        size_t count = arg_size(v_.r(3));
        void* buf = v_.mmu(v_.r(2), count);
        if(buf == nullptr) {
            v_.r(0) = -EFAULT;
            return true;
        }
        int rc = read(it->second->fd, buf, count);
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = rc;
        return true;
    }

    bool do_write() {
        auto it = fds().find(arg_s32(v_.r(1)));
        if(it == fds().end()) {
            v_.r(0) = -EBADF;
            return true;
        }
        size_t count = arg_size(v_.r(3));
        void* buf = v_.mmu(v_.r(2), count);
        if(buf == nullptr) {
            v_.r(0) = -EFAULT;
            return true;
        }
        int rc = write(it->second->fd, buf, count);
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = rc;
        return true;
    }

    bool do_lseek() {
        auto it = fds().find(arg_s32(v_.r(1)));
        if(it == fds().end()) {
            v_.r(0) = -EBADF;
            return true;
        }
        int rc = lseek64(it->second->fd, (off_t)v_.r(2), arg_s32(v_.r(3)));
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = rc;
        return true;
    }

    bool do_truncate() {
        std::string path;
        if(!read_c_string(v_.r(1), path, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }
        int rc = truncate(resolve_path(path).c_str(), static_cast<off_t>(v_.r(2)));
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = 0;
        return true;
    }

    bool do_ftruncate() {
        auto it = fds().find(arg_s32(v_.r(1)));
        if(it == fds().end()) {
            v_.r(0) = -EBADF;
            return true;
        }
        int rc = ftruncate(it->second->fd, static_cast<off_t>(v_.r(2)));
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = 0;
        return true;
    }

    bool do_close() {
        auto it = fds().find(arg_s32(v_.r(1)));
        if(it == fds().end()) {
            v_.r(0) = -EBADF;
            return true;
        }
        fds().erase(it);
        v_.r(0) = 0;
        return true;
    }

    bool do_unlinkat() {
        int dirfd = arg_s32(v_.r(1));
        std::string path;
        if(!read_c_string(v_.r(2), path, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }
        int flags = arg_s32(v_.r(3));
        int rc = -1;
        if(dirfd == AT_FDCWD) {
            rc = unlinkat(AT_FDCWD, resolve_path(path).c_str(), flags);
        } else {
            auto it = fds().find(dirfd);
            if(it == fds().end()) {
                v_.r(0) = -EBADF;
                return true;
            }
            rc = unlinkat(it->second->fd, path.c_str(), flags);
        }
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = 0;
        return true;
    }

    bool do_mkdir() {
        std::string path;
        if(!read_c_string(v_.r(1), path, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }
        int rc = mkdir(resolve_path(path).c_str(), (mode_t)(arg_u32(v_.r(2)) & ~umask_val()));
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = 0;
        return true;
    }

    bool do_rmdir() {
        std::string path;
        if(!read_c_string(v_.r(1), path, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }
        int rc = rmdir(resolve_path(path).c_str());
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = 0;
        return true;
    }

    bool do_symlinkat() {
        std::string target;
        std::string linkpath;
        if(!read_c_string(v_.r(1), target, 4096) || !read_c_string(v_.r(3), linkpath, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }
        int new_dirfd = arg_s32(v_.r(2));
        int rc = -1;
        if(new_dirfd == AT_FDCWD) {
            rc = symlinkat(target.c_str(), AT_FDCWD, resolve_path(linkpath).c_str());
        } else {
            auto it = fds().find(new_dirfd);
            if(it == fds().end()) {
                v_.r(0) = -EBADF;
                return true;
            }
            rc = symlinkat(target.c_str(), it->second->fd, linkpath.c_str());
        }
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = 0;
        return true;
    }

    bool do_linkat() {
        std::string oldpath;
        std::string newpath;
        if(!read_c_string(v_.r(2), oldpath, 4096) || !read_c_string(v_.r(4), newpath, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }
        int olddirfd = arg_s32(v_.r(1));
        int newdirfd = arg_s32(v_.r(3));
        int flags = arg_s32(v_.r(5));

        int host_olddirfd = AT_FDCWD;
        if (olddirfd != AT_FDCWD) {
            auto it = fds().find(olddirfd);
            if (it == fds().end()) {
                v_.r(0) = -EBADF;
                return true;
            }
            host_olddirfd = it->second->fd;
        }

        int host_newdirfd = AT_FDCWD;
        if (newdirfd != AT_FDCWD) {
            auto it = fds().find(newdirfd);
            if (it == fds().end()) {
                v_.r(0) = -EBADF;
                return true;
            }
            host_newdirfd = it->second->fd;
        }

        std::string resolved_old = oldpath;
        if (olddirfd == AT_FDCWD) {
            resolved_old = resolve_path(oldpath);
        }
        std::string resolved_new = newpath;
        if (newdirfd == AT_FDCWD) {
            resolved_new = resolve_path(newpath);
        }

        int rc = linkat(host_olddirfd, resolved_old.c_str(), host_newdirfd, resolved_new.c_str(), flags);
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = 0;
        return true;
    }

    bool do_renameat() {
        std::string old_path;
        std::string new_path;
        if(!read_c_string(v_.r(2), old_path, 4096) || !read_c_string(v_.r(4), new_path, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }
        int old_dirfd = arg_s32(v_.r(1));
        int new_dirfd = arg_s32(v_.r(3));

        int host_old_dirfd = AT_FDCWD;
        if (old_dirfd != AT_FDCWD) {
            auto it = fds().find(old_dirfd);
            if (it == fds().end()) {
                v_.r(0) = -EBADF;
                return true;
            }
            host_old_dirfd = it->second->fd;
        }

        int host_new_dirfd = AT_FDCWD;
        if (new_dirfd != AT_FDCWD) {
            auto it = fds().find(new_dirfd);
            if (it == fds().end()) {
                v_.r(0) = -EBADF;
                return true;
            }
            host_new_dirfd = it->second->fd;
        }

        std::string resolved_old = old_path;
        std::string resolved_new = new_path;
        if(old_dirfd == AT_FDCWD) {
            resolved_old = resolve_path(old_path);
        }
        if(new_dirfd == AT_FDCWD) {
            resolved_new = resolve_path(new_path);
        }
        int rc = renameat(host_old_dirfd, resolved_old.c_str(), host_new_dirfd, resolved_new.c_str());
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = 0;
        return true;
    }

    bool do_readlink() {
        std::string path;
        if(!read_c_string(v_.r(1), path, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }
        size_t bufsiz = arg_size(v_.r(3));
        char* buf = (char*)v_.mmu(v_.r(2), bufsiz);
        if(buf == nullptr) {
            v_.r(0) = -EFAULT;
            return true;
        }
        int rc = readlink(resolve_path(path).c_str(), buf, bufsiz);
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = rc;
        return true;
    }

    bool do_execve() {
        std::string path;
        std::vector<std::string> argv_strings;
        std::vector<std::string> envp_strings;
        if(!read_c_string(v_.r(1), path, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }
        if(!read_c_string_array(v_.r(2), argv_strings, 1024, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }
        if(!read_c_string_array(v_.r(3), envp_strings, 1024, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }

        std::unordered_map<int, std::shared_ptr<fd_handle>> new_fds;
        for (const auto& entry : fds()) {
            if (!entry.second->cloexec) {
                new_fds.insert(entry);
            }
        }

        auto fresh = std::shared_ptr<vm>(new vm(vm::Token{}, ppid().load(), new_fds)); // temporary use, avoid pid_map pollution
        PosixSyscalls fresh_sys(*fresh);
        fresh_sys.cwd() = cwd();
        uint64_t entry = fresh->load_elf(resolve_path(path).c_str());
        if(entry == 0) {
            v_.r(0) = -ENOEXEC;
            return true;
        }

        for(size_t i = 0; i < 11; i++) {
            fresh_sys.v_.r(i) = 0;
        }
        if(!fresh->setup_stack(argv_strings, envp_strings)) {
            v_.r(0) = -E2BIG;
            return true;
        }
        const bpf_insn* new_pc = (const bpf_insn*)fresh->mmu(entry);
        if(new_pc == nullptr) {
            v_.r(0) = -ENOEXEC;
            return true;
        }

        std::array<vm::signal_action, NSIG> new_actions{};
        const uint64_t sig_dfl = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_DFL));
        const uint64_t sig_ign = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_IGN));
        for(size_t i = 0; i < new_actions.size(); i++) {
            if(signal_actions()[i].handler == sig_ign) {
                new_actions[i].handler = sig_ign;
            } else {
                new_actions[i].handler = sig_dfl;
            }
        }

        fresh_sys.pid() = pid();
        fresh_sys.ppid() = ppid().load();
        maps().swap(fresh_sys.maps());
        fds().swap(fresh_sys.fds());
        for(size_t i = 0; i < 11; i++) {
            v_.r(i) = fresh_sys.v_.r(i);
        }
        signal_actions() = new_actions;
        signal_depth() = 0;
        pc() = new_pc;
        v_.push_frame(0);
        pc()--;
        v_.r(0) = 0;
        return true;
    }

    bool do_fork() {
        std::unordered_map<int, std::shared_ptr<fd_handle>> child_fds;
        for(const auto& entry : fds()) {
            int new_host_fd = dup(entry.second->fd);
            if(new_host_fd < 0) {
                v_.r(0) = -errno;
                return true;
            }
            auto new_handle = std::make_shared<fd_handle>(new_host_fd, entry.second->path);
            new_handle->cloexec = entry.second->cloexec;
            child_fds[entry.first] = new_handle;
        }

        auto child = std::shared_ptr<vm>(new vm(vm::Token{}, pid(), child_fds));
        PosixSyscalls child_sys(*child);
        child_sys.options() = options();
        child_sys.signal_actions() = signal_actions();
        child_sys.signal_depth() = signal_depth();
        child_sys.cwd() = cwd();
        child_sys.umask_val() = umask_val();
        for(const auto& map : maps()) {
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
                v_.r(0) = -ENOMEM;
                return true;
            }
            memcpy(cloned.data, map.data, cloned.size);
            if((prot & PROT_WRITE) == 0) {
                mprotect(cloned.data, cloned.size, prot);
            }
            child->addmem(std::move(cloned));
        }

        for(size_t i = 0; i < 11; i++) {
            child_sys.v_.r(i) = v_.r(i);
        }
        child->r(0) = 0;

        uint64_t pc_addr = v_.unmmu(pc());
        const bpf_insn* child_pc = (const bpf_insn*)child->mmu(pc_addr);
        if(child_pc == nullptr) {
            v_.r(0) = -EFAULT;
            return true;
        }
        child_sys.pc() = child_pc + 1;
        pthread_attr_t attr;
        pthread_t worker;
        int rc = pthread_attr_init(&attr);
        if(rc != 0) {
            v_.r(0) = -rc;
            return true;
        }
        rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if(rc != 0) {
            pthread_attr_destroy(&attr);
            v_.r(0) = -rc;
            return true;
        }
        auto* holder = new std::shared_ptr<vm>(child);
        rc = pthread_create(&worker, &attr, [](void* arg) -> void* {
            auto* child = static_cast<std::shared_ptr<vm>*>(arg);
            (*child)->run();
            delete child;
            return nullptr;
        }, holder);
        pthread_attr_destroy(&attr);
        if(rc != 0) {
            delete holder;
            v_.r(0) = -rc;
            return true;
        }
        {
            std::lock_guard<std::mutex> lock(pid_map_mutex());
            pid_map()[child_sys.pid()] = child;
        }
        v_.r(0) = child_sys.pid();
        return true;
    }

    bool do_getpid() {
        v_.r(0) = pid();
        return true;
    }

    bool do_getppid() {
        v_.r(0) = ppid().load();
        return true;
    }

    bool do_waitpid() {
        int64_t target_pid = static_cast<int64_t>(arg_s32(v_.r(1)));
        uint64_t status_addr = v_.r(2);
        int32_t options = arg_s32(v_.r(3));

        if((options & ~WNOHANG) != 0) {
            v_.r(0) = -EINVAL;
            return true;
        }

        if(target_pid == (int64_t)pid() || target_pid == 0) {
            v_.r(0) = -EINVAL;
            return true;
        }

        int* status_ptr = nullptr;
        if(status_addr != 0) {
            status_ptr = static_cast<int*>(v_.mmu(status_addr));
            if(status_ptr == nullptr) {
                v_.r(0) = -EFAULT;
                return true;
            }
        }

        std::vector<std::shared_ptr<vm>> children;
        {
            std::lock_guard<std::mutex> lock(pid_map_mutex());
            if(target_pid == -1) {
                for(const auto& entry : pid_map()) {
                    PosixSyscalls child(*entry.second);
                    if(child.ppid().load() != pid()) {
                        continue;
                    }
                    if(child.exited().load(std::memory_order_acquire)) {
                        children.clear();
                        children.push_back(entry.second);
                        break;
                    }
                    children.push_back(entry.second);
                }
            } else if(target_pid > 0) {
                auto it = pid_map().find(static_cast<uint64_t>(target_pid));
                if(it == pid_map().end()) {
                    v_.r(0) = -ECHILD;
                    return true;
                }
                PosixSyscalls child(*it->second);
                if(child.ppid().load() != pid()) {
                    v_.r(0) = -ECHILD;
                    return true;
                }
                children.push_back(it->second);
            } else {
                v_.r(0) = -EINVAL;
                return true;
            }
        }

        if(children.empty()) {
            v_.r(0) = -ECHILD;
            return true;
        }

        std::shared_ptr<vm> child;
        if(children.size() == 1 && PosixSyscalls(*children[0]).exited().load(std::memory_order_acquire)) {
            child = children[0];
        } else {
            if(options & WNOHANG) {
                v_.r(0) = 0;
                return true;
            }

            do {
                for(const auto& candidate : children) {
                    if(candidate->wait_for_exit(100)) {
                        child = candidate;
                        break;
                    }
                    if(!pending_signals().empty() || exited().load(std::memory_order_acquire)) {
                        v_.r(0) = -EINTR;
                        return true;
                    }
                }
            } while(child == nullptr);
        }

        //wait不能加锁，否则会死锁
        uint64_t exit_code = child->r(0);
        if(status_ptr != nullptr) {
            int status = (static_cast<int>(exit_code) & 0xff) << 8;
            *status_ptr = status;
        }

        uint64_t child_pid = PosixSyscalls(*child).pid();
        {
            std::lock_guard<std::mutex> lock(pid_map_mutex());
            pid_map().erase(child_pid);
        }
        v_.r(0) = child_pid;
        return true;
    }

    bool do_dup() {
        int old_fd = arg_s32(v_.r(1));
        if(old_fd < 0) {
            v_.r(0) = -EBADF;
            return true;
        }

        auto it = fds().find(old_fd);
        if(it == fds().end()) {
            v_.r(0) = -EBADF;
            return true;
        }

        int new_host_fd = dup(it->second->fd);
        if(new_host_fd < 0) {
            v_.r(0) = -errno;
            return true;
        }

        int new_fd = allocate_fd();
        fds()[new_fd] = std::make_shared<fd_handle>(new_host_fd, it->second->path);
        v_.r(0) = new_fd;
        return true;
    }

    bool do_dup2() {
        int old_fd = arg_s32(v_.r(1));
        int new_fd = arg_s32(v_.r(2));
        if(old_fd < 0 || new_fd < 0) {
            v_.r(0) = -EBADF;
            return true;
        }

        auto it = fds().find(old_fd);
        if(it == fds().end()) {
            v_.r(0) = -EBADF;
            return true;
        }

        if(old_fd == new_fd) {
            v_.r(0) = new_fd;
            return true;
        }

        int new_host_fd = dup(it->second->fd);
        if(new_host_fd < 0) {
            v_.r(0) = -errno;
            return true;
        }

        fds()[new_fd] = std::make_shared<fd_handle>(new_host_fd, it->second->path);
        v_.r(0) = new_fd;
        return true;
    }

    bool do_pipe2() {
        int* pipefd = static_cast<int*>(v_.mmu(v_.r(1), 2 * sizeof(int)));
        if(pipefd == nullptr) {
            v_.r(0) = -EFAULT;
            return true;
        }

        int flags = arg_s32(v_.r(2));
        int host_fds[2] = {-1, -1};

        int rc = pipe2(host_fds, flags);
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }

        int guest_fd0 = allocate_fd();
        auto handle0 = std::make_shared<fd_handle>(host_fds[0]);
        if (flags & O_CLOEXEC) {
            handle0->cloexec = true;
        }
        fds()[guest_fd0] = handle0;

        int guest_fd1 = allocate_fd(guest_fd0 + 1);
        auto handle1 = std::make_shared<fd_handle>(host_fds[1]);
        if (flags & O_CLOEXEC) {
            handle1->cloexec = true;
        }
        fds()[guest_fd1] = handle1;

        pipefd[0] = guest_fd0;
        pipefd[1] = guest_fd1;
        v_.r(0) = 0;
        return true;
    }

    bool do_fchdir() {
        int fd = arg_s32(v_.r(1));
        auto it = fds().find(fd);
        if(it == fds().end()) {
            v_.r(0) = -EBADF;
            return true;
        }
        struct stat st = {};
        if(fstat(it->second->fd, &st) == -1) {
            v_.r(0) = -errno;
            return true;
        }
        if(!S_ISDIR(st.st_mode)) {
            v_.r(0) = -ENOTDIR;
            return true;
        }
        if(it->second->path.empty()) {
            v_.r(0) = -ENOENT;
            return true;
        }
        cwd() = it->second->path;
        v_.r(0) = 0;
        return true;
    }

    bool do_getcwd() {
        uint64_t buf_addr = v_.r(1);
        size_t size = arg_size(v_.r(2));
        if(size == 0) {
            v_.r(0) = -ERANGE;
            return true;
        }
        char* buf = static_cast<char*>(v_.mmu(buf_addr, size));
        if(buf == nullptr) {
            v_.r(0) = -EFAULT;
            return true;
        }
        std::string path = cwd().empty() ? "/" : cwd();
        if(size <= path.size()) {
            v_.r(0) = -ERANGE;
            return true;
        }
        memcpy(buf, path.c_str(), path.size() + 1);
        v_.r(0) = path.size() + 1;
        return true;
    }

    bool do_fdopendir() {
        int fd = arg_s32(v_.r(1));
        auto out_dir = static_cast<bpf::DIR*>(v_.mmu(v_.r(2)));
        if(out_dir == nullptr) {
            v_.r(0) = -EFAULT;
            return true;
        }
        auto it = fds().find(fd);
        if(it == fds().end()) {
            v_.r(0) = -EBADF;
            return true;
        }
        it->second->cloexec = true;
        DIR* dir = fdopendir(it->second->fd);
        if(dir == nullptr) {
            v_.r(0) = -errno;
            return true;
        }
        out_dir->handle = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(dir));
        out_dir->fd = fd;
        v_.r(0) = 0;
        return true;
    }

    bool do_readdir() {
        auto dirp = static_cast<bpf::DIR*>(v_.mmu(v_.r(1)));
        if(dirp == nullptr) {
            v_.r(0) = -EFAULT;
            return true;
        }
        auto out_entry = static_cast<bpf::dirent*>(v_.mmu(v_.r(2)));
        if(out_entry == nullptr) {
            v_.r(0) = -EFAULT;
            return true;
        }
        if(dirp->handle == 0) {
            v_.r(0) = -EBADF;
            return true;
        }
        DIR* dir = reinterpret_cast<DIR*>(static_cast<uintptr_t>(dirp->handle));
        errno = 0;
        struct dirent* ent = readdir(dir);
        if(ent == nullptr) {
            if(errno != 0) {
                v_.r(0) = -errno;
            } else {
                v_.r(0) = 0;
            }
            return true;
        }
        memset(out_entry, 0, sizeof(*out_entry));
        strncpy(out_entry->d_name, ent->d_name, sizeof(out_entry->d_name) - 1);
#ifdef _DIRENT_HAVE_D_TYPE
        out_entry->d_type = ent->d_type;
#else
        out_entry->d_type = DT_UNKNOWN;
#endif
        v_.r(0) = 1;
        return true;
    }

    bool do_closedir() {
        auto dirp = static_cast<bpf::DIR*>(v_.mmu(v_.r(1)));
        if(dirp == nullptr) {
            v_.r(0) = -EFAULT;
            return true;
        }
        if(dirp->handle == 0) {
            v_.r(0) = -EBADF;
            return true;
        }
        DIR* dir = reinterpret_cast<DIR*>(static_cast<uintptr_t>(dirp->handle));
        if(closedir(dir) == -1) {
            v_.r(0) = -errno;
            return true;
        }
        fds().erase(dirp->fd);
        dirp->fd = -1;
        dirp->handle = 0;
        v_.r(0) = 0;
        return true;
    }

    bool do_fstatat() {
        int dirfd = arg_s32(v_.r(1));
        std::string path;
        if(!read_c_string(v_.r(2), path, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }
        auto out = static_cast<bpf::stat*>(v_.mmu(v_.r(3)));
        if(out == nullptr) {
            v_.r(0) = -EFAULT;
            return true;
        }
        int flags = arg_s32(v_.r(4));
        struct stat st = {};
        int rc = -1;
        if(dirfd == AT_FDCWD) {
            rc = fstatat(AT_FDCWD, resolve_path(path).c_str(), &st, flags);
        } else {
            auto it = fds().find(dirfd);
            if(it == fds().end()) {
                v_.r(0) = -EBADF;
                return true;
            }
            rc = fstatat(it->second->fd, path.c_str(), &st, flags);
        }
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        fill_bpf_stat64(st, *out);
        v_.r(0) = 0;
        return true;
    }

    bool do_fchmodat() {
        int dirfd = arg_s32(v_.r(1));
        std::string path;
        if(!read_c_string(v_.r(2), path, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }
        mode_t mode = (mode_t)arg_u32(v_.r(3));
        int flags = arg_s32(v_.r(4));
        int rc = -1;
        if(dirfd == AT_FDCWD) {
            rc = fchmodat(AT_FDCWD, resolve_path(path).c_str(), mode, flags);
        } else {
            auto it = fds().find(dirfd);
            if(it == fds().end()) {
                v_.r(0) = -EBADF;
                return true;
            }
            rc = fchmodat(it->second->fd, path.c_str(), mode, flags);
        }
        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = 0;
        return true;
    }

    bool do_utimensat() {
        int dirfd = arg_s32(v_.r(1));
        std::string path;
        bool has_path = (v_.r(2) != 0);

        if (has_path) {
            if(!read_c_string(v_.r(2), path, 4096)) {
                v_.r(0) = -EFAULT;
                return true;
            }
        }

        uint64_t times_addr = v_.r(3);
        int flags = arg_s32(v_.r(4));

        struct timespec pts[2];
        struct timespec* times_ptr = nullptr;

        if (times_addr != 0) {
            int64_t* raw = (int64_t*)v_.mmu(times_addr);
            if (raw == nullptr) {
                v_.r(0) = -EFAULT;
                return true;
            }
            pts[0].tv_sec = raw[0];
            pts[0].tv_nsec = raw[1];
            pts[1].tv_sec = raw[2];
            pts[1].tv_nsec = raw[3];
            times_ptr = pts;
        }

        int rc = -1;
        if (dirfd == AT_FDCWD) {
            if (!has_path) {
                v_.r(0) = -EFAULT;
                return true;
            }
            rc = utimensat(AT_FDCWD, resolve_path(path).c_str(), times_ptr, flags);
        } else {
            auto it = fds().find(dirfd);
            if (it == fds().end()) {
                v_.r(0) = -EBADF;
                return true;
            }
            rc = utimensat(it->second->fd, has_path ? path.c_str() : nullptr, times_ptr, flags);
        }

        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = 0;
        return true;
    }

    bool do_faccessat() {
        int dirfd = arg_s32(v_.r(1));
        std::string path;
        if(!read_c_string(v_.r(2), path, 4096)) {
            v_.r(0) = -EFAULT;
            return true;
        }
        int mode = arg_s32(v_.r(3));
        int flags = arg_s32(v_.r(4));

        int rc = -1;
        if (dirfd == AT_FDCWD) {
            rc = faccessat(AT_FDCWD, resolve_path(path).c_str(), mode, flags);
        } else {
            auto it = fds().find(dirfd);
            if(it == fds().end()) {
                v_.r(0) = -EBADF;
                return true;
            }
            rc = faccessat(it->second->fd, path.c_str(), mode, flags);
        }

        if(rc == -1) {
            v_.r(0) = -errno;
            return true;
        }
        v_.r(0) = 0;
        return true;
    }

    bool do_kill() {
        int target_pid = arg_s32(v_.r(1));
        int sig = arg_s32(v_.r(2));
        if(sig < 0 || sig >= NSIG || target_pid <= 0) {
            v_.r(0) = -EINVAL;
            return true;
        }
        if(sig == 0) {
            if(static_cast<uint64_t>(target_pid) == pid()) {
                v_.r(0) = 0;
                return true;
            }
            std::lock_guard<std::mutex> lock(pid_map_mutex());
            v_.r(0) = (pid_map().count(static_cast<uint64_t>(target_pid)) > 0) ? 0 : -ESRCH;
            return true;
        }
        if(static_cast<uint64_t>(target_pid) == pid()) {
            v_.queue_signal(sig);
            v_.r(0) = 0;
            return true;
        }
        std::shared_ptr<vm> target;
        {
            std::lock_guard<std::mutex> lock(pid_map_mutex());
            auto it = pid_map().find(static_cast<uint64_t>(target_pid));
            if(it != pid_map().end()) {
                target = it->second;
            }
        }
        if(target == nullptr) {
            v_.r(0) = -ESRCH;
            return true;
        }
        target->queue_signal(sig);
        v_.r(0) = 0;
        return true;
    }

    bool do_sigaction() {
        int signo = arg_s32(v_.r(1));
        uint64_t act_addr = v_.r(2);
        uint64_t oldact_addr = v_.r(3);

        if(signo <= 0 || signo >= NSIG || signo == SIGKILL || signo == SIGSTOP) {
            v_.r(0) = -EINVAL;
            return true;
        }

        if(oldact_addr != 0) {
            auto oldact = static_cast<struct bpf::sigaction*>(v_.mmu(oldact_addr));
            if(oldact == nullptr) {
                v_.r(0) = -EFAULT;
                return true;
            }
            const auto& current = signal_actions()[static_cast<size_t>(signo)];
            oldact->sa_handler = reinterpret_cast<void (*)(int)>(static_cast<uintptr_t>(current.handler));
            oldact->sa_mask = static_cast<bpf::sigset_t>(current.mask);
            oldact->sa_flags = current.flags;
        }

        if(act_addr != 0) {
            auto action = static_cast<const struct bpf::sigaction*>(v_.mmu(act_addr));
            if(action == nullptr) {
                v_.r(0) = -EFAULT;
                return true;
            }
            if(reinterpret_cast<uintptr_t>(action->sa_handler) == reinterpret_cast<uintptr_t>(SIG_ERR)) {
                v_.r(0) = -EINVAL;
                return true;
            }
            auto& current = signal_actions()[static_cast<size_t>(signo)];
            current.handler = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(action->sa_handler));
            current.mask = static_cast<uint64_t>(action->sa_mask);
            current.flags = action->sa_flags;
        }

        v_.r(0) = 0;
        return true;
    }

    bool do_fcntl() {
        auto it = fds().find(arg_s32(v_.r(1)));
        if(it == fds().end()) {
            v_.r(0) = -EBADF;
            return true;
        }
        int cmd = arg_s32(v_.r(2));
        if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
            int min_fd = arg_s32(v_.r(3));
            if (min_fd < 0) {
                v_.r(0) = -EINVAL;
                return true;
            }

            int new_fd = allocate_fd(min_fd);

            int new_host_fd = dup(it->second->fd);
            if(new_host_fd < 0) {
                v_.r(0) = -errno;
                return true;
            }

            auto new_handle = std::make_shared<fd_handle>(new_host_fd, it->second->path);
            if (cmd == F_DUPFD_CLOEXEC) {
                new_handle->cloexec = true;
            }
            fds()[new_fd] = new_handle;
            v_.r(0) = new_fd;
            return true;
        }
        if (cmd == F_GETFD) {
            v_.r(0) = it->second->cloexec ? FD_CLOEXEC : 0;
            return true;
        }
        if (cmd == F_SETFD) {
            it->second->cloexec = (v_.r(3) & FD_CLOEXEC) != 0;
            v_.r(0) = 0;
            return true;
        }

        uint64_t arg = v_.r(3);
        int rc = -1;
        if (cmd == F_GETLK || cmd == F_SETLK || cmd == F_SETLKW) {
             rc = fcntl(it->second->fd, cmd, v_.mmu(arg));
        } else {
             rc = fcntl(it->second->fd, cmd, arg);
        }

        if(rc == -1) {
            v_.r(0) = -errno;
        } else {
            v_.r(0) = rc;
        }
        return true;
    }

    bool do_ioctl() {
        auto it = fds().find(arg_s32(v_.r(1)));
        if(it == fds().end()) {
            v_.r(0) = -EBADF;
            return true;
        }
        unsigned long request = v_.r(2);
        int rc;

        if (request == TCGETS) {
            struct termios host_t = {};
            rc = ioctl(it->second->fd, TCGETS, &host_t);
            if (rc == 0) {
                auto guest_t = (bpf::termios*)v_.mmu(v_.r(3));
                if (guest_t) {
                    guest_t->c_lflag = host_t.c_lflag;
                } else {
                    v_.r(0) = -EFAULT;
                    return true;
                }
            }
        } else if (request == TIOCGWINSZ) {
            void* arg = v_.mmu(v_.r(3), sizeof(struct winsize));
            if(arg == nullptr) {
                v_.r(0) = -EFAULT;
                return true;
            }
            rc = ioctl(it->second->fd, TIOCGWINSZ, arg);
        } else {
            // Check if the command has a size field > 0, indicating a pointer argument.
            // Linux ioctl encoding: size is bits 16-29 (14 bits).
            size_t ioctl_size = (request >> 16) & 0x3FFF;
            if (ioctl_size) {
                void* arg = v_.mmu(v_.r(3), ioctl_size);
                if(arg == nullptr) {
                    v_.r(0) = -EFAULT;
                    return true;
                }
                rc = ioctl(it->second->fd, request, arg);
            } else {
                rc = ioctl(it->second->fd, request, (void*)v_.r(3));
            }
        }

        if(rc == -1) {
            v_.r(0) = -errno;
        } else {
            v_.r(0) = rc;
        }
        return true;
    }

    bool do_umask() {
        uint32_t new_mask = arg_u32(v_.r(1));
        v_.r(0) = umask_val();
        umask_val() = new_mask & 0777;
        return true;
    }

    bool do_setjmp() {
        uint64_t env_addr = v_.r(1);
        uint64_t* env = (uint64_t*)v_.mmu(env_addr);
        if (!env) {
            v_.r(0) = -EFAULT;
            return true;
        }
        env[0] = v_.r(6);
        env[1] = v_.r(7);
        env[2] = v_.r(8);
        env[3] = v_.r(9);
        env[4] = v_.r(10);
        env[5] = v_.unmmu(pc());
        env[6] = signal_depth();
        v_.r(0) = 0;
        return true;
    }

    bool do_longjmp() {
        uint64_t env_addr = v_.r(1);
        int32_t val = arg_s32(v_.r(2));
        uint64_t* env = (uint64_t*)v_.mmu(env_addr);
        if (!env) {
            v_.r(0) = -EFAULT;
            return true;
        }
        v_.r(6) = env[0];
        v_.r(7) = env[1];
        v_.r(8) = env[2];
        v_.r(9) = env[3];
        v_.r(10) = env[4];
        uint64_t saved_pc = env[5];
        signal_depth() = static_cast<size_t>(env[6]);
        pc() = (const bpf_insn*)v_.mmu(saved_pc);
        // pc points to syscall instruction.
        // loop increments pc.
        // next instruction is executed.

        v_.r(0) = (val == 0) ? 1 : val;
        return true;
    }

    bool dispatch(uint32_t call) {
        uint32_t sys_id = call;
        if(call >= BPF_CALL_BASE) {
            sys_id = BPF_CALL_TO_ID(call);
        }
        switch (sys_id) {
        case BPF_SYS_MMAP:          return do_mmap();
        case BPF_SYS_MUNMAP:        return do_munmap();
        case BPF_SYS_EXIT:          return do_exit();
        case BPF_SYS_NANOSLEEP:     return do_nanosleep();
        case BPF_SYS_OPENAT:        return do_openat();
        case BPF_SYS_READ:          return do_read();
        case BPF_SYS_WRITE:         return do_write();
        case BPF_SYS_LSEEK:         return do_lseek();
        case BPF_SYS_TRUNCATE:      return do_truncate();
        case BPF_SYS_FTRUNCATE:     return do_ftruncate();
        case BPF_SYS_CLOSE:         return do_close();
        case BPF_SYS_UNLINKAT:      return do_unlinkat();
        case BPF_SYS_MKDIR:         return do_mkdir();
        case BPF_SYS_RMDIR:         return do_rmdir();
        case BPF_SYS_SYMLINKAT:     return do_symlinkat();
        case BPF_SYS_LINKAT:        return do_linkat();
        case BPF_SYS_RENAMEAT:      return do_renameat();
        case BPF_SYS_READLINK:      return do_readlink();
        case BPF_SYS_EXECVE:        return do_execve();
        case BPF_SYS_FORK:          return do_fork();
        case BPF_SYS_GETPID:        return do_getpid();
        case BPF_SYS_GETPPID:       return do_getppid();
        case BPF_SYS_WAITPID:       return do_waitpid();
        case BPF_SYS_DUP:           return do_dup();
        case BPF_SYS_DUP2:          return do_dup2();
        case BPF_SYS_PIPE2:         return do_pipe2();
        case BPF_SYS_FCHDIR:        return do_fchdir();
        case BPF_SYS_GETCWD:        return do_getcwd();
        case BPF_SYS_FDOPENDIR:     return do_fdopendir();
        case BPF_SYS_READDIR:       return do_readdir();
        case BPF_SYS_CLOSEDIR:      return do_closedir();
        case BPF_SYS_FSTATAT:       return do_fstatat();
        case BPF_SYS_FCHMODAT:      return do_fchmodat();
        case BPF_SYS_UTIMENSAT:     return do_utimensat();
        case BPF_SYS_FACCESSAT:     return do_faccessat();
        case BPF_SYS_KILL:          return do_kill();
        case BPF_SYS_SIGACTION:     return do_sigaction();
        case BPF_SYS_FCNTL:         return do_fcntl();
        case BPF_SYS_IOCTL:         return do_ioctl();
        case BPF_SYS_UMASK:         return do_umask();
        case BPF_SYS_SETJMP:        return do_setjmp();
        case BPF_SYS_LONGJMP:       return do_longjmp();
        case BPF_SYS_CLOCK_GETTIME: return do_clock_gettime();
        default:
            fprintf(stderr, "unsupported func: 0x%x\n", call);
            v_.r(0) = -ENOSYS;
            return true;
        }
    }
};

bool posix_syscall(vm& v, uint32_t call) {
    return PosixSyscalls(v).dispatch(call);
}
