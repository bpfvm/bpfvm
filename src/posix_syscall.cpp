#include "posix_syscall.h"
#include "include/bpf_call.h"
namespace bpf{
    #define BPF_NO_SYSCALL
    #include "include/signal.h"
    #include "include/sys/stat.h"
    #include "include/dirent.h"
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
#include <signal.h>
#include <pthread.h>

#undef sa_handler
#undef sa_sigaction

MpscQueue::MpscQueue() {
    for(size_t i = 0; i < k_capacity; ++i) {
        slots[i].seq.store(i, std::memory_order_relaxed);
    }
}

bool MpscQueue::try_push(int value) {
    uint64_t pos = tail.load(std::memory_order_relaxed);
    while(true) {
        slot& s = slots[pos & k_mask];
        uint64_t seq = s.seq.load(std::memory_order_acquire);
        intptr_t dif = (intptr_t)seq - (intptr_t)pos;
        if(dif == 0) {
            if(tail.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                s.value = value;
                s.seq.store(pos + 1, std::memory_order_release);
                return true;
            }
        } else if(dif < 0) {
            return false;
        } else {
            pos = tail.load(std::memory_order_relaxed);
        }
    }
}

bool MpscQueue::try_pop(int& value) {
    uint64_t pos = head.load(std::memory_order_relaxed);
    while(true) {
        slot& s = slots[pos & k_mask];
        uint64_t seq = s.seq.load(std::memory_order_acquire);
        intptr_t dif = (intptr_t)seq - (intptr_t)(pos + 1);
        if(dif == 0) {
            if(head.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                value = s.value;
                s.seq.store(pos + k_capacity, std::memory_order_release);
                return true;
            }
        } else if(dif < 0) {
            return false;
        } else {
            pos = head.load(std::memory_order_relaxed);
        }
    }
}

std::atomic<uint64_t> PosixSyscall::next_pid{1};
std::unordered_map<uint64_t, std::shared_ptr<vm>> PosixSyscall::pid_map{};
std::mutex PosixSyscall::pid_map_mutex;

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

fd_handle::~fd_handle() {
    if(fd >= 0) {
        close(fd);
    }
}

PosixSyscall::PosixSyscall() {
    pid = next_pid.fetch_add(1);
    fds.emplace(0, std::make_shared<fd_handle>(dup(STDIN_FILENO)));
    fds.emplace(1, std::make_shared<fd_handle>(dup(STDOUT_FILENO)));
    fds.emplace(2, std::make_shared<fd_handle>(dup(STDERR_FILENO)));

    char buf[PATH_MAX];
    if(::getcwd(buf, sizeof(buf)) != nullptr) {
        cwd = buf;
    } else {
        cwd = "/";
    }
}

PosixSyscall::PosixSyscall(uint64_t ppid, const std::unordered_map<int, std::shared_ptr<fd_handle>>& opened, std::string cwd_) {
    pid = next_pid.fetch_add(1);
    this->ppid = ppid;
    fds = opened;
    cwd = cwd_;
}

void PosixSyscall::init(const std::shared_ptr<vm>& v){
    tid = pthread_self();
    std::lock_guard<std::mutex> lock(pid_map_mutex);
    //这里只对1号进程添加，其他进程由fork添加，因为推迟到这里就太晚了
    if(pid == 1) pid_map[pid] = v;
}

void PosixSyscall::fini(const std::shared_ptr<vm>& v) {
    fds.clear();
    signal_depth(v.get()) = 0;
    if(pid == 1) {
        return;
    }
    maps(v.get()).clear();
    std::lock_guard<std::mutex> lock(pid_map_mutex);
    for(auto& entry : pid_map) {
        auto child_sys = sys(entry.second.get());
        if(child_sys && child_sys->ppid.load() == pid) {
            child_sys->ppid.store(1);
        }
    }
}

void PosixSyscall::queue_signal(vm* v, int sig) {
    if(sig == SIGKILL) {
        flags(v).fetch_or(vm::VM_KILLED, std::memory_order_release);
        v->wakeup();
    } else if(sig == SIGSTOP) {
        flags(v).fetch_or(vm::VM_STOPPED, std::memory_order_release);
        v->wakeup();
    } else if(sig == SIGCONT) {
        flags(v).fetch_and(~vm::VM_STOPPED, std::memory_order_release);
        v->wakeup();
    } else {
        // Best-effort: drop if the queue is full to avoid blocking the VM thread.
        if(pending_signals.try_push(sig)) {
            flags(v).fetch_or(vm::VM_SIGNAL_PENDING, std::memory_order_release);
        }
    }
    if (tid != 0) {
        pthread_kill(tid, SIGUSR1);
    }
}

bool PosixSyscall::handle_signals(vm* v) {
    int sig = 0;
    if(!pending_signals.try_pop(sig)) {
        // Queue is empty. Clear VM_SIGNAL_PENDING with a seq_cst fence, then
        // re-check to close the race window with a concurrent queue_signal:
        // if another thread pushed between try_pop and the clear, the second
        // try_pop will catch it; if it pushed after the clear, it will have
        // set VM_SIGNAL_PENDING again, so the next safepoint() will retry.
        flags(v).fetch_and(~vm::VM_SIGNAL_PENDING, std::memory_order_seq_cst);
        if(!pending_signals.try_pop(sig)) {
            return true;
        }
        flags(v).fetch_or(vm::VM_SIGNAL_PENDING, std::memory_order_relaxed);
    }
    if(sig <= 0 || sig >= NSIG) {
        return true;
    }
    const uint64_t sig_dfl = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_DFL));
    const uint64_t sig_ign = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_IGN));
    uint64_t handler = signal_actions[static_cast<size_t>(sig)].handler;
    if(options(v).verbose) {
        std::lock_guard<std::mutex> lock(log_mutex);
        printf("[#%d] signal %d handler=0x%lx return=0x%lx\n",
               id(), sig, static_cast<unsigned long>(handler), pc(v));
    }
    if(handler == sig_ign) {
        return true;
    }
    if(handler == sig_dfl) {
        switch(sig) {
        case SIGTERM:
        case SIGINT:
        case SIGABRT:
        case SIGSEGV:
        case SIGILL:
        case SIGFPE:
            v->r(1) = 128 + static_cast<uint64_t>(sig);
            return do_exit(v);
        case SIGTSTP:
        case SIGTTIN:
        case SIGTTOU:
            flags(v).fetch_or(vm::VM_STOPPED, std::memory_order_release);
            v->wakeup();
            return true;
        default:
            return true;
        }
    }

    if(!v->mmu(handler)) {
        v->r(1) = 128 + static_cast<uint64_t>(SIGSEGV);
        return do_exit(v);
    }
    if(!v->push_frame(pc(v), true)) {
        v->r(1) = 128 + static_cast<uint64_t>(SIGBUS);
        return do_exit(v);
    }
    v->r(1) = static_cast<uint64_t>(sig);
    pc(v) = handler;
    return true;
}

std::shared_ptr<PosixSyscall> PosixSyscall::sys(vm* v) {
    if (v == nullptr) {
        return nullptr;
    }
    return std::dynamic_pointer_cast<PosixSyscall>(options(v).sys);
}


int PosixSyscall::allocate_fd(int min_fd) {
    int fd = min_fd;
    while(fds.count(fd)) {
        fd++;
    }
    return fd;
}

bool PosixSyscall::read_c_string(vm* v, uint64_t addr, std::string& out, size_t max_len) {
    out.clear();
    if(addr == 0) {
        return false;
    }
    for(size_t i = 0; i < max_len; i++) {
        void* p = v->mmu(addr + i);
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

bool PosixSyscall::read_c_string_array(vm* v, uint64_t addr, std::vector<std::string>& out, size_t max_count, size_t max_str_len) {
    out.clear();
    if(addr == 0) {
        return true;
    }
    for(size_t i = 0; i < max_count; i++) {
        void* p = v->mmu(addr + i * sizeof(uint64_t));
        if(p == nullptr) {
            return false;
        }
        uint64_t str_addr = *(uint64_t*)p;
        if(str_addr == 0) {
            return true;
        }
        std::string value;
        if(!read_c_string(v, str_addr, value, max_str_len)) {
            return false;
        }
        out.push_back(std::move(value));
    }
    return false;
}

std::string PosixSyscall::resolve_path(const std::string& path) {
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

bool PosixSyscall::do_clock_gettime(vm* v) {
    clockid_t clock_id = (clockid_t)arg_s32(v->r(1));
    struct timespec* tp = (struct timespec*)v->mmu_w(v->r(2), sizeof(*tp));
    if(tp == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    if(clock_gettime(clock_id, tp) == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_mmap(vm* v) {
    int prot = arg_s32(v->r(2));
    int flags = arg_s32(v->r(3));
    int fd = arg_s32(v->r(4));
    int host_fd = -1;

    if (!(flags & MAP_ANONYMOUS)) {
        auto it = fds.find(fd);
        if (it == fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        host_fd = it->second->fd;
    }

    void* addr = mmap(nullptr, arg_size(v->r(1)), prot, flags, host_fd, (off_t)v->r(5));
    if(addr == MAP_FAILED) {
        v->r(0) = -errno;
        return true;
    }
    memmap mem;
    mem.size = arg_size(v->r(1));
    mem.set_data((unsigned char*)addr, mem.size);
    mem.paddr = maps(v).back().paddr + maps(v).back().size;
    mem.flags = 0;
    if(prot & PROT_READ) {
        mem.flags |= PF_R;
    }
    if(prot & PROT_WRITE) {
        mem.flags |= PF_W;
    }
    if(prot & PROT_EXEC) {
        mem.flags |= PF_X;
    }
    v->r(0) = mem.paddr;
    v->addmem(std::move(mem));
    return true;
}

bool PosixSyscall::do_munmap(vm* v) {
    if(!v->unmap(v->r(1))) {
        v->r(0) = -EINVAL;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_exit(vm* v) {
    v->r(0) = (uint64_t)arg_s32(v->r(1));
    return false;
}

bool PosixSyscall::do_nanosleep(vm* v) {
    const struct timespec* req = static_cast<const struct timespec*>(v->mmu(v->r(1)));
    if(req == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }

    struct timespec* rem = nullptr;
    if(v->r(2) != 0) {
        rem = static_cast<struct timespec*>(v->mmu_w(v->r(2), sizeof(*rem)));
        if(rem == nullptr) {
            v->r(0) = -EFAULT;
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
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_openat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int flags = arg_s32(v->r(3));
    mode_t mode = (mode_t)(arg_u32(v->r(4)) & ~umask_val);
    int fd = -1;
    std::string resolved;
    if(dirfd == AT_FDCWD) {
        resolved = resolve_path(path);
        fd = openat(AT_FDCWD, resolved.c_str(), flags, mode);
    } else {
        auto it = fds.find(dirfd);
        if(it == fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        fd = openat(it->second->fd, path.c_str(), flags, mode);
        if(!it->second->path.empty()) {
            resolved = (std::filesystem::path(it->second->path) / path).lexically_normal().string();
        }
    }
    if(fd == -1) {
        v->r(0) = -errno;
        return true;
    }
    auto handle = std::make_shared<fd_handle>(fd, std::move(resolved));
    if(flags & O_CLOEXEC) {
        handle->cloexec = true;
    }
    int guest_fd = allocate_fd();
    fds[guest_fd] = handle;
    v->r(0) = guest_fd;
    return true;
}

bool PosixSyscall::do_read(vm* v) {
    auto it = fds.find(arg_s32(v->r(1)));
    if(it == fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu_w(v->r(2), count);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    int rc = read(it->second->fd, buf, count);
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = rc;
    return true;
}

bool PosixSyscall::do_write(vm* v) {
    auto it = fds.find(arg_s32(v->r(1)));
    if(it == fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu(v->r(2), count);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    int rc = write(it->second->fd, buf, count);
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = rc;
    return true;
}

bool PosixSyscall::do_lseek(vm* v) {
    auto it = fds.find(arg_s32(v->r(1)));
    if(it == fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    int rc = lseek64(it->second->fd, (off_t)v->r(2), arg_s32(v->r(3)));
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = rc;
    return true;
}

bool PosixSyscall::do_truncate(vm* v) {
    std::string path;
    if(!read_c_string(v, v->r(1), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int rc = truncate(resolve_path(path).c_str(), static_cast<off_t>(v->r(2)));
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_ftruncate(vm* v) {
    auto it = fds.find(arg_s32(v->r(1)));
    if(it == fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    int rc = ftruncate(it->second->fd, static_cast<off_t>(v->r(2)));
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_close(vm* v) {
    auto it = fds.find(arg_s32(v->r(1)));
    if(it == fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    fds.erase(it);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_unlinkat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int flags = arg_s32(v->r(3));
    int rc = -1;
    if(dirfd == AT_FDCWD) {
        rc = unlinkat(AT_FDCWD, resolve_path(path).c_str(), flags);
    } else {
        auto it = fds.find(dirfd);
        if(it == fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        rc = unlinkat(it->second->fd, path.c_str(), flags);
    }
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_mkdir(vm* v) {
    std::string path;
    if(!read_c_string(v, v->r(1), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int rc = mkdir(resolve_path(path).c_str(), (mode_t)(arg_u32(v->r(2)) & ~umask_val));
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_rmdir(vm* v) {
    std::string path;
    if(!read_c_string(v, v->r(1), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int rc = rmdir(resolve_path(path).c_str());
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_symlinkat(vm* v) {
    std::string target;
    std::string linkpath;
    if(!read_c_string(v, v->r(1), target, 4096) || !read_c_string(v, v->r(3), linkpath, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int new_dirfd = arg_s32(v->r(2));
    int rc = -1;
    if(new_dirfd == AT_FDCWD) {
        rc = symlinkat(target.c_str(), AT_FDCWD, resolve_path(linkpath).c_str());
    } else {
        auto it = fds.find(new_dirfd);
        if(it == fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        rc = symlinkat(target.c_str(), it->second->fd, linkpath.c_str());
    }
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_linkat(vm* v) {
    std::string oldpath;
    std::string newpath;
    if(!read_c_string(v, v->r(2), oldpath, 4096) || !read_c_string(v, v->r(4), newpath, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int olddirfd = arg_s32(v->r(1));
    int newdirfd = arg_s32(v->r(3));
    int flags = arg_s32(v->r(5));

    int host_olddirfd = AT_FDCWD;
    if (olddirfd != AT_FDCWD) {
        auto it = fds.find(olddirfd);
        if (it == fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        host_olddirfd = it->second->fd;
    }

    int host_newdirfd = AT_FDCWD;
    if (newdirfd != AT_FDCWD) {
        auto it = fds.find(newdirfd);
        if (it == fds.end()) {
            v->r(0) = -EBADF;
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
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_renameat(vm* v) {
    std::string old_path;
    std::string new_path;
    if(!read_c_string(v, v->r(2), old_path, 4096) || !read_c_string(v, v->r(4), new_path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int old_dirfd = arg_s32(v->r(1));
    int new_dirfd = arg_s32(v->r(3));

    int host_old_dirfd = AT_FDCWD;
    if (old_dirfd != AT_FDCWD) {
        auto it = fds.find(old_dirfd);
        if (it == fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        host_old_dirfd = it->second->fd;
    }

    int host_new_dirfd = AT_FDCWD;
    if (new_dirfd != AT_FDCWD) {
        auto it = fds.find(new_dirfd);
        if (it == fds.end()) {
            v->r(0) = -EBADF;
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
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_readlink(vm* v) {
    std::string path;
    if(!read_c_string(v, v->r(1), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    size_t bufsiz = arg_size(v->r(3));
    char* buf = (char*)v->mmu_w(v->r(2), bufsiz);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    int rc = readlink(resolve_path(path).c_str(), buf, bufsiz);
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = rc;
    return true;
}

bool PosixSyscall::do_execve(vm* v) {
    std::string path;
    std::vector<std::string> argv_strings;
    std::vector<std::string> envp_strings;
    if(!read_c_string(v, v->r(1), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    if(!read_c_string_array(v, v->r(2), argv_strings, 1024, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    if(!read_c_string_array(v, v->r(3), envp_strings, 1024, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }

    auto fresh = vm::create();
    uint64_t entry = fresh->load_elf(resolve_path(path).c_str());
    if(entry == 0) {
        v->r(0) = -ENOEXEC;
        return true;
    }
    if(!fresh->setup_stack(argv_strings, envp_strings)) {
        v->r(0) = -E2BIG;
        return true;
    }
    if(!fresh->mmu(entry)) {
        v->r(0) = -ENOEXEC;
        return true;
    }
    maps(v).swap(maps(fresh.get()));
    v->flush_tlb();
    // execve 替换了整个 guest 地址空间：旧程序编译的 JIT 函数全部失效。
    // 且新旧程序共享相同的 guest 地址区间（都从 0x400000 链接），必须清空缓存，
    // 否则会误命中旧程序的编译产物。
    v->clear_jit_cache();

    decltype(signal_actions) new_actions{};
    const uint64_t sig_dfl = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_DFL));
    const uint64_t sig_ign = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_IGN));
    for(size_t i = 0; i < new_actions.size(); i++) {
        if(signal_actions[i].handler == sig_ign) {
            new_actions[i].handler = sig_ign;
        } else {
            new_actions[i].handler = sig_dfl;
        }
    }
    signal_actions = new_actions;
    signal_depth(v) = 0;

    std::unordered_map<int, std::shared_ptr<fd_handle>> new_fds;
    for (const auto& entry : fds) {
        if (!entry.second->cloexec) {
            new_fds.insert(entry);
        }
    }
    fds.swap(new_fds);
    v->r(1) = fresh->r(1);
    v->r(10) = STACK_BASE + STACK_SIZE - 8;
    pc(v) = entry;
    v->push_frame(0);
    pc(v) -= sizeof(bpf_insn);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_fork(vm* v) {
    std::unordered_map<int, std::shared_ptr<fd_handle>> child_fds;
    for(const auto& entry : fds) {
        int new_host_fd = dup(entry.second->fd);
        if(new_host_fd < 0) {
            v->r(0) = -errno;
            return true;
        }
        auto new_handle = std::make_shared<fd_handle>(new_host_fd, entry.second->path);
        new_handle->cloexec = entry.second->cloexec;
        child_fds[entry.first] = new_handle;
    }

    auto child = vm::create();
    options(child.get()) = options(v);
    signal_depth(child.get()) = signal_depth(v);

    auto child_sys = std::make_shared<PosixSyscall>(pid, child_fds, cwd);
    child_sys->umask_val = umask_val;
    child_sys->signal_actions = signal_actions;
    options(child.get()).sys = child_sys;

    for(auto& map : maps(v)) {
        memmap child_map;
        child_map.size  = map.size;
        child_map.paddr = map.paddr;
        child_map.flags = map.flags;

        if(map.flags & PF_W) {
            if(!map.cow_data && map.data.get_deleter().owned) {
                // First fork: convert parent mapping to CoW
                // Note: PF_W + owned==false + cow_data==null is intentionally left as-is;
                // it represents externally-managed shared memory (MAP_SHARED semantics) where
                // writes are meant to be visible across parent and child.
                map.cow_data = std::shared_ptr<unsigned char>(
                    map.data.get(), DataDeleter{map.data.get_deleter().size, true});
                map.data.get_deleter().owned = false; // transfer ownership to cow_data
            }
            child_map.set_data(map.data.get(), map.size, false);
            child_map.cow_data = map.cow_data;
        } else {
            // Read-only mapping: share pointer directly (mmu_w rejects writes)
            child_map.set_data(map.data.get(), map.size, false);
        }
        child->addmem(std::move(child_map));
    }

    v->flush_tlb();

    for(size_t i = 0; i < 11; i++) {
        child->r(i) = v->r(i);
    }
    child->r(0) = 0;

    uint64_t pc_addr = pc(v);
    if(!child->mmu(pc_addr)) {
        v->r(0) = -EFAULT;
        return true;
    }
    pc(child.get()) = pc_addr + sizeof(bpf_insn);
    pthread_attr_t attr;
    pthread_t worker;
    int rc = pthread_attr_init(&attr);
    if(rc != 0) {
        v->r(0) = -rc;
        return true;
    }
    rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if(rc != 0) {
        pthread_attr_destroy(&attr);
        v->r(0) = -rc;
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
        v->r(0) = -rc;
        return true;
    }
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        pid_map[child_sys->pid] = child;
    }
    v->r(0) = child_sys->pid;
    return true;
}

bool PosixSyscall::do_getpid(vm* v) {
    v->r(0) = pid;
    return true;
}

bool PosixSyscall::do_getppid(vm* v) {
    v->r(0) = ppid.load();
    return true;
}

bool PosixSyscall::do_waitpid(vm* v) {
    int64_t target_pid = static_cast<int64_t>(arg_s32(v->r(1)));
    uint64_t status_addr = v->r(2);
    int32_t options = arg_s32(v->r(3));

    if((options & ~WNOHANG) != 0) {
        v->r(0) = -EINVAL;
        return true;
    }

    if(target_pid == (int64_t)pid || target_pid == 0) {
        v->r(0) = -EINVAL;
        return true;
    }

    int* status_ptr = nullptr;
    if(status_addr != 0) {
        status_ptr = static_cast<int*>(v->mmu_w(status_addr, sizeof(*status_ptr)));
        if(status_ptr == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
    }

    std::vector<std::shared_ptr<vm>> children;
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        if(target_pid == -1) {
            for(const auto& entry : pid_map) {
                auto child_sys = sys(entry.second.get());
                if(child_sys && child_sys->ppid.load() != pid) {
                    continue;
                }
                if(flags(entry.second.get()).load(std::memory_order_acquire) & vm::VM_EXITED) {
                    children.clear();
                    children.push_back(entry.second);
                    break;
                }
                children.push_back(entry.second);
            }
        } else if(target_pid > 0) {
            auto it = pid_map.find(static_cast<uint64_t>(target_pid));
            if(it == pid_map.end()) {
                v->r(0) = -ECHILD;
                return true;
            }
            auto child_sys = sys(it->second.get());
            if(child_sys == nullptr || child_sys->ppid.load() != pid) {
                v->r(0) = -ECHILD;
                return true;
            }
            children.push_back(it->second);
        } else {
            v->r(0) = -EINVAL;
            return true;
        }
    }

    if(children.empty()) {
        v->r(0) = -ECHILD;
        return true;
    }

    std::shared_ptr<vm> child;
    if(children.size() == 1 && (flags(children[0].get()).load(std::memory_order_acquire) & vm::VM_EXITED)) {
        child = children[0];
    } else {
        if(options & WNOHANG) {
            v->r(0) = 0;
            return true;
        }

        do {
            for(const auto& candidate : children) {
                if(candidate->wait_for_exit(100)) {
                    child = candidate;
                    break;
                }
                if(!pending_signals.empty() || (flags(v).load(std::memory_order_acquire) & vm::VM_EXITED)) {
                    v->r(0) = -EINTR;
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

    uint64_t child_pid = sys(child.get())->pid;
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        pid_map.erase(child_pid);
    }
    v->r(0) = child_pid;
    return true;
}

bool PosixSyscall::do_dup(vm* v) {
    int old_fd = arg_s32(v->r(1));
    if(old_fd < 0) {
        v->r(0) = -EBADF;
        return true;
    }

    auto it = fds.find(old_fd);
    if(it == fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }

    int new_host_fd = dup(it->second->fd);
    if(new_host_fd < 0) {
        v->r(0) = -errno;
        return true;
    }

    int new_fd = allocate_fd();
    fds[new_fd] = std::make_shared<fd_handle>(new_host_fd, it->second->path);
    v->r(0) = new_fd;
    return true;
}

bool PosixSyscall::do_dup2(vm* v) {
    int old_fd = arg_s32(v->r(1));
    int new_fd = arg_s32(v->r(2));
    if(old_fd < 0 || new_fd < 0) {
        v->r(0) = -EBADF;
        return true;
    }

    auto it = fds.find(old_fd);
    if(it == fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }

    if(old_fd == new_fd) {
        v->r(0) = new_fd;
        return true;
    }

    int new_host_fd = dup(it->second->fd);
    if(new_host_fd < 0) {
        v->r(0) = -errno;
        return true;
    }

    fds[new_fd] = std::make_shared<fd_handle>(new_host_fd, it->second->path);
    v->r(0) = new_fd;
    return true;
}

bool PosixSyscall::do_pipe2(vm* v) {
    int* pipefd = static_cast<int*>(v->mmu_w(v->r(1), 2 * sizeof(int)));
    if(pipefd == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }

    int flags = arg_s32(v->r(2));
    int host_fds[2] = {-1, -1};

    int rc = pipe2(host_fds, flags);
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }

    int guest_fd0 = allocate_fd();
    auto handle0 = std::make_shared<fd_handle>(host_fds[0]);
    if (flags & O_CLOEXEC) {
        handle0->cloexec = true;
    }
    fds[guest_fd0] = handle0;

    int guest_fd1 = allocate_fd(guest_fd0 + 1);
    auto handle1 = std::make_shared<fd_handle>(host_fds[1]);
    if (flags & O_CLOEXEC) {
        handle1->cloexec = true;
    }
    fds[guest_fd1] = handle1;

    pipefd[0] = guest_fd0;
    pipefd[1] = guest_fd1;
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_fchdir(vm* v) {
    int fd = arg_s32(v->r(1));
    auto it = fds.find(fd);
    if(it == fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    struct stat st = {};
    if(fstat(it->second->fd, &st) == -1) {
        v->r(0) = -errno;
        return true;
    }
    if(!S_ISDIR(st.st_mode)) {
        v->r(0) = -ENOTDIR;
        return true;
    }
    if(it->second->path.empty()) {
        v->r(0) = -ENOENT;
        return true;
    }
    cwd = it->second->path;
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_getcwd(vm* v) {
    uint64_t buf_addr = v->r(1);
    size_t size = arg_size(v->r(2));
    if(size == 0) {
        v->r(0) = -ERANGE;
        return true;
    }
    char* buf = static_cast<char*>(v->mmu_w(buf_addr, size));
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    std::string path = cwd.empty() ? "/" : cwd;
    if(size <= path.size()) {
        v->r(0) = -ERANGE;
        return true;
    }
    memcpy(buf, path.c_str(), path.size() + 1);
    v->r(0) = path.size() + 1;
    return true;
}

bool PosixSyscall::do_fdopendir(vm* v) {
    int fd = arg_s32(v->r(1));
    auto out_dir = static_cast<bpf::DIR*>(v->mmu_w(v->r(2), sizeof(bpf::DIR)));
    if(out_dir == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    auto it = fds.find(fd);
    if(it == fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    it->second->cloexec = true;
    DIR* dir = fdopendir(it->second->fd);
    if(dir == nullptr) {
        v->r(0) = -errno;
        return true;
    }
    out_dir->handle = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(dir));
    out_dir->fd = fd;
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_readdir(vm* v) {
    auto dirp = static_cast<bpf::DIR*>(v->mmu(v->r(1)));
    if(dirp == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    auto out_entry = static_cast<bpf::dirent*>(v->mmu_w(v->r(2), sizeof(bpf::dirent)));
    if(out_entry == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    if(dirp->handle == 0) {
        v->r(0) = -EBADF;
        return true;
    }
    DIR* dir = reinterpret_cast<DIR*>(static_cast<uintptr_t>(dirp->handle));
    errno = 0;
    struct dirent* ent = readdir(dir);
    if(ent == nullptr) {
        if(errno != 0) {
            v->r(0) = -errno;
        } else {
            v->r(0) = 0;
        }
        return true;
    }
    memset(out_entry, 0, sizeof(*out_entry));
    // 已 memset 整块清零，d_name 尾部为 '\0'；用 strnlen+memcpy 拷贝实际长度，
    // 避免 strncpy 在源串恰好填满时的 -Wstringop-truncation 告警（语义不变）。
    size_t name_len = strnlen(ent->d_name, sizeof(out_entry->d_name) - 1);
    memcpy(out_entry->d_name, ent->d_name, name_len);
#ifdef _DIRENT_HAVE_D_TYPE
    out_entry->d_type = ent->d_type;
#else
    out_entry->d_type = DT_UNKNOWN;
#endif
    v->r(0) = 1;
    return true;
}

bool PosixSyscall::do_closedir(vm* v) {
    auto dirp = static_cast<bpf::DIR*>(v->mmu_w(v->r(1), sizeof(bpf::DIR)));
    if(dirp == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    if(dirp->handle == 0) {
        v->r(0) = -EBADF;
        return true;
    }
    DIR* dir = reinterpret_cast<DIR*>(static_cast<uintptr_t>(dirp->handle));
    if(closedir(dir) == -1) {
        v->r(0) = -errno;
        return true;
    }
    fds.erase(dirp->fd);
    dirp->fd = -1;
    dirp->handle = 0;
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_fstatat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    auto out = static_cast<bpf::stat*>(v->mmu_w(v->r(3), sizeof(bpf::stat)));
    if(out == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    int flags = arg_s32(v->r(4));
    struct stat st = {};
    int rc = -1;
    if(dirfd == AT_FDCWD) {
        rc = fstatat(AT_FDCWD, resolve_path(path).c_str(), &st, flags);
    } else {
        auto it = fds.find(dirfd);
        if(it == fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        rc = fstatat(it->second->fd, path.c_str(), &st, flags);
    }
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    fill_bpf_stat64(st, *out);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_fchmodat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    mode_t mode = (mode_t)arg_u32(v->r(3));
    int flags = arg_s32(v->r(4));
    int rc = -1;
    if(dirfd == AT_FDCWD) {
        rc = fchmodat(AT_FDCWD, resolve_path(path).c_str(), mode, flags);
    } else {
        auto it = fds.find(dirfd);
        if(it == fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        rc = fchmodat(it->second->fd, path.c_str(), mode, flags);
    }
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_utimensat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    bool has_path = (v->r(2) != 0);

    if (has_path) {
        if(!read_c_string(v, v->r(2), path, 4096)) {
            v->r(0) = -EFAULT;
            return true;
        }
    }

    uint64_t times_addr = v->r(3);
    int flags = arg_s32(v->r(4));

    struct timespec pts[2];
    struct timespec* times_ptr = nullptr;

    if (times_addr != 0) {
        int64_t* raw = (int64_t*)v->mmu(times_addr);
        if (raw == nullptr) {
            v->r(0) = -EFAULT;
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
            v->r(0) = -EFAULT;
            return true;
        }
        rc = utimensat(AT_FDCWD, resolve_path(path).c_str(), times_ptr, flags);
    } else {
        auto it = fds.find(dirfd);
        if (it == fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        // utimensat(2) 允许 path=NULL（配合 AT_EMPTY_PATH 作用于 fd 自身），
        // 但 glibc 头声明为 nonnull，编译器误报，这里局部抑制。
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull"
        rc = utimensat(it->second->fd, has_path ? path.c_str() : nullptr, times_ptr, flags);
#pragma GCC diagnostic pop
    }

    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_faccessat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int mode = arg_s32(v->r(3));
    int flags = arg_s32(v->r(4));

    int rc = -1;
    if (dirfd == AT_FDCWD) {
        rc = faccessat(AT_FDCWD, resolve_path(path).c_str(), mode, flags);
    } else {
        auto it = fds.find(dirfd);
        if(it == fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        rc = faccessat(it->second->fd, path.c_str(), mode, flags);
    }

    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_kill(vm* v) {
    int target_pid = arg_s32(v->r(1));
    int sig = arg_s32(v->r(2));
    if(sig < 0 || sig >= NSIG || target_pid <= 0) {
        v->r(0) = -EINVAL;
        return true;
    }
    if(sig == 0) {
        if(static_cast<uint64_t>(target_pid) == pid) {
            v->r(0) = 0;
            return true;
        }
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        v->r(0) = (pid_map.count(static_cast<uint64_t>(target_pid)) > 0) ? 0 : -ESRCH;
        return true;
    }
    if(static_cast<uint64_t>(target_pid) == pid) {
        queue_signal(v, sig);
        v->r(0) = 0;
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
        v->r(0) = -ESRCH;
        return true;
    }
    options(target.get()).sys->queue_signal(target.get(), sig);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_sigaction(vm* v) {
    int signo = arg_s32(v->r(1));
    uint64_t act_addr = v->r(2);
    uint64_t oldact_addr = v->r(3);

    if(signo <= 0 || signo >= NSIG || signo == SIGKILL || signo == SIGSTOP) {
        v->r(0) = -EINVAL;
        return true;
    }

    if(oldact_addr != 0) {
        auto oldact = static_cast<struct bpf::sigaction*>(v->mmu_w(oldact_addr, sizeof(struct bpf::sigaction)));
        if(oldact == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        const auto& current = signal_actions[static_cast<size_t>(signo)];
        oldact->sa_handler = reinterpret_cast<void (*)(int)>(static_cast<uintptr_t>(current.handler));
        oldact->sa_mask = static_cast<bpf::sigset_t>(current.mask);
        oldact->sa_flags = current.flags;
    }

    if(act_addr != 0) {
        auto action = static_cast<const struct bpf::sigaction*>(v->mmu(act_addr));
        if(action == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        if(reinterpret_cast<uintptr_t>(action->sa_handler) == reinterpret_cast<uintptr_t>(SIG_ERR)) {
            v->r(0) = -EINVAL;
            return true;
        }
        auto& current = signal_actions[static_cast<size_t>(signo)];
        current.handler = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(action->sa_handler));
        current.mask = static_cast<uint64_t>(action->sa_mask);
        current.flags = action->sa_flags;
    }

    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_fcntl(vm* v) {
    auto it = fds.find(arg_s32(v->r(1)));
    if(it == fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    int cmd = arg_s32(v->r(2));
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        int min_fd = arg_s32(v->r(3));
        if (min_fd < 0) {
            v->r(0) = -EINVAL;
            return true;
        }

        int new_fd = allocate_fd(min_fd);

        int new_host_fd = dup(it->second->fd);
        if(new_host_fd < 0) {
            v->r(0) = -errno;
            return true;
        }

        auto new_handle = std::make_shared<fd_handle>(new_host_fd, it->second->path);
        if (cmd == F_DUPFD_CLOEXEC) {
            new_handle->cloexec = true;
        }
        fds[new_fd] = new_handle;
        v->r(0) = new_fd;
        return true;
    }
    if (cmd == F_GETFD) {
        v->r(0) = it->second->cloexec ? FD_CLOEXEC : 0;
        return true;
    }
    if (cmd == F_SETFD) {
        it->second->cloexec = (v->r(3) & FD_CLOEXEC) != 0;
        v->r(0) = 0;
        return true;
    }

    uint64_t arg = v->r(3);
    int rc = -1;
    if (cmd == F_GETLK) {
            void* guest_arg = v->mmu_w(arg, sizeof(struct flock));
            if(guest_arg == nullptr) {
                v->r(0) = -EFAULT;
                return true;
            }
            rc = fcntl(it->second->fd, cmd, guest_arg);
    } else if (cmd == F_SETLK || cmd == F_SETLKW) {
            void* guest_arg = v->mmu(arg, sizeof(struct flock));
            if(guest_arg == nullptr) {
                v->r(0) = -EFAULT;
                return true;
            }
            rc = fcntl(it->second->fd, cmd, guest_arg);
    } else {
            rc = fcntl(it->second->fd, cmd, arg);
    }

    if(rc == -1) {
        v->r(0) = -errno;
    } else {
        v->r(0) = rc;
    }
    return true;
}

bool PosixSyscall::do_ioctl(vm* v) {
    auto it = fds.find(arg_s32(v->r(1)));
    if(it == fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    unsigned long request = v->r(2);
    int rc;

    if (request == TCGETS) {
        struct termios host_t = {};
        rc = ioctl(it->second->fd, TCGETS, &host_t);
        if (rc == 0) {
            auto guest_t = (bpf::termios*)v->mmu_w(v->r(3), sizeof(bpf::termios));
            if (guest_t) {
                guest_t->c_lflag = host_t.c_lflag;
            } else {
                v->r(0) = -EFAULT;
                return true;
            }
        }
    } else if (request == TIOCGWINSZ) {
        void* arg = v->mmu_w(v->r(3), sizeof(struct winsize));
        if(arg == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        rc = ioctl(it->second->fd, TIOCGWINSZ, arg);
    } else {
        // Check if the command has a size field > 0, indicating a pointer argument.
        // Linux ioctl encoding: size is bits 16-29 (14 bits).
        size_t ioctl_size = (request >> 16) & 0x3FFF;
        if (ioctl_size) {
            int dir = _IOC_DIR(request);
            void* arg = (dir & _IOC_READ) ? v->mmu_w(v->r(3), ioctl_size) : v->mmu(v->r(3), ioctl_size);
            if(arg == nullptr) {
                v->r(0) = -EFAULT;
                return true;
            }
            rc = ioctl(it->second->fd, request, arg);
        } else {
            rc = ioctl(it->second->fd, request, (void*)v->r(3));
        }
    }

    if(rc == -1) {
        v->r(0) = -errno;
    } else {
        v->r(0) = rc;
    }
    return true;
}

bool PosixSyscall::do_umask(vm* v) {
    uint32_t new_mask = arg_u32(v->r(1));
    v->r(0) = umask_val;
    umask_val = new_mask & 0777;
    return true;
}

bool PosixSyscall::do_setjmp(vm* v) {
    uint64_t env_addr = v->r(1);
    uint64_t* env = (uint64_t*)v->mmu_w(env_addr, 7 * sizeof(uint64_t));
    if (!env) {
        v->r(0) = -EFAULT;
        return true;
    }
    env[0] = v->r(6);
    env[1] = v->r(7);
    env[2] = v->r(8);
    env[3] = v->r(9);
    env[4] = v->r(10);
    env[5] = pc(v);
    env[6] = signal_depth(v);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_longjmp(vm* v) {
    uint64_t env_addr = v->r(1);
    int32_t val = arg_s32(v->r(2));
    uint64_t* env = (uint64_t*)v->mmu(env_addr);
    if (!env) {
        v->r(0) = -EFAULT;
        return true;
    }
    v->r(6) = env[0];
    v->r(7) = env[1];
    v->r(8) = env[2];
    v->r(9) = env[3];
    v->r(10) = env[4];
    uint64_t saved_pc = env[5];
    signal_depth(v) = static_cast<size_t>(env[6]);
    pc(v) = saved_pc;
    // pc points to syscall instruction.
    // loop increments pc.
    // next instruction is executed.

    v->r(0) = (val == 0) ? 1 : val;
    return true;
}


bool PosixSyscall::syscall(vm* v, uint32_t call) {
    uint32_t sys_id = call;
    if(call >= BPF_CALL_BASE) {
        sys_id = BPF_CALL_TO_ID(call);
    }
    switch (sys_id) {
    case BPF_SYS_MMAP:          return do_mmap(v);
    case BPF_SYS_MUNMAP:        return do_munmap(v);
    case BPF_SYS_EXIT:          return do_exit(v);
    case BPF_SYS_NANOSLEEP:     return do_nanosleep(v);
    case BPF_SYS_OPENAT:        return do_openat(v);
    case BPF_SYS_READ:          return do_read(v);
    case BPF_SYS_WRITE:         return do_write(v);
    case BPF_SYS_LSEEK:         return do_lseek(v);
    case BPF_SYS_TRUNCATE:      return do_truncate(v);
    case BPF_SYS_FTRUNCATE:     return do_ftruncate(v);
    case BPF_SYS_CLOSE:         return do_close(v);
    case BPF_SYS_UNLINKAT:      return do_unlinkat(v);
    case BPF_SYS_MKDIR:         return do_mkdir(v);
    case BPF_SYS_RMDIR:         return do_rmdir(v);
    case BPF_SYS_SYMLINKAT:     return do_symlinkat(v);
    case BPF_SYS_LINKAT:        return do_linkat(v);
    case BPF_SYS_RENAMEAT:      return do_renameat(v);
    case BPF_SYS_READLINK:      return do_readlink(v);
    case BPF_SYS_EXECVE:        return do_execve(v);
    case BPF_SYS_FORK:          return do_fork(v);
    case BPF_SYS_GETPID:        return do_getpid(v);
    case BPF_SYS_GETPPID:       return do_getppid(v);
    case BPF_SYS_WAITPID:       return do_waitpid(v);
    case BPF_SYS_DUP:           return do_dup(v);
    case BPF_SYS_DUP2:          return do_dup2(v);
    case BPF_SYS_PIPE2:         return do_pipe2(v);
    case BPF_SYS_FCHDIR:        return do_fchdir(v);
    case BPF_SYS_GETCWD:        return do_getcwd(v);
    case BPF_SYS_FDOPENDIR:     return do_fdopendir(v);
    case BPF_SYS_READDIR:       return do_readdir(v);
    case BPF_SYS_CLOSEDIR:      return do_closedir(v);
    case BPF_SYS_FSTATAT:       return do_fstatat(v);
    case BPF_SYS_FCHMODAT:      return do_fchmodat(v);
    case BPF_SYS_UTIMENSAT:     return do_utimensat(v);
    case BPF_SYS_FACCESSAT:     return do_faccessat(v);
    case BPF_SYS_KILL:          return do_kill(v);
    case BPF_SYS_SIGACTION:     return do_sigaction(v);
    case BPF_SYS_FCNTL:         return do_fcntl(v);
    case BPF_SYS_IOCTL:         return do_ioctl(v);
    case BPF_SYS_UMASK:         return do_umask(v);
    case BPF_SYS_SETJMP:        return do_setjmp(v);
    case BPF_SYS_LONGJMP:       return do_longjmp(v);
    case BPF_SYS_CLOCK_GETTIME: return do_clock_gettime(v);
    default:
        fprintf(stderr, "unsupported func: 0x%x\n", call);
        v->r(0) = -ENOSYS;
        return true;
    }
}
