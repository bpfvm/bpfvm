#include "posix_internal.h"

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
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
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
    ps->fds[guest_fd] = handle;
    v->r(0) = guest_fd;
    return true;
}

bool PosixSyscall::do_read(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
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
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
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
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
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
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
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
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    ps->fds.erase(it);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_readv(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    int iovcnt = arg_s32(v->r(3));
    if(iovcnt <= 0) {
        v->r(0) = (iovcnt == 0) ? 0 : -EINVAL;
        return true;
    }
    auto guest_vec = static_cast<bpf::iovec*>(v->mmu(v->r(2), sizeof(bpf::iovec) * iovcnt));
    if(guest_vec == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    // 把 guest 的 iov 翻译成宿主 iovec：iov_base 走 mmu_w 转成 host 指针。
    // 这样宿主 readv 一次性按 iov 顺序填充，跨 iov 的短读/EOF 语义与内核一致。
    std::vector<iovec> host_vec;
    host_vec.reserve(iovcnt);
    for(int i = 0; i < iovcnt; ++i) {
        size_t len = (size_t)guest_vec[i].iov_len;
        if(len == 0) continue;
        void* buf = v->mmu_w((uint64_t)guest_vec[i].iov_base, len);
        if(buf == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        host_vec.push_back({buf, len});
    }
    if(host_vec.empty()) {
        v->r(0) = 0;
        return true;
    }
    ssize_t rc = readv(it->second->fd, host_vec.data(), (int)host_vec.size());
    if(rc < 0) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = (uint64_t)rc;
    return true;
}

bool PosixSyscall::do_writev(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    int iovcnt = arg_s32(v->r(3));
    if(iovcnt <= 0) {
        v->r(0) = (iovcnt == 0) ? 0 : -EINVAL;
        return true;
    }
    auto guest_vec = static_cast<bpf::iovec*>(v->mmu(v->r(2), sizeof(bpf::iovec) * iovcnt));
    if(guest_vec == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    // 把 guest 的 iov 翻译成宿主 iovec：iov_base 走 mmu 转成 host 指针（只读即可）。
    // 这样宿主 writev 一次性按 iov 顺序输出，短写语义与内核一致。
    std::vector<iovec> host_vec;
    host_vec.reserve(iovcnt);
    for(int i = 0; i < iovcnt; ++i) {
        size_t len = (size_t)guest_vec[i].iov_len;
        if(len == 0) continue;
        void* buf = v->mmu((uint64_t)guest_vec[i].iov_base, len);
        if(buf == nullptr) {
            v->r(0) = -EFAULT;
            return true;
        }
        host_vec.push_back({buf, len});
    }
    if(host_vec.empty()) {
        v->r(0) = 0;
        return true;
    }
    ssize_t rc = writev(it->second->fd, host_vec.data(), (int)host_vec.size());
    if(rc < 0) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = (uint64_t)rc;
    return true;
}

bool PosixSyscall::do_pread(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu_w(v->r(2), count);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    off_t off = (off_t)v->r(4);
    ssize_t rc = pread(it->second->fd, buf, count, off);
    if(rc < 0) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = (uint64_t)rc;
    return true;
}

bool PosixSyscall::do_pwrite(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    size_t count = arg_size(v->r(3));
    void* buf = v->mmu(v->r(2), count);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    off_t off = (off_t)v->r(4);
    ssize_t rc = pwrite(it->second->fd, buf, count, off);
    if(rc < 0) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = (uint64_t)rc;
    return true;
}

bool PosixSyscall::do_getdents64(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }
    size_t count = arg_size(v->r(3));
    if(count == 0) {
        v->r(0) = -EINVAL;
        return true;
    }
    void* buf = v->mmu_w(v->r(2), count);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    int rc = (int)::syscall(SYS_getdents64, it->second->fd, buf, (int)count);
    if(rc < 0) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = (uint64_t)rc;
    return true;
}
