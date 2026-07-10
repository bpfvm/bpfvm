#include "posix_internal.h"

// 从 guest 地址空间读出一个 NUL 结尾字符串（最多 max_len 字节）。
// 与下面的 resolve_path 同属「guest 内存 ↔ 字符串」工具，故放在本文件。
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

// 读出一个 guest 字符串数组（argv/envp 风格：连续 uint64 指针，以 NULL 结尾）。
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

std::string PosixSyscall::guest_abs_path(const std::string& path) {
    if(path.empty()) {
        return path;
    }
    // 求 guest 视角的绝对路径（ps->cwd 已是 guest 视角），lexically_normal 消除
    // '..'，使 '/../../etc/passwd' 规范化为 '/etc/passwd' —— 仍被限制在 root 下，无法逃逸。
    std::filesystem::path input(path);
    std::string guest_abs;
    if(input.is_absolute()) {
        guest_abs = input.lexically_normal().string();
    } else {
        std::filesystem::path base = ps->cwd.empty() ? std::filesystem::path("/") : std::filesystem::path(ps->cwd);
        guest_abs = (base / input).lexically_normal().string();
    }
    // lexically_normal 对根目录 "/" 会返回空，补回。
    if(guest_abs.empty()) {
        guest_abs = "/";
    }
    return guest_abs;
}

std::string PosixSyscall::resolve_path(const std::string& path) {
    std::string guest_abs = guest_abs_path(path);
    if(guest_abs.empty()) {
        return guest_abs;
    }
    // 非 chroot 模式：直接返回 guest 绝对路径（= 原行为）。
    // chroot 模式：拼上宿主 root 前缀得到实际宿主路径。
    if(ps->root.empty()) {
        return guest_abs;
    }
    // root 已去尾斜杠；guest_abs 以 '/' 开头，两者拼接即宿主路径。
    return ps->root + guest_abs;
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
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
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

bool PosixSyscall::do_mkdirat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    mode_t mode = (mode_t)(arg_u32(v->r(3)) & ~umask_val);
    int rc;
    if(dirfd == AT_FDCWD) {
        rc = mkdir(resolve_path(path).c_str(), mode);
    } else {
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        rc = mkdirat(it->second->fd, path.c_str(), mode);
    }
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
        auto it = ps->fds.find(new_dirfd);
        if(it == ps->fds.end()) {
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
        auto it = ps->fds.find(olddirfd);
        if (it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        host_olddirfd = it->second->fd;
    }

    int host_newdirfd = AT_FDCWD;
    if (newdirfd != AT_FDCWD) {
        auto it = ps->fds.find(newdirfd);
        if (it == ps->fds.end()) {
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

bool PosixSyscall::do_renameat2(vm* v) {
    std::string old_path;
    std::string new_path;
    if(!read_c_string(v, v->r(2), old_path, 4096) || !read_c_string(v, v->r(4), new_path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int old_dirfd = arg_s32(v->r(1));
    int new_dirfd = arg_s32(v->r(3));
    unsigned int flags = arg_u32(v->r(5));

    int host_old_dirfd = AT_FDCWD;
    if (old_dirfd != AT_FDCWD) {
        auto it = ps->fds.find(old_dirfd);
        if (it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        host_old_dirfd = it->second->fd;
    }

    int host_new_dirfd = AT_FDCWD;
    if (new_dirfd != AT_FDCWD) {
        auto it = ps->fds.find(new_dirfd);
        if (it == ps->fds.end()) {
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
#if defined(__ANDROID__)
    // Android bionic 不暴露 renameat2() libc 包装函数，直接走 syscall。
    int rc = (int)::syscall(SYS_renameat2, host_old_dirfd, resolved_old.c_str(),
                            host_new_dirfd, resolved_new.c_str(), flags);
#else
    int rc = renameat2(host_old_dirfd, resolved_old.c_str(),
                       host_new_dirfd, resolved_new.c_str(), flags);
#endif
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_readlinkat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    size_t bufsiz = arg_size(v->r(4));
    char* buf = (char*)v->mmu_w(v->r(3), bufsiz);
    if(buf == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    ssize_t rc;
    if(dirfd == AT_FDCWD) {
        rc = readlink(resolve_path(path).c_str(), buf, bufsiz);
    } else {
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
        rc = readlinkat(it->second->fd, path.c_str(), buf, bufsiz);
    }
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    v->r(0) = rc;
    return true;
}

bool PosixSyscall::do_fchdir(vm* v) {
    int fd = arg_s32(v->r(1));
    auto it = ps->fds.find(fd);
    if(it == ps->fds.end()) {
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
    ps->cwd = it->second->path;
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
    std::string path = ps->cwd.empty() ? "/" : ps->cwd;
    if(size <= path.size()) {
        v->r(0) = -ERANGE;
        return true;
    }
    memcpy(buf, path.c_str(), path.size() + 1);
    v->r(0) = path.size() + 1;
    return true;
}

bool PosixSyscall::do_statx(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        v->r(0) = -EFAULT;
        return true;
    }
    int flags = arg_s32(v->r(3));
    unsigned int mask = arg_u32(v->r(4));
    /* host struct statx 与 guest 的均源自 Linux UAPI stat.h，布局二进制兼容（同 256 字节、
     * 同偏移），故直接用 host 类型：statx() 直写后 memcpy 进 guest 缓冲即可，无需逐字段转换，
     * 也不必依赖 guest 头 include/sys/stat.h。 */
    auto out = static_cast<struct statx*>(v->mmu_w(v->r(5), sizeof(struct statx)));
    if(out == nullptr) {
        v->r(0) = -EFAULT;
        return true;
    }
    struct statx stx = {};
    int rc = -1;
    if(dirfd == AT_FDCWD) {
#if defined(__ANDROID__)
        rc = (int)::syscall(SYS_statx, AT_FDCWD, resolve_path(path).c_str(),
                            flags, mask, &stx);
#else
        rc = statx(AT_FDCWD, resolve_path(path).c_str(), flags, mask, &stx);
#endif
    } else {
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
            v->r(0) = -EBADF;
            return true;
        }
#if defined(__ANDROID__)
        rc = (int)::syscall(SYS_statx, it->second->fd, path.c_str(), flags, mask, &stx);
#else
        rc = statx(it->second->fd, path.c_str(), flags, mask, &stx);
#endif
    }
    if(rc == -1) {
        v->r(0) = -errno;
        return true;
    }
    std::memcpy(out, &stx, sizeof(stx));
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
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
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
        auto it = ps->fds.find(dirfd);
        if (it == ps->fds.end()) {
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
        auto it = ps->fds.find(dirfd);
        if(it == ps->fds.end()) {
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
