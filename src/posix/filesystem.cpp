#include "posix_internal.h"

// 从 guest 地址空间读出一个 NUL 结尾字符串（最多 max_len 字节）。
// 与下面的 resolve_path 同属「guest 内存 <-> 字符串」工具，故放在本文件。
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

std::string PosixSyscall::guest_abs_path(const std::string& path, int dirfd) {
    if(path.empty()) {
        return path;
    }
    // 求 guest 视角的绝对路径，lexically_normal 消除
    // '..'，使 '/../../etc/passwd' 规范化为 '/etc/passwd'
    std::filesystem::path input(path);
    std::string guest_abs;
    if(input.is_absolute()) {
        // 绝对路径忽略 dirfd（Linux openat 语义：绝对路径不看 dirfd）。
        guest_abs = input.lexically_normal().string();
    } else {
        // 相对路径：dirfd != AT_FDCWD 时取 fd 对应的 guest 视角目录作 base
        // fd 无 path 时退化为相对 cwd。
        std::string base = ps->cwd.empty() ? std::string("/") : ps->cwd;
        if(dirfd != AT_FDCWD) {
            if(auto h = ps->find_fd(dirfd); h && !h->path.empty()) {
                base = h->path;
            }
        }
        guest_abs = (std::filesystem::path(base) / input).lexically_normal().string();
    }
    // lexically_normal 对根目录 "/" 会返回空，补回。
    if(guest_abs.empty()) {
        guest_abs = "/";
    }
    return guest_abs;
}

int64_t PosixSyscall::do_unlinkat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    if(dirfd != AT_FDCWD && !ps->find_fd(dirfd)) {
        return -EBADF;
    }
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        return -EFAULT;
    }
    int flags = arg_s32(v->r(3));
    return ResolvePath(this, guest_abs_path(path, dirfd))->unlink(flags);
}

int64_t PosixSyscall::do_mkdirat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    if(dirfd != AT_FDCWD && !ps->find_fd(dirfd)) {
        return -EBADF;
    }
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        return -EFAULT;
    }
    mode_t mode = (mode_t)(arg_u32(v->r(3)) & ~ps->umask);
    return ResolvePath(this, guest_abs_path(path, dirfd))->mkdir(mode);
}

int64_t PosixSyscall::do_symlinkat(vm* v) {
    int dirfd = arg_s32(v->r(2));
    if(dirfd != AT_FDCWD && !ps->find_fd(dirfd)) {
        return -EBADF;
    }
    std::string target;
    std::string linkpath;
    if(!read_c_string(v, v->r(1), target, 4096) || !read_c_string(v, v->r(3), linkpath, 4096)) {
        return -EFAULT;
    }
    return ResolvePath(this, guest_abs_path(linkpath, dirfd))->symlink(target);
}

int64_t PosixSyscall::do_linkat(vm* v) {
    int olddirfd = arg_s32(v->r(1));
    int newdirfd = arg_s32(v->r(3));
    int flags = arg_s32(v->r(5));
    if(olddirfd != AT_FDCWD && !ps->find_fd(olddirfd)) {
        return -EBADF;
    }
    if(newdirfd != AT_FDCWD && !ps->find_fd(newdirfd)) {
        return -EBADF;
    }
    std::string oldpath;
    std::string newpath;
    if(!read_c_string(v, v->r(2), oldpath, 4096) || !read_c_string(v, v->r(4), newpath, 4096)) {
        return -EFAULT;
    }
    auto oldp = ResolvePath(this, guest_abs_path(oldpath, olddirfd));
    auto newp = ResolvePath(this, guest_abs_path(newpath, newdirfd));
    return oldp->link(*newp, flags);
}

int64_t PosixSyscall::do_renameat2(vm* v) {
    int old_dirfd = arg_s32(v->r(1));
    int new_dirfd = arg_s32(v->r(3));
    unsigned int flags = arg_u32(v->r(5));
    if(old_dirfd != AT_FDCWD && !ps->find_fd(old_dirfd)) {
        return -EBADF;
    }
    if(new_dirfd != AT_FDCWD && !ps->find_fd(new_dirfd)) {
        return -EBADF;
    }
    std::string old_path;
    std::string new_path;
    if(!read_c_string(v, v->r(2), old_path, 4096) || !read_c_string(v, v->r(4), new_path, 4096)) {
        return -EFAULT;
    }
    auto oldp = ResolvePath(this, guest_abs_path(old_path, old_dirfd));
    auto newp = ResolvePath(this, guest_abs_path(new_path, new_dirfd));
    return oldp->rename(*newp, flags);
}

int64_t PosixSyscall::do_readlinkat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    if(dirfd != AT_FDCWD && !ps->find_fd(dirfd)) {
        return -EBADF;
    }
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        return -EFAULT;
    }
    size_t bufsiz = arg_size(v->r(4));
    char* buf = (char*)v->mmu_w(v->r(3), bufsiz);
    if(buf == nullptr) {
        return -EFAULT;
    }
    // readlink 由 Path 统一分发：/proc 符号链接（magic + LinkGen）bpfvm 自决目标，
    // 其余走 host readlink（直写 buf）。dirfd 与 path 在 guest_abs_path 内合成 guest 绝对路径。
    return ResolvePath(this, guest_abs_path(path, dirfd))->readlink(buf, bufsiz);
}

int64_t PosixSyscall::do_fchdir(vm* v) {
    int fd = arg_s32(v->r(1));
    auto h = ps->find_fd(fd);
    if(!h) {
        return -EBADF;
    }
    struct statx stx = {};
    int rc = h->fstatx(&stx, STATX_TYPE, 0);
    if(rc < 0) {
        return rc;
    }
    if(!S_ISDIR(stx.stx_mode)) {
        return -ENOTDIR;
    }
    if(h->path.empty()) {
        return -ENOENT;
    }
    ps->cwd = h->path;
    return 0;
}

int64_t PosixSyscall::do_getcwd(vm* v) {
    uint64_t buf_addr = v->r(1);
    size_t size = arg_size(v->r(2));
    if(size == 0) {
        return -ERANGE;
    }
    char* buf = static_cast<char*>(v->mmu_w(buf_addr, size));
    if(buf == nullptr) {
        return -EFAULT;
    }
    std::string path = ps->cwd.empty() ? "/" : ps->cwd;
    if(size <= path.size()) {
        return -ERANGE;
    }
    memcpy(buf, path.c_str(), path.size() + 1);
    return (int64_t)(path.size() + 1);
}

int64_t PosixSyscall::do_statx(vm* v) {
    int dirfd = arg_s32(v->r(1));
    if(dirfd != AT_FDCWD && !ps->find_fd(dirfd)) {
        return -EBADF;
    }
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        return -EFAULT;
    }
    int flags = arg_s32(v->r(3));
    unsigned int mask = arg_u32(v->r(4));
    // 路径以 '/' 结尾时即使 AT_SYMLINK_NOFOLLOW 也必须follow符号链接
    if(!path.empty() && path.back() == '/') {
        flags &= ~AT_SYMLINK_NOFOLLOW;
    }
    /* host struct statx 与 guest 的均源自 Linux UAPI stat.h，布局二进制兼容（同 256 字节、
     * 同偏移），故直接用 host 类型：statx() 直写后 memcpy 进 guest 缓冲即可，无需逐字段转换，
     * 也不必依赖 guest 头 include/sys/stat.h。 */
    auto out = static_cast<struct statx*>(v->mmu_w(v->r(5), sizeof(struct statx)));
    if(out == nullptr) {
        return -EFAULT;
    }
    // AT_EMPTY_PATH（或 path 为空）+ 有效 dirfd：纯 fd 操作（fstat 语义）。
    // 经 Fd::fstatx 多态分发：HostFd 透传 host statx（socket fd 也正确返回 S_IFSOCK），
    if(dirfd != AT_FDCWD && (flags & AT_EMPTY_PATH)) {
        auto h = ps->find_fd(dirfd);
        if(!h) return -EBADF;
        return h->fstatx(out, mask, flags);
    }
    return ResolvePath(this, guest_abs_path(path, dirfd))->statx(out, mask, flags);
}

int64_t PosixSyscall::do_fchmodat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    if(dirfd != AT_FDCWD && !ps->find_fd(dirfd)) {
        return -EBADF;
    }
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        return -EFAULT;
    }
    mode_t mode = (mode_t)arg_u32(v->r(3));
    int flags = arg_s32(v->r(4));
    return ResolvePath(this, guest_abs_path(path, dirfd))->chmod(mode, flags);
}

int64_t PosixSyscall::do_utimensat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    if(dirfd != AT_FDCWD && !ps->find_fd(dirfd)) {
        return -EBADF;
    }

    std::string path;
    bool has_path = (v->r(2) != 0);
    if (has_path && !read_c_string(v, v->r(2), path, 4096)) {
        return -EFAULT;
    }

    uint64_t times_addr = v->r(3);
    int flags = arg_s32(v->r(4));

    struct timespec pts[2];
    struct timespec* times_ptr = nullptr;

    if (times_addr != 0) {
        int64_t* raw = (int64_t*)v->mmu(times_addr);
        if (raw == nullptr) {
            return -EFAULT;
        }
        pts[0].tv_sec = raw[0];
        pts[0].tv_nsec = raw[1];
        pts[1].tv_sec = raw[2];
        pts[1].tv_nsec = raw[3];
        times_ptr = pts;
    }

    // path=NULL -> 纯 fd 形式（内核：utimensat(fd,NULL,...) == futimens(fd)）
    // dirfd 顶部已校验有效；AT_FDCWD 时无 fd 可作用 -> EFAULT（utimensat 语义）。
    if(!has_path) {
        if(dirfd == AT_FDCWD) return -EFAULT;
        auto h = ps->find_fd(dirfd);
        if(!h) return -EBADF;
        return h->futimens(times_ptr, flags);
    }
    return ResolvePath(this, guest_abs_path(path, dirfd))->utimens(times_ptr, flags);
}

int64_t PosixSyscall::do_faccessat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        return -EFAULT;
    }
    int mode = arg_s32(v->r(3));
    int flags = arg_s32(v->r(4));
    if(dirfd != AT_FDCWD && !ps->find_fd(dirfd)) {
        return -EBADF;
    }
    return ResolvePath(this, guest_abs_path(path, dirfd))->access(mode, flags);
}
