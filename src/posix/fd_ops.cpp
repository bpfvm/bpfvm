#include "posix_internal.h"

int PosixSyscall::allocate_fd(int min_fd) {
    int fd = min_fd;
    while(ps->fds.count(fd)) {
        fd++;
    }
    return fd;
}

bool PosixSyscall::do_umask(vm* v) {
    uint32_t new_mask = arg_u32(v->r(1));
    v->r(0) = umask_val;
    umask_val = new_mask & 0777;
    return true;
}

bool PosixSyscall::do_dup(vm* v) {
    int old_fd = arg_s32(v->r(1));
    if(old_fd < 0) {
        v->r(0) = -EBADF;
        return true;
    }

    auto it = ps->fds.find(old_fd);
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }

    int new_host_fd = dup(it->second->fd);
    if(new_host_fd < 0) {
        v->r(0) = -errno;
        return true;
    }

    int new_fd = allocate_fd();
    ps->fds[new_fd] = std::make_shared<fd_handle>(new_host_fd, it->second->path);
    v->r(0) = new_fd;
    return true;
}

bool PosixSyscall::do_dup3(vm* v) {
    int old_fd = arg_s32(v->r(1));
    int new_fd = arg_s32(v->r(2));
    int flags = arg_s32(v->r(3));
    if(old_fd < 0 || new_fd < 0) {
        v->r(0) = -EBADF;
        return true;
    }
    if(old_fd == new_fd) {
        v->r(0) = -EINVAL;
        return true;
    }
    if(flags & ~O_CLOEXEC) {
        v->r(0) = -EINVAL;
        return true;
    }

    auto it = ps->fds.find(old_fd);
    if(it == ps->fds.end()) {
        v->r(0) = -EBADF;
        return true;
    }

    int new_host_fd = dup(it->second->fd);
    if(new_host_fd < 0) {
        v->r(0) = -errno;
        return true;
    }

    auto handle = std::make_shared<fd_handle>(new_host_fd, it->second->path);
    if(flags & O_CLOEXEC) {
        handle->cloexec = true;
    }
    ps->fds[new_fd] = handle;
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
    ps->fds[guest_fd0] = handle0;

    int guest_fd1 = allocate_fd(guest_fd0 + 1);
    auto handle1 = std::make_shared<fd_handle>(host_fds[1]);
    if (flags & O_CLOEXEC) {
        handle1->cloexec = true;
    }
    ps->fds[guest_fd1] = handle1;

    pipefd[0] = guest_fd0;
    pipefd[1] = guest_fd1;
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_fcntl(vm* v) {
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
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
        ps->fds[new_fd] = new_handle;
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
    auto it = ps->fds.find(arg_s32(v->r(1)));
    if(it == ps->fds.end()) {
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
