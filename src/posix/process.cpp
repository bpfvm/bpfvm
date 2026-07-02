#include "posix_internal.h"

bool PosixSyscall::do_exit(vm* v) {
    int code = arg_s32(v->r(1));
    v->r(0) = (uint64_t)(unsigned int)code;
    // CAS(-1 -> code)：首个正常退出者赢，后续不覆盖。致命信号默认动作走 do_exit_group，不经过此函数。
    int expected = -1;
    tg->exit_code.compare_exchange_strong(expected, code, std::memory_order_acq_rel);
    return false;  // fini 减 live_threads + clear-child-tid
}

bool PosixSyscall::do_exit_group(vm* v) {
    int code = arg_s32(v->r(1));
    v->r(0) = (uint64_t)(unsigned int)code;
    // CAS(-1 -> code)：首个正常退出者赢，被置 VM_KILLED 的线程不走 do_exit，不会覆盖。
    int expected = -1;
    tg->exit_code.compare_exchange_strong(expected, code, std::memory_order_acq_rel);
    {
        // 杀掉线程组内所有其他线程。走目标线程自己的 queue_signal(SIGKILL)：
        std::lock_guard<std::mutex> lock(tg->mtx);
        for(auto& weak_vm : tg->threads) {
            auto tvm = weak_vm.lock();
            if(tvm && tvm.get() != v) {
                options(tvm.get()).sys->queue_signal(tvm.get(), SIGKILL);
            }
        }
    }
    return false;  // 调用线程退出 → fini
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
    ElfLoadInfo load_info = fresh->load_elf(resolve_path(path).c_str());
    if(load_info.entry == 0) {
        v->r(0) = -ENOEXEC;
        return true;
    }
    const uint64_t entry = load_info.entry;
    // setup_stack 直接接收 load_info，用它合成 auxv（musl __init_tls 靠
    // AT_PHDR/AT_PHENT/AT_PHNUM/AT_ENTRY 定位 PT_TLS）。
    if(!fresh->setup_stack(argv_strings, envp_strings, load_info)) {
        v->r(0) = -E2BIG;
        return true;
    }
    if(!fresh->mmu(entry)) {
        v->r(0) = -ENOEXEC;
        return true;
    }
    // execve 替换整个 guest 地址空间为新程序：同步 v->options 里「跑什么程序」的字段
    //（entry/argv/envp），让后续 dump_stats/调试读到的是新程序而非旧残留。
    // 宿主侧配置（verbose/breakpoint/insn_limit/sys 等）跨 execve 保留不变。
    options(v).entry = entry;
    options(v).argv = std::move(argv_strings);
    options(v).envp = std::move(envp_strings);
    {
        std::lock_guard<std::mutex> lock(*maps_mutex(v));
        maps(v).swap(maps(fresh.get()));
    }
    v->flush_tlb();
    // execve 替换了整个 guest 地址空间：旧程序编译的 JIT 函数全部失效。
    // 且新旧程序共享相同的 guest 地址区间（都从 0x400000 链接），必须清空缓存，
    // 否则会误命中旧程序的编译产物。
    v->clear_jit_cache();

    decltype(ps->signal_actions) new_actions{};
    const uint64_t sig_dfl = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_DFL));
    const uint64_t sig_ign = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_IGN));
    for(size_t i = 0; i < new_actions.size(); i++) {
        if(ps->signal_actions[i].handler == sig_ign) {
            new_actions[i].handler = sig_ign;
        } else {
            new_actions[i].handler = sig_dfl;
        }
    }
    ps->signal_actions = new_actions;
    signal_depth(v) = 0;

    std::unordered_map<int, std::shared_ptr<fd_handle>> new_fds;
    for (const auto& entry : ps->fds) {
        if (!entry.second->cloexec) {
            new_fds.insert(entry);
        }
    }
    ps->fds.swap(new_fds);
    v->r(1) = fresh->r(1);
    v->r(10) = STACK_BASE + STACK_SIZE - 8;
    pc(v) = entry;
    v->push_frame(0);
    pc(v) -= sizeof(bpf_insn);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_clone(vm* v) {
    uint64_t flags  = v->r(1);
    uint64_t stack  = v->r(2);
    uint64_t ptid   = v->r(3);
    uint64_t ctid   = v->r(4);
    uint64_t newtls = v->r(5);

    bool is_thread = (flags & CLONE_THREAD) != 0;
    bool share_vm = (flags & CLONE_VM) != 0;

    auto child = vm::create();
    options(child.get()) = options(v);
    /* CLONE_THREAD 是新线程，不在任何信号处理上下文 → signal_depth=0。
     * 非 CLONE_THREAD（如 fork / 裸 clone 新进程）继承父 signal_depth，
     * 与 fork 语义一致（fork 复制整个执行状态）。 */
    signal_depth(child.get()) = is_thread ? 0 : signal_depth(v);

    /* 共享或拷贝进程级状态（fds/signal_actions/cwd）。
     * CLONE_THREAD: 整体共享 ps（musl 总是同时传 CLONE_FILES|SIGHAND|FS|THREAD）。
     * 非 CLONE_THREAD: 拷贝 ps（同 fork 语义）——dup 父 fd 成独立 host fd，
     *   否则子进程会丢掉所有打开的文件描述符。 */
    std::unordered_map<int, std::shared_ptr<fd_handle>> child_fds;
    if(!is_thread) {
        for(const auto& entry : ps->fds) {
            int new_host_fd = dup(entry.second->fd);
            if(new_host_fd < 0) {
                v->r(0) = -errno;
                return true;
            }
            auto new_handle = std::make_shared<fd_handle>(new_host_fd, entry.second->path);
            new_handle->cloexec = entry.second->cloexec;
            child_fds[entry.first] = new_handle;
        }
    }
    auto child_sys = std::make_shared<PosixSyscall>(
        is_thread ? ppid.load() : tg->tgid,
        is_thread ? ps->fds : child_fds,
        ps->cwd, pgrp, session);
    if(!is_thread) {
        child_sys->ps->signal_actions = ps->signal_actions;
    } else {
        child_sys->ps = ps;
        child_sys->tg = tg;
        tg->live_threads.fetch_add(1);
    }
    child_sys->umask_val = umask_val;
    options(child.get()).sys = child_sys;

    /* 地址空间：CLONE_VM 共享 maps（同一 shared_ptr，后续 mmap 互通可见）；
     * 否则 CoW 拷贝（同 fork）。 */
    if(share_vm) {
        maps_ptr(child.get()) = maps_ptr(v);
        maps_mutex(child.get()) = maps_mutex(v);
    } else {
        std::lock_guard<std::mutex> lock(*maps_mutex(v));
        for(auto& map : maps(v)) {
            memmap child_map;
            child_map.size  = map.size;
            child_map.paddr = map.paddr;
            child_map.flags = map.flags;

            if(map.flags & PF_W) {
                if(!map.cow_data && map.data.get_deleter().owned) {
                    map.cow_data = std::shared_ptr<unsigned char>(
                        map.data.get(), DataDeleter{map.data.get_deleter().size, true});
                    map.data.get_deleter().owned = false;
                }
                child_map.set_data(map.data.get(), map.size, false);
                child_map.cow_data = map.cow_data;
            } else {
                child_map.set_data(map.data.get(), map.size, false);
            }
            child->addmem(std::move(child_map));
        }
    }
    if(share_vm) {
        v->flush_tlb();
    } else {
        /* fork（非 CLONE_VM）就地修改父地址空间：每段 writable map 建立 cow_data、
         * data.owned 置 false。父线程组里其它线程（如 pthread_create 出来的 worker）的
         * TLB 此时是陈旧的——条目仍是 cow=false、host_base 指向原页，会绕过 CoW 直接写
         * 共享页，破坏 CoW 不变式。必须把同组所有线程的 TLB 一并刷新（仅 v->flush_tlb()
         * 只清了调用线程）。CLONE_THREAD 不改 maps，无需此步。 */
        std::lock_guard<std::mutex> tlock(tg->mtx);
        for(auto& weak : tg->threads) {
            if(auto t = weak.lock()) t->flush_tlb();
        }
    }

    /* child 继承父所有寄存器（含 r9=func，供 musl __clone.s child 路径 callx r9）。
     * r(0)=0（clone 返回值），r(10)=新栈顶（arg 已由 .s 压在 *(u64*)(r10+0)），
     * pc=syscall 返回点（call 后下一条指令）。 */
    for(size_t i = 0; i < 11; i++) {
        child->r(i) = v->r(i);
    }
    child->r(0) = 0;
    /* 栈来源：clone 调用者通过 r(2) 提供新栈顶；stack==NULL（如 fork 经 do_clone
     * 传入）时继承父 r(10)——fork 的子进程是父地址空间的 CoW 副本，栈也在其中，
     * 直接用父栈指针即可（上面 r(i)=v->r(i) 已拷贝了 r(10)，这里 stack!=0 才覆盖）。 */
    if(stack != 0) {
        child->r(10) = stack;
    }
    pc(child.get()) = pc(v) + sizeof(bpf_insn);

    /* CLONE_SETTLS：新线程用调用者提供的 tls。
     * 否则（非 CLONE_THREAD，如 fork / 裸 clone 新进程）继承父 tp：子进程是父
     * 地址空间的副本（CoW），struct pthread 仍在同样的虚拟地址，TP 指向它依然
     * 有效。若不继承，子进程 tp_=0 → __pthread_self() 返回 NULL → musl 后续写
     * self->tid（偏移 0x30）会 invalid write at 0x30 崩溃。 */
    if(flags & CLONE_SETTLS) {
        tp(child.get()) = newtls;
    } else if(!is_thread) {
        tp(child.get()) = tp(v);
    }

    /* CLONE_PARENT_SETTID / CLONE_CHILD_SETTID：写 child tid（pid_t = int, 4 字节）。
     * musl 传 ptid=&new->tid、ctid=&__thread_list_lock（后者配合 CLEARTID 用）。
     * CLONE_VM 下父子地址空间共享，用父 mmu_w。 */
    if(flags & CLONE_PARENT_SETTID) {
        auto* p = static_cast<int*>(v->mmu_w(ptid, sizeof(int)));
        if(p) *p = (int)child_sys->pid;
    }
    if(flags & CLONE_CHILD_SETTID) {
        auto* p = static_cast<int*>(v->mmu_w(ctid, sizeof(int)));
        if(p) *p = (int)child_sys->pid;
    }
    if(flags & CLONE_CHILD_CLEARTID) {
        child_sys->tid_address_ = ctid;
    }

    /* 启动 host 线程 */
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
        if(is_thread) tg->live_threads.fetch_sub(1);
        v->r(0) = -rc;
        return true;
    }
    {
        std::lock_guard<std::mutex> lock(child_sys->tg->mtx);
        child_sys->tg->threads.push_back(child);
    }
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        pid_map[child_sys->pid] = child;
    }
    v->r(0) = child_sys->pid;
    return true;
}

bool PosixSyscall::do_getpid(vm* v) {
    v->r(0) = tg->tgid;
    return true;
}

bool PosixSyscall::do_getppid(vm* v) {
    v->r(0) = ppid.load();
    return true;
}

// 在 pid_map 中按 pid 查找 task，返回 vm shared_ptr（持锁内取出，调用方持有期间 vm 不会析构）。
std::shared_ptr<vm> PosixSyscall::find_task(uint64_t target_pid) {
    std::lock_guard<std::mutex> lock(pid_map_mutex);
    auto it = pid_map.find(target_pid);
    if(it == pid_map.end()) {
        return nullptr;
    }
    return it->second;
}

bool PosixSyscall::do_waitpid(vm* v) {
    int64_t target_pid = static_cast<int64_t>(arg_s32(v->r(1)));
    uint64_t status_addr = v->r(2);
    int32_t options = arg_s32(v->r(3));

    if((options & ~WNOHANG) != 0) {
        v->r(0) = -EINVAL;
        return true;
    }

    // waitpid(self) 无意义
    if(target_pid == (int64_t)pid) {
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

    // 收集候选子进程。Linux 语义：
    //   pid > 0  → 指定 task（必须是自身子进程的线程组 leader）
    //   pid == 0 → 调用者进程组里任意子进程
    //   pid == -1→ 任意子进程
    //   pid < -1 → 进程组 -pid 里任意子进程
    // 只有 leader（pid == tg->tgid）可被 waitpid；非 leader 线程退出不产生可 wait 状态。
    auto match_child = [&](const std::shared_ptr<vm>& task_vm) -> bool {
        auto s = sys(task_vm.get());
        if(!s || s->ppid.load() != tg->tgid) return false;
        if(s->pid != s->tg->tgid) return false;  // 仅 leader 可 wait
        if(target_pid == -1) return true;
        if(target_pid == 0) return s->pgrp->pgid == pgrp->pgid;
        if(target_pid < -1) return s->pgrp->pgid == static_cast<uint64_t>(-target_pid);
        return false;
    };

    auto child_exited = [](const std::shared_ptr<vm>& task_vm) -> bool {
        auto s = sys(task_vm.get());
        return s && s->tg->exited.load(std::memory_order_acquire);
    };

    std::vector<std::shared_ptr<vm>> children;
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        if(target_pid > 0) {
            auto it = pid_map.find(static_cast<uint64_t>(target_pid));
            if(it == pid_map.end()) {
                v->r(0) = -ECHILD;
                return true;
            }
            auto child_sys = sys(it->second.get());
            if(child_sys == nullptr || child_sys->ppid.load() != tg->tgid) {
                v->r(0) = -ECHILD;
                return true;
            }
            children.push_back(it->second);
        } else {
            for(const auto& entry : pid_map) {
                if(!match_child(entry.second)) continue;
                if(child_exited(entry.second)) {
                    children.clear();
                    children.push_back(entry.second);
                    break;
                }
                children.push_back(entry.second);
            }
        }
    }

    if(children.empty()) {
        v->r(0) = -ECHILD;
        return true;
    }

    std::shared_ptr<vm> child;
    if(children.size() == 1 && child_exited(children[0])) {
        child = children[0];
    } else {
        if(options & WNOHANG) {
            v->r(0) = 0;
            return true;
        }

        do {
            for(const auto& candidate : children) {
                auto cs = sys(candidate.get());
                if(!cs) continue;
                {
                    std::unique_lock<std::mutex> lk(cs->tg->mtx);
                    cs->tg->cv.wait_for(lk, std::chrono::milliseconds(100), [&]{
                        return cs->tg->exited.load(std::memory_order_acquire);
                    });
                }
                if(cs->tg->exited.load(std::memory_order_acquire)) {
                    child = candidate;
                    break;
                }
                // VM_KILLED：被 exit_group / 致命信号命中，应立即返回 EINTR 让线程回 safepoint 退出。
                // 不查 VM_EXITED：它在 run() 末尾才置，线程卡在 waitpid 内部时恒为假。
                if(!pending_signals.empty() || (flags(v).load(std::memory_order_acquire) & vm::VM_KILLED)) {
                    v->r(0) = -EINTR;
                    return true;
                }
            }
        } while(child == nullptr);
    }

    //wait不能加锁，否则会死锁
    auto cs = sys(child.get());
    uint64_t exit_code = static_cast<uint64_t>(cs->tg->exit_code.load(std::memory_order_acquire));
    if(status_ptr != nullptr) {
        int status = (static_cast<int>(exit_code) & 0xff) << 8;
        *status_ptr = status;
    }

    uint64_t child_pid = cs->pid;  // leader 的 pid（== tg->tgid）
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        pid_map.erase(child_pid);
    }
    v->r(0) = child_pid;
    return true;
}

bool PosixSyscall::do_set_tid_address(vm* v) {
    tid_address_ = v->r(1);
    // 这里返回 PID，让 musl __init_libc 认为 tid_address 已注册即可。
    // tid_address_ 由 fini() 的 clear-child-tid 路径读取（清零 + futex_wake）。
    v->r(0) = pid;
    return true;
}

bool PosixSyscall::do_sched_yield(vm* v) {
    sched_yield();
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_gettid(vm* v) {
    // 单线程进程语义下 gettid == getpid；fork 出去的子 VM 也是各自独立单线程，
    // 同样满足 gettid==getpid。
    v->r(0) = pid;
    return true;
}

bool PosixSyscall::do_set_tls(vm* v) {
    // 设置 thread pointer（musl __init_tp → __set_thread_area 在启动时调用）。
    // BPF 无 TLS 寄存器，用一个 VM 字段 tp_ 模拟；guest 侧 __get_tp() 经
    // BPF_SYS_GET_TLS 读回同一值。
    // 必须返回 0（成功），否则 musl __init_tls.c:149 会 a_crash()。
    tp(v) = v->r(1);
    v->r(0) = 0;
    return true;
}

bool PosixSyscall::do_get_tls(vm* v) {
    // 读取 thread pointer（guest 侧 __get_tp 用）。单线程下调用稀疏
    // （stdio getc/putc 热路径因 f->lock==0 短路，不触发 __pthread_self）。
    v->r(0) = tp(v);
    return true;
}
