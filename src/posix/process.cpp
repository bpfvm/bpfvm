#include "posix_internal.h"
#include <sys/wait.h>    // WEXITED/WSTOPPED/WNOWAIT（waitid 选项标志）

int64_t PosixSyscall::do_exit(vm* v) {
    int code = arg_s32(v->r(1));
    // CAS(-1 -> code)：首个正常退出者赢，后续不覆盖。致命信号默认动作走 do_exit_group，不经过此函数。
    int expected = -1;
    tg->exit_code.compare_exchange_strong(expected, code, std::memory_order_acq_rel);
    v->set_flags(vm::VM_EXITED);  // fini 减 live_threads + clear-child-tid
    return code;
}

int64_t PosixSyscall::do_exit_group(vm* v) {
    int code = arg_s32(v->r(1));
    // CAS(-1 -> code)：首个正常退出者赢，被置 VM_KILLED 的线程不走 do_exit，不会覆盖。
    int expected = -1;
    tg->exit_code.compare_exchange_strong(expected, code, std::memory_order_acq_rel);
    {
        // 杀掉线程组内所有其他线程。走目标线程自己的 queue_signal(SIGKILL)：
        std::lock_guard<std::mutex> lock(tg->mtx);
        for(auto& weak_vm : tg->threads) {
            auto tvm = weak_vm.lock();
            if(tvm && tvm.get() != v) {
                if(auto s = sys(tvm.get())) s->queue_signal(tvm.get(), {SIGKILL, pid, SI_USER, 0});
            }
        }
    }
    v->set_flags(vm::VM_EXITED);  // 调用线程退出 → fini
    return code;
}

// execveat(dirfd, path, argv, envp, flags) —— 唯一的 exec 入口。
// execve(path,...) 在 musl 里等价转发为 execveat(AT_FDCWD, path, argv, envp, 0)，
int64_t PosixSyscall::do_execveat(vm* v) {
    int dirfd = arg_s32(v->r(1));
    std::string path;
    if(!read_c_string(v, v->r(2), path, 4096)) {
        return -EFAULT;
    }
    int flags = arg_s32(v->r(5));

    if (dirfd == AT_FDCWD && (flags & AT_EMPTY_PATH)) {
        return -EINVAL;   // AT_EMPTY_PATH 需要有效 dirfd，不能是 AT_FDCWD
    }
    // 常规路径：dirfd+path 解析 + 符号链接穿透 + chroot 前缀。
    if(dirfd != AT_FDCWD && !ps->find_fd(dirfd)) {
        return -EBADF;
    }

    std::vector<std::string> argv_strings;
    std::vector<std::string> envp_strings;
    if(!read_c_string_array(v, v->r(3), argv_strings, 1024, 4096)) {
        return -EFAULT;
    }
    if(!read_c_string_array(v, v->r(4), envp_strings, 1024, 4096)) {
        return -EFAULT;
    }
    // envp_strings 是从 guest 读出的 "KEY=VALUE" 列表（read_c_string_array 的输出）
    std::map<std::string, std::string> envp_map;
    for(const auto& e : envp_strings) {
        auto eq = e.find('=');
        if(eq != std::string::npos) {
            envp_map[e.substr(0, eq)] = e.substr(eq + 1);
        }
    }
    std::string guest_abs;
    if(flags & AT_EMPTY_PATH) {
        auto fd = ps->find_fd(dirfd);
        if(!fd || fd->path.empty()) {
            return -EBADF;
        }
        guest_abs = ResolvePath(this, guest_abs_path(fd->path))->follow();
    } else {
        // follow 符号链接后取真实 guest 路径（/proc/self/exe→/bin/busybox 等），再拼 chroot 前缀
        guest_abs = ResolvePath(this, guest_abs_path(path, dirfd))->follow();
    }
    std::string host_path = guest_abs;
    if(!ps->root.empty()) {
        host_path = std::filesystem::path(ps->root + guest_abs).lexically_normal().string();
    }

    // 加载 ELF 并替换整个 guest 地址空间为新程序。
    //   host_path   —— 传给 load_elf 的宿主路径（已含 chroot 前缀）。
    //   guest_abs   —— guest 视角 exe 路径（写进 ps->exe_path，/proc/self/exe 目标；派生 comm）。
    auto fresh = vm::create();
    options(fresh.get()).stack_limit = options(v).stack_limit;
    options(fresh.get()).raw_stack   = options(v).raw_stack;
    ElfLoadInfo load_info = fresh->load_elf(host_path.c_str(), envp_map);
    if(load_info.entry == 0) {
        // load_elf 失败时 err 给出精确原因（ENOENT/EACCES/ENOEXEC...），未设置则回退 ENOEXEC。
        return load_info.err ? -load_info.err : -ENOEXEC;
    }
    const uint64_t entry = load_info.entry;
    // setup_stack 直接接收 load_info，用它合成 auxv
    if(!fresh->setup_stack(argv_strings, envp_map, load_info)) {
        return -E2BIG;
    }
    if(!fresh->mmu(entry)) {
        return -ENOEXEC;
    }
    options(v).entry = entry;
    options(v).argv = std::move(argv_strings);
    options(v).envp = std::move(envp_map);
    ps->exe_path = guest_abs;
    comm_ = make_comm(guest_abs);
    {
        std::lock_guard<std::mutex> lock(*maps_mutex(v));
        maps(v).swap(maps(fresh.get()));
    }
    v->flush_tlb();
    // exec 替换了整个 guest 地址空间：旧程序编译的 JIT 函数全部失效。
    v->clear_jit_cache();

    decltype(ps->signal_actions) new_actions{};
    const uint64_t sig_dfl = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_DFL));
    const uint64_t sig_ign = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(SIG_IGN));
    // exec：被忽略的信号保留 SIG_IGN（POSIX），其余恢复 SIG_DFL。
    for(size_t i = 0; i < new_actions.size(); i++) {
        new_actions[i].handler = handler_is_ignored(ps->signal_actions[i].handler) ? sig_ign : sig_dfl;
    }
    ps->signal_actions = new_actions;
    signal_depth(v) = 0;

    // exec 关闭所有 cloexec fd：保留非 cloexec 的构造新快照，cloexec 的 on_close（锁外）。
    auto cur_snap = ps->fds_snap();
    auto kept = std::make_shared<SharedState::FdMap>();
    for(const auto& entry : *cur_snap) {
        if(!entry.second->cloexec) {
            kept->insert(entry);
        } else {
            entry.second->on_close(this, v);
        }
    }
    ps->fds_replace(std::const_pointer_cast<const SharedState::FdMap>(kept));
    v->r(1) = fresh->r(1);
    v->r(10) = STACK_BASE + STACK_SIZE - 8;
    v->pc() = entry;
    v->push_frame(0);
    v->pc() -= sizeof(bpf_insn);
    return 0;
}

int64_t PosixSyscall::do_clone(vm* v) {
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
    std::shared_ptr<const SharedState::FdMap> child_fds_snap;
    if(!is_thread) {
        // 锁外逐个 host dup（::dup 是 syscall，不能在 fds_mutate 重试循环里），
        // 构造子的 FdMap 后整表 store 进子的 ps。
        auto parent_snap = ps->fds_snap();
        auto mutable_child = std::make_shared<SharedState::FdMap>();
        for(const auto& entry : *parent_snap) {
            // fork：host dup 得独立 host fd；GuestTty共享。
            auto new_handle = entry.second->clone();
            if(!new_handle) {
                return -errno;
            }
            new_handle->cloexec = entry.second->cloexec;
            (*mutable_child)[entry.first] = new_handle;
        }
        child_fds_snap = std::const_pointer_cast<const SharedState::FdMap>(mutable_child);
    }
    auto child_sys = std::make_shared<PosixSyscall>(pgrp, session);
    if(!is_thread) {
        // 整体拷贝而非逐字段罗列，避免新增 ps 字段时漏拷
        child_sys->ps = std::make_shared<SharedState>(*ps);
        // SharedState copy ctor 会让父子共享同一 fds 快照，子进程必须有独立 host fd，
        // 故整表替换覆盖。
        child_sys->ps->fds_replace(child_fds_snap);
        child_sys->tg->ppid.store(tg->tgid);
    } else {
        child_sys->ps = ps;
        child_sys->tg = tg;
        tg->live_threads.fetch_add(1);
    }
    // comm 是 per-thread：fork/CLONE_THREAD 都继承 creator 的 comm。
    child_sys->comm_ = comm_;
    // fork/clone 都继承父的信号掩码（Linux：clone 不论 CLONE_THREAD 都按 fork 语义拷贝 mask）。
    child_sys->sigmask.store(sigmask.load(std::memory_order_relaxed), std::memory_order_relaxed);
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
            child_map.path = map.path;

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
        /* fork（非 CLONE_VM）时 emutls 副本段也随 maps 走 CoW（PF_W 段已建 cow_data）。
         * 把父的 emutls_slots_ 直接复制给子：子的 slot 指向同一 guest 地址（同一 CoW
         * 共享页），子进程写 TLS 时 mmu_w 触发 CoW 分配独立页，达到"子继承父的 TLS
         * 当前值、之后各自独立"的 fork 语义。CLONE_THREAD（线程）不进此分支，每线程
         * 的 slots 本就独立。 */
        emutls_slots(child.get()) = emutls_slots(v);
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

    // child 继承父所有寄存器。其中libc的clone的func、arg是通过callee-save寄存器保留的
    for(size_t i = 0; i < 11; i++) {
        child->r(i) = v->r(i);
    }
    child->r(0) = 0;
    /* 栈来源：clone 调用者通过 r(2) 提供新栈顶；stack==NULL（如 fork 经 do_clone
     * 传入）时继承父 r(10)——fork 的子进程是父地址空间的 CoW 副本，栈也在其中，
     * 直接用父栈指针即可（上面 r(i)=v->r(i) 已拷贝了 r(10)，这里 stack!=0 才覆盖）。 */
    if(stack != 0) {
        child->r(10) = stack;
        // 提供了新栈（pthread 路径），写入哨兵帧, clone返回后应该立即调用func(arg)，压入一个真实帧
        if(uint64_t* sent = static_cast<uint64_t*>(v->mmu_w(stack, sizeof(uint64_t)))) {
            *sent = frame_flags_make(false, 0);
        }
    }
    child->pc() = v->pc() + sizeof(bpf_insn);

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
        return -rc;
    }
    rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if(rc != 0) {
        pthread_attr_destroy(&attr);
        return -rc;
    }
    // 先登记 pid_map / tg->threads，再启动 host 线程。
    {
        std::lock_guard<std::mutex> lock(child_sys->tg->mtx);
        child_sys->tg->threads.push_back(child);
    }
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        pid_map[child_sys->pid] = child;
    }
    v->notify_create(child.get(), is_thread);
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
        {
            std::lock_guard<std::mutex> lock(pid_map_mutex);
            pid_map.erase(child_sys->pid);
        }
        {
            std::lock_guard<std::mutex> lock(child_sys->tg->mtx);
            child_sys->tg->threads.pop_back();
        }
        return -rc;
    }
    return (int64_t)child_sys->pid;
}

int64_t PosixSyscall::do_getpid(vm*) {
    return (int64_t)tg->tgid;
}

int64_t PosixSyscall::do_getppid(vm*) {
    return (int64_t)tg->ppid.load();
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

// 枚举存活 pid（pid_map 的 key 快照）。供 procfs 列举 /proc 顶层 [pid] 目录。
std::vector<uint64_t> PosixSyscall::list_pids() {
    std::lock_guard<std::mutex> lock(pid_map_mutex);
    std::vector<uint64_t> pids;
    pids.reserve(pid_map.size());
    for(const auto& kv : pid_map) {
        pids.push_back(kv.first);
    }
    return pids;
}

// wait4/waitid 共享的等待核心。idtype/id 用 POSIX 语义（P_ALL=0/P_PID=1/P_PGID=2），
// 由两个 handler 把各自的 syscall 参数归一化后传入。options 已经过 handler 校验。
// 选定 child 后只填充 out，不写 status/siginfo、不 erase pid_map（由 handler 按 WNOWAIT 决定）。
// 返回值：负 errno=失败；SYSCALL_RESTART=被信号打断可重启；0=成功（out.child 可能为空，
//   表示 WNOHANG 且无事件，handler 据此返回 0 pid）。
int64_t PosixSyscall::do_wait_common(vm* v, int idtype, int64_t id, int options, wait_event& out) {
    // 收集候选子进程。Linux 语义：
    //   P_PID  (id > 0) → 指定 task（必须是自身子进程的线程组 leader）
    //   P_PGID (id >=0) → 进程组 id 里任意子进程（wait4 的 pid==0 表示调用者进程组）
    //   P_ALL         → 任意子进程
    // 只有 leader（pid == tg->tgid）可被 wait；非 leader 线程退出不产生可 wait 状态。
    // wait4 的 pid==0 映射为 P_PGID + 调用者 pgid，已由 do_wait4 转好。
    auto match_child = [&](const std::shared_ptr<vm>& task_vm) -> bool {
        auto s = sys(task_vm.get());
        if(!s || s->tg->ppid.load() != tg->tgid) return false;
        if(s->pid != s->tg->tgid) return false;  // 仅 leader 可 wait
        if(idtype == 0 /*P_ALL*/) return true;
        if(idtype == 1 /*P_PID*/)  return s->pid == static_cast<uint64_t>(id);
        if(idtype == 2 /*P_PGID*/) return s->pgrp->pgid == static_cast<uint64_t>(id);
        return false;
    };

    // 子进程是否有可报告事件：已退出（WIFEXITED/WIFSIGNALED）或已停止且 stop_reported（WIFSTOPPED）。
    // stop_reported 由 stop_process 投 SIGCHLD 时置 true，消费后清——它兼做"该停止已通知过"
    // 的去重标志：只有 stop_reported 为真的停止才可被报告（避免重复报告同一停止）。
    auto child_has_event = [](const std::shared_ptr<vm>& task_vm) -> bool {
        auto s = sys(task_vm.get());
        if(!s) return false;
        return s->tg->exited.load(std::memory_order_acquire) ||
               (s->tg->stopped.load(std::memory_order_acquire) &&
                s->tg->stop_reported.load(std::memory_order_acquire));
    };

    std::vector<std::shared_ptr<vm>> children;
    {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        if(idtype == 1 /*P_PID*/) {
            auto it = pid_map.find(static_cast<uint64_t>(id));
            if(it == pid_map.end()) {
                return -ECHILD;
            }
            auto child_sys = sys(it->second.get());
            if(child_sys == nullptr || child_sys->tg->ppid.load() != tg->tgid) {
                return -ECHILD;
            }
            children.push_back(it->second);
        } else {
            for(const auto& entry : pid_map) {
                if(!match_child(entry.second)) continue;
                children.push_back(entry.second);
            }
            // 优先返回已有事件的子进程（退出或已通知的停止）。
            for(auto& c : children) {
                if(child_has_event(c)) {
                    children = {c};
                    break;
                }
            }
        }
    }

    if(children.empty()) {
        return -ECHILD;
    }

    // 选一个有事件的子进程。无事件且非阻塞 → 立即返空 child；否则轮询 tg->cv 等事件。
    std::shared_ptr<vm> child;
    for(auto& c : children) {
        if(child_has_event(c)) {
            child = c;
            break;
        }
    }
    if((child == nullptr) && (options & WNOHANG)) {
        return 0;  // out.child 保持空，handler 据此返回 0
    }

    while(child == nullptr) {
        for(const auto& candidate : children) {
            auto cs = sys(candidate.get());
            if(!cs) continue;
            {
                std::unique_lock<std::mutex> lk(cs->tg->mtx);
                // 子退出 或 子停止且已通知。notify 来自 fini()/stop_process()。
                cs->tg->cv.wait_for(lk, std::chrono::milliseconds(100), [&]{
                    return cs->tg->exited.load(std::memory_order_acquire) ||
                           (cs->tg->stopped.load(std::memory_order_acquire) &&
                            cs->tg->stop_reported.load(std::memory_order_acquire));
                });
            }
            if(cs->tg->exited.load(std::memory_order_acquire)) {
                child = candidate;
                break;
            }
            if(cs->tg->stopped.load(std::memory_order_acquire) &&
               cs->tg->stop_reported.load(std::memory_order_acquire)) {
                child = candidate;
                break;
            }
            // 调用者自身被 VM_KILL / 收到信号 / GDB 请求停下 -> 标记为可重启。
            // 不查 VM_EXITED：它在 run() 末尾才置，线程卡在 wait 内部时恒为假。
            // VM_DEBUG_STOP：GDB Ctrl-C/单步经 stop_all_vms 置位，要求本 vm 回解释器停下。
            if(!pending_signals.empty() ||
               (v->get_flags() & (vm::VM_KILLED | vm::VM_STOPPED | vm::VM_DEBUG_STOP))) {
                return SYSCALL_RESTART;
            }
        }
    }

    //wait 不能加锁，否则会死锁
    auto cs = sys(child.get());
    out.child = child;
    // exited 优先于 stopped：被 SIGKILL 的已停止进程，fini 设 tg->exited 但不清
    // tg->stopped（只有 SIGCONT 清），必须按退出报告，否则父进程（如 dash `kill -9 %1`）
    // 永不回收作业。
    if(cs->tg->exited.load(std::memory_order_acquire)) {
        out.exited = true;
        out.exit_code = static_cast<uint64_t>(cs->tg->exit_code.load(std::memory_order_acquire));
    } else {
        // 报告停止。进程仍存活：不 erase pid_map，不清 stopped（SIGCONT 才清），
        // 清 stop_reported 使下次停止能再投 SIGCHLD + 再被报告。
        out.exited = false;
        out.stop_sig = cs->tg->stop_sig.load(std::memory_order_acquire);
        cs->tg->stop_reported.store(false, std::memory_order_release);
    }
    return 0;
}

// 把子进程 exit_code 编码成 wait4 的 int status（WIFEXITED/WIFSIGNALED）。
// exit_code < 128=正常退出码（bits 8-15）；>=128=128+sig（信号致死），status=sig&0x7f。
static int wait4_exit_status(uint64_t exit_code) {
    if(exit_code >= 128) {
        return static_cast<int>(exit_code - 128) & 0x7f;  // WIFSIGNALED
    }
    return (static_cast<int>(exit_code) & 0xff) << 8;  // WIFEXITED
}

int64_t PosixSyscall::do_wait4(vm* v) {
    int64_t target_pid = static_cast<int64_t>(arg_s32(v->r(1)));
    uint64_t status_addr = v->r(2);
    int32_t options = arg_s32(v->r(3));
    // wait4 不接受 waitid 专属选项位（WEXITED/WSTOPPED/WNOWAIT 等），其余选项（WCONTINUED 等）暂不支持。
    if((options & ~(WNOHANG | WUNTRACED)) != 0) {
        return -EINVAL;
    }

    // waitpid(self) 无意义
    if(target_pid == (int64_t)pid) {
        return -EINVAL;
    }

    int* status_ptr = nullptr;
    if(status_addr != 0) {
        status_ptr = static_cast<int*>(v->mmu_w(status_addr, sizeof(*status_ptr)));
        if(status_ptr == nullptr) {
            return -EFAULT;
        }
    }

    // wait4 的 pid 编码归一化为 (idtype, id)：
    //   pid > 0  → P_PID
    //   pid == 0 → P_PGID（调用者进程组）
    //   pid == -1→ P_ALL
    //   pid < -1 → P_PGID（进程组 -pid）
    int idtype;
    int64_t id;
    if(target_pid > 0) {
        idtype = 1 /*P_PID*/;
        id = target_pid;
    } else if(target_pid == -1) {
        idtype = 0 /*P_ALL*/;
        id = 0;
    } else if(target_pid == 0) {
        idtype = 2 /*P_PGID*/;
        id = static_cast<int64_t>(pgrp->pgid);
    } else {
        idtype = 2 /*P_PGID*/;
        id = -target_pid;
    }

    wait_event ev;
    int64_t rc = do_wait_common(v, idtype, id, options, ev);
    if(rc != 0) {
        return rc;  // 负 errno / SYSCALL_RESTART
    }
    if(ev.child == nullptr) {
        return 0;  // WNOHANG 且无事件
    }

    auto cs = sys(ev.child.get());
    if(status_ptr != nullptr) {
        if(ev.exited) {
            *status_ptr = wait4_exit_status(ev.exit_code);
        } else {
            // 停止：status = (stop_sig << 8) | 0x7f（musl WIFSTOPPED 判定低字节 == 0x7f，
            // WSTOPSIG 取高字节）。
            *status_ptr = ((ev.stop_sig & 0xff) << 8) | 0x7f;
        }
    }

    // 退出的子进程回收 pid_map；停止的进程仍存活，不 erase。
    if(ev.exited) {
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        pid_map.erase(cs->pid);
    }
    return (int64_t)cs->pid;  // leader 的 pid（== tg->tgid）；停止/退出均返此值
}

int64_t PosixSyscall::do_waitid(vm* v) {
    int idtype = arg_s32(v->r(1));
    int64_t id = static_cast<int64_t>(v->r(2));
    uint64_t info_addr = v->r(3);
    int32_t options = arg_s32(v->r(4));

    // idtype 必须是已知值（P_ALL=0/P_PID=1/P_PGID=2）。P_PIDFD（=3）VM 不支持。
    if(idtype < 0 || idtype > 2) {
        return -EINVAL;
    }

    // waitid 选项：WEXITED/WSTOPPED/WCONTINUED 至少置一，可加 WNOHANG/WNOWAIT。
    // 当前实现不支持 WCONTINUED（停止/退出已覆盖常见用法）。
    const int WAITID_VALID = WNOHANG | WUNTRACED /*=WSTOPPED*/ | WEXITED | WNOWAIT;
    if((options & ~WAITID_VALID) != 0 || (options & (WEXITED | WUNTRACED)) == 0) {
        return -EINVAL;
    }

    // P_ALL 时 id 被忽略；P_PID/P_PGID 时 id 须非负。
    if(idtype != 0 && id < 0) {
        return -EINVAL;
    }

    // waitid(P_PGID, 0) 与 wait4 的 pid==0 同义：表示调用者进程组。
    // do_wait_common 的 match_child 按 pgid 数值匹配（pgid==0 的进程组不存在），
    // 故这里把 id==0 归一化为调用者 pgid，与 do_wait4 行为对齐。
    if(idtype == 2 /*P_PGID*/ && id == 0) {
        id = static_cast<int64_t>(pgrp->pgid);
    }

    // 映射 waitid 的 idtype 到 do_wait_common 用的同一套（0/1/2 一致）。
    wait_event ev;
    // do_wait_common 内部用 WNOHANG/WUNTRACED；waitid 的 WEXITED 对应"报告退出"，
    // 是 do_wait_common 默认行为（exited 优先），无需额外位；WNOWAIT 由本函数处理（不回收）。
    int common_opts = (options & WNOHANG) | ((options & WUNTRACED) ? WUNTRACED : 0);
    int64_t rc = do_wait_common(v, idtype, id, common_opts, ev);
    if(rc != 0) {
        return rc;  // 负 errno / SYSCALL_RESTART
    }

    // 成功。即使 info_addr==0（合法：仅回收不取细节），waitid 成功返 0。
    // 无可报告事件（WNOHANG）：返 0 且不填 siginfo（与 Linux 一致：0 表示无事件）。
    if(ev.child != nullptr && info_addr != 0) {
        auto cs = sys(ev.child.get());
        // siginfo 布局（musl 默认 ABI，非 mips swap）：
        //   si_signo@0(int) si_errno@4(int) si_code@8(int) 填充@12
        //   si_pid@16(int) si_uid@20(int) si_status@24(int)
        // 全部按 int（4 字节）写。
        // si_status 语义与 wait4 的 int status 不同：对 SIGCHLD 事件，waitid 的
        // si_status 存的是【原始值】（CLD_EXITED=退出码、CLD_KILLED/CLD_DUMPED=信号号、
        // CLD_STOPPED=停止信号号），不是 wait4 的 (code<<8|sig) 状态字——不能用
        // WEXITSTATUS/WTERMSIG 解码 si_status（实测 Linux：_exit(42)→si_status=42，
        // SIGKILL→si_status=9）。局部变量加 out_ 前缀避开 glibc <signal.h> 宏。
        int out_signo = 17 /*SIGCHLD*/;
        int out_code;
        int out_status;
        if(ev.exited) {
            // exit_code：<128=正常退出码，>=128=128+sig（信号致死）。
            if(ev.exit_code >= 128) {
                out_code = 2 /*CLD_KILLED*/;
                out_status = static_cast<int>(ev.exit_code - 128);  // 原始信号号
            } else {
                out_code = 1 /*CLD_EXITED*/;
                out_status = static_cast<int>(ev.exit_code);  // 原始退出码
            }
        } else {
            out_code = 5 /*CLD_STOPPED*/;
            out_status = ev.stop_sig;  // 原始停止信号号
        }
        int out_pid = static_cast<int>(cs->pid);
        // 用 mmu_w 取一整块（28 字节，覆盖到 si_status）逐字段写。
        if(auto* p = static_cast<int*>(v->mmu_w(info_addr, 28))) {
            p[0] = out_signo;   // @0  si_signo
            p[1] = 0;           // @4  si_errno
            p[2] = out_code;    // @8  si_code
            // @12 对齐填充，保持 0
            p[4] = out_pid;     // @16 si_pid
            p[5] = 0;           // @20 si_uid（VM 无真实 uid）
            p[6] = out_status;  // @24 si_status（原始值，见上）
        } else {
            return -EFAULT;
        }
    }

    // 回收：退出事件且未要求 WNOWAIT 才 erase。停止事件不回收（进程仍存活）。
    if(ev.child != nullptr && ev.exited && !(options & WNOWAIT)) {
        auto cs = sys(ev.child.get());
        std::lock_guard<std::mutex> lock(pid_map_mutex);
        pid_map.erase(cs->pid);
    }
    return 0;  // waitid 成功返 0（不是 pid）
}

int64_t PosixSyscall::do_set_tid_address(vm* v) {
    tid_address_ = v->r(1);
    // 这里返回 PID，让 musl __init_libc 认为 tid_address 已注册即可。
    // tid_address_ 由 fini() 的 clear-child-tid 路径读取（清零 + futex_wake）。
    return (int64_t)pid;
}

int64_t PosixSyscall::do_sched_yield(vm*) {
    sched_yield();
    return 0;
}

int64_t PosixSyscall::do_gettid(vm*) {
    // 单线程进程语义下 gettid == getpid；fork 出去的子 VM 也是各自独立单线程，
    // 同样满足 gettid==getpid。
    return (int64_t)pid;
}

int64_t PosixSyscall::do_set_tls(vm* v) {
    // 设置 thread pointer（musl __init_tp → __set_thread_area 在启动时调用）。
    // BPF 无 TLS 寄存器，用一个 VM 字段 tp_ 模拟；guest 侧 __get_tp() 经
    // BPF_SYS_GET_TLS 读回同一值。
    // 必须返回 0（成功），否则 musl __init_tls.c:149 会 a_crash()。
    tp(v) = v->r(1);
    return 0;
}

int64_t PosixSyscall::do_get_tls(vm* v) {
    // 读取 thread pointer（guest 侧 __get_tp 用）。单线程下调用稀疏
    // （stdio getc/putc 热路径因 f->lock==0 短路，不触发 __pthread_self）。
    return (int64_t)tp(v);
}
