//
// GDB Remote Serial Protocol (RSP) server 实现。详见 gdb_server.h。
//

#include "gdb_server.h"
#include "posix/posix_syscall.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

#include <cstring>
#include <cstdio>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// BPF 寄存器在 g/G 包里的顺序与数量（r0..r9, r10=fp, pc）。
// GDB bpf-tdep.c 把 r0..r10 + pc 列为 num_regs，每个 8 字节小端。
static constexpr int GDB_NUM_REGS = 12;  // r0-r10 + pc

GdbServer::GdbServer(std::shared_ptr<vm> main_vm, uint16_t port, const ElfLoadInfo& info,
                     bool stop_at_start)
    : main_vm_(std::move(main_vm)), port_(port), info_(info), stop_at_start_(stop_at_start) {}

GdbServer::~GdbServer() {
    stop();
}

void GdbServer::start() {
    // 主 vm 登记到自维护 tracee 表（后续 fork/clone 的子由 on_create_vm 登记）。
    // 此时 main_vm_ 尚未 run()，options.sys 未初始化（run() 内才赋值），无法取 sys()->id()，
    // 但根进程的 pid 恒为 1（next_pid 初值 1，pid 1 永远是根进程），故显式传 1。
    register_task(1, main_vm_);
    // 注册 vm 派生回调 + syscall 钩子：父 vm fork/clone 时 do_clone 经 notify_create 同步调用
    // hooks->create，据此把调试态/断点继承给子并按需停父上报 fork 事件；syscall 钩子在
    // do_syscall 的 entry/return 同步调用。回调内会把它继承给 child，故多层派生（main→child1
    // →child2…）都通知到本 server。连上前未 attach 时 syscall 钩子因 sys 未... 实际上钩子
    // 恒挂载，但回调内查 syscall_catch_.enabled（默认 false）直接返回；create 回调在父无
    // VM_DEBUG_ATTACHED 时提前返回，子不被 trace（对齐「未 attach 啥都不跟踪」）。
    install_debug_hooks();

    if(stop_at_start_) {
        // --stop（对齐 QEMU -S）：在 run() 前就把主 vm 置调试态 + 待停。
        //   VM_DEBUG_ATTACHED：禁 JIT（compile() 见到返回 nullptr）、step() 据此每步查断点
        //   VM_DEBUG_STOP：第一条 step() 命中即置 VM_STOPPED 在 safepoint 阻塞，等 GDB 连接后
        //                  continue 才放行。必须在 run() 启动前设置，否则与首条指令竞态。
        main_vm_->set_flags(vm::VM_DEBUG_ATTACHED | vm::VM_DEBUG_STOP);
    }
    // 默认（不带 --stop）：不置任何调试 flag，主 vm 全速 JIT 跑，等 GDB 连上后由
    // attach_on_connect() 置 VM_DEBUG_ATTACHED|VM_STOPPED 停在当前 pc。
    running_ = true;
    thread_ = std::thread([this] { server_loop(); });
}

void GdbServer::stop() {
    // 清空 vm 派生回调 + syscall 钩子：防止 stop 后（虽然此时 vm 已退出）任何残留的
    // notify_create / do_syscall 触发悬空回调。幂等——start() 下次会话会重新注册。
    if(main_vm_) main_vm_->set_debug_hooks(std::make_shared<const DebugHooks>());
    // 关闭 listen fd 拒绝新连接；client fd 由 server_loop 在 GDB 断开或 vm 退出后
    // 自行关闭。main 在 run() 返回后调用本函数。server_loop 用带超时的 recv（SO_RCVTIMEO）
    // 周期性检查 running_，从而在收到停止信号后能及时退出。
    //
    // 注意：不能用 `if(!running_.exchange(false)) return;` 提前返回——server_loop 的
    // LoopExitGuard 在退出时会把 running_ 置 false（如 GDB 断开后自然退出），此时若 main
    // 再调 stop()，exchange 返回 false 会直接 return，跳过下面的 thread_.join()，
    // 导致 std::thread 析构时仍 joinable → std::terminate（kill 场景必现崩溃）。
    // 是否要 join 只取决于 thread_.joinable()，与 running_ 的值无关。
    running_ = false;
    if(listen_fd_ >= 0) {
        shutdown(listen_fd_, SHUT_RDWR);
        close(listen_fd_);
        listen_fd_ = -1;
    }
    if(thread_.joinable()) {
        // 轮询等待 server_loop 自然退出（GDB 断开或 vm 退出），最多 ~6 秒。
        // running_ 已 false，server 应在 ≤0.2s（一个 recv 超时周期）内退出；超时则
        // 强制关 client fd 让阻塞中的 recv 返回后再 join。
        for(int i = 0; i < 60 && !loop_done_.load(std::memory_order_acquire); i++) {
            timespec ts{0, 100000000};  // 0.1s
            nanosleep(&ts, nullptr);
        }
        if(!loop_done_.load(std::memory_order_acquire)) {
            if(client_fd_ >= 0) { ::shutdown(client_fd_, SHUT_RDWR); ::close(client_fd_); client_fd_ = -1; }
        }
        thread_.join();
    }
}

// ── hex 工具 ──────────────────────────────────────────────────────────────
int GdbServer::hex_val(char c) {
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string GdbServer::to_hex2(uint8_t v) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s += d[(v >> 4) & 0xF];
    s += d[v & 0xF];
    return s;
}

std::string GdbServer::reg_to_hex(uint64_t v) {
    // 小端：低字节在前
    std::string s;
    for(int i = 0; i < 8; i++) s += to_hex2((v >> (i * 8)) & 0xFF);
    return s;
}

uint64_t GdbServer::hex_to_reg(const std::string& s) {
    uint64_t v = 0;
    for(int i = 0; i < 8 && (size_t)(i * 2) < s.size(); i++) {
        int hi = hex_val(s[i * 2]);
        int lo = hex_val(s[i * 2 + 1]);
        if(hi < 0 || lo < 0) break;
        v |= (uint64_t)((hi << 4) | lo) << (i * 8);
    }
    return v;
}

std::string GdbServer::hex_encode(const void* data, size_t len) {
    auto* p = static_cast<const unsigned char*>(data);
    std::string s;
    s.reserve(len * 2);
    for(size_t i = 0; i < len; i++) s += to_hex2(p[i]);
    return s;
}

bool GdbServer::hex_decode(const std::string& s, void* out, size_t len) {
    if(s.size() < len * 2) return false;
    auto* p = static_cast<unsigned char*>(out);
    for(size_t i = 0; i < len; i++) {
        int hi = hex_val(s[i * 2]);
        int lo = hex_val(s[i * 2 + 1]);
        if(hi < 0 || lo < 0) return false;
        p[i] = (unsigned char)((hi << 4) | lo);
    }
    return true;
}

// ── RSP 包 I/O ────────────────────────────────────────────────────────────
// 单字节可靠接收：SO_RCVTIMEO 超时（EAGAIN/EWOULDBLOCK）和被信号打断（EINTR）时
// 重试——GDB 握手时会流水线连发多个包，单字节 recv 可能在包中间超时，若直接当
// 错误返回会截断包导致校验和失败。仅以下情况返回 false：EOF、硬错误、或 running_
// 被外部（stop()）置 false（此时不再重试，让 recv_packet 返回，server 退出）。
bool GdbServer::recv_byte(char& out) {
    for(;;) {
        if(!running_) return false;
        ssize_t n = recv(client_fd_, &out, 1, 0);
        if(n == 1) return true;
        if(n == 0) return false;  // EOF
        if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
        return false;  // 硬错误
    }
}

bool GdbServer::recv_packet(std::string& out) {
    // 略过 ack '+'/'-'（no_ack 模式下理论上不会来，但容错跳过）和 Ctrl-C (0x03)
    char c;
    for(;;) {
        if(!recv_byte(c)) return false;
        if(c == '$') break;
        // 其余（+, -, 0x03）忽略
    }
    std::string data;
    uint8_t cksum = 0;
    for(;;) {
        if(!recv_byte(c)) return false;
        if(c == '#') break;
        data += c;
        cksum += (uint8_t)c;
    }
    // 校验和两 hex
    char cs[2];
    if(!recv_byte(cs[0])) return false;
    if(!recv_byte(cs[1])) return false;
    int hi = hex_val(cs[0]), lo = hex_val(cs[1]);
    if(!no_ack_) {
        char ack = (hi < 0 || lo < 0 || (uint8_t)((hi << 4) | lo) != cksum) ? '-' : '+';
        send(client_fd_, &ack, 1, 0);
    }
    out = data;
    return true;
}

void GdbServer::send_packet(const std::string& payload) {
    uint8_t cksum = 0;
    for(char c : payload) cksum += (uint8_t)c;
    std::string pkt = "$" + payload + "#";
    pkt += to_hex2(cksum);
    // 简单发送（payload 小，TCP 缓冲足够）
    size_t off = 0;
    while(off < pkt.size()) {
        ssize_t n = send(client_fd_, pkt.data() + off, pkt.size() - off, 0);
        if(n <= 0) break;
        off += (size_t)n;
    }
}

// ── vm 状态访问 ──────────────────────────────────────────────────────────
// 主 vm 的线程 id（PosixSyscall::pid）。用于 H0/H-1/qC 等需要真实线程 id 的回复——
// RSP 线程 id 0 是特殊值，不能作为 current 返回，否则 GDB switch_to_thread(NULL) 崩。
uint64_t GdbServer::main_thread_id() {
    return main_vm_->sys()->id();
}

// ── 自维护 tracee 表（tasks_）helper ─────────────────────────────────────
// 按 pid 查 tasks_。持锁取 shared_ptr 出来，调用方持有期间 vm 不会被析构。
// 注意：vm 即使已退出（VM_EXITED）仍在此表（直到 send_exit_reply/detach_vm 移除），
// 故退出后仍可读 r(0)/tgid 发退出回复——这正是自维护表而非依赖 pid_map 的意义。
std::shared_ptr<vm> GdbServer::find_task(uint64_t pid) {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    auto it = tasks_.find(pid);
    return it == tasks_.end() ? nullptr : it->second;
}

// tasks_ 的 key 快照（供 all-stop 协调 / 线程枚举等迭代）。持锁内拷贝，锁外遍历安全。
std::vector<uint64_t> GdbServer::list_tasks() {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    std::vector<uint64_t> pids;
    pids.reserve(tasks_.size());
    for(const auto& kv : tasks_) pids.push_back(kv.first);
    return pids;
}

// 存入 tasks_。pid 由调用方提供（见头文件注释）。已存在则覆盖（理论上同一 pid 不会
// 重复登记，覆盖是防御）。
void GdbServer::register_task(uint64_t pid, std::shared_ptr<vm> v) {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    tasks_[pid] = std::move(v);
}

// 从 tasks_ 移除 pid（释放 shared_ptr 引用）。不存在则空操作。
void GdbServer::unregister_task(uint64_t pid) {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    tasks_.erase(pid);
}

// 取 vm 所属线程组 id（tgid）。multiprocess 线程 id 形如 pPID.TID，其中 PID 是进程级
// 标识（tgid）、TID 是线程级标识（vm 的 pid）。leader 线程的 pid==tgid；非 leader 线程
// pid!=tgid。sys 为非 PosixSyscall（测试 EmptySyscall）时退化为 pid。
uint64_t GdbServer::vm_tgid(vm* v) {
    if(auto s = PosixSyscall::sys(v)) return s->tg->tgid;
    return (uint64_t)v->sys()->id();
}

// 把 vm 的 pid 编码成 RSP 线程 id 字符串。multiprocess 关闭：裸 hex pid（如 "1"）；
// 开启：pPID.TID（如 "p1.1"，PID=tgid、TID=pid）。主 vm 退化为 main_thread_id()。
std::string GdbServer::encode_tid(uint64_t pid) {
    char buf[64];
    if(!multiprocess_) {
        std::snprintf(buf, sizeof(buf), "%lx", (unsigned long)pid);
        return buf;
    }
    auto v = find_task(pid);
    if(!v) {
        // 不在本 server 表里（已 detach / 未知 pid）：用 pid 作 tgid 兜底（GDB 仅用于显示）
        std::snprintf(buf, sizeof(buf), "p%lx.%lx", (unsigned long)pid, (unsigned long)pid);
        return buf;
    }
    uint64_t tgid = vm_tgid(v.get());
    std::snprintf(buf, sizeof(buf), "p%lx.%lx", (unsigned long)tgid, (unsigned long)pid);
    return buf;
}

// 解析 RSP 线程 id 字符串为 vm 的 pid。
//   裸 hex（"1"/"2a"）：multiprocess 关闭时直接 strtoull；开启时按裸 pid 处理（兼容）。
//   pPID.TID（"p1.1"）：multiprocess 格式，取 TID 段作为 pid。
//   "0"/"-1"/"p0.0"/"p-1.-1"：RSP 特殊值（任意/所有），返回 0（调用方映射到主线程）。
uint64_t GdbServer::decode_tid(const std::string& s) {
    if(s.empty()) return 0;
    if(s[0] == 'p') {
        // multiprocess 形式 pPID.TID
        std::string rest = s.substr(1);
        auto dot = rest.find('.');
        std::string tid_str = (dot == std::string::npos) ? rest : rest.substr(dot + 1);
        if(tid_str == "0" || tid_str == "-1") return 0;
        return std::strtoull(tid_str.c_str(), nullptr, 16);
    }
    if(s == "0" || s == "-1") return 0;
    return std::strtoull(s.c_str(), nullptr, 16);
}

std::shared_ptr<vm> GdbServer::current_vm() {
    if(current_thread_ != 0) {
        if(auto v = find_task(current_thread_)) return v;
    }
    return main_vm_;
}

bool GdbServer::is_vm_exited(vm* v) {
    return v->get_flags() & (vm::VM_EXITED | vm::VM_KILLED);
}

// 每次 GDB 连上（accept 成功）后调：复位 per-connection 协商态。每条连接都是全新的
// RSP 会话，上一会话的 multiprocess/fork-events 等协商结果不应带过来（否则未协商的
// 新 GDB 会收到 pPID.TID 格式的 tid 但按裸 hex 解析，错乱）。
void GdbServer::reset_session_state() {
    no_ack_ = false;
    multiprocess_ = false;
    report_fork_events_ = false;
    exit_notified_ = false;
    current_thread_ = 0;
    {
        std::lock_guard<std::mutex> lk(fork_events_mutex_);
        fork_events_.clear();
    }
    // 新会话默认不 catch syscall（除非 GDB 重新发 QCatchSyscalls）；清残留待上报事件。
    syscall_catch_.store(std::make_shared<const SyscallCatchCfg>());
    {
        std::lock_guard<std::mutex> lk(syscall_events_mutex_);
        pending_syscall_events_.clear();
    }
}

// 每次 GDB 连上后调：确保 pid 1 被 attach 并停在当前 pc。
//   - 默认模式（--gdb）：start() 没置任何 flag，pid 1 正全速 JIT 跑。这里置
//     VM_DEBUG_ATTACHED|VM_DEBUG_STOP（请求位）+ wakeup + host_signal：flags 非零让 JIT
//     safepoint（循环头/helper_do_syscall）退出 JIT 回解释器；回解释器后 step() 见
//     VM_DEBUG_STOP 即 debug_park 转成 VM_STOPPED 阻塞；host_signal（pthread_kill SIGUSR1）
//     EINTR 阻塞中的 host syscall 让它回解释器边界。VM_DEBUG_ATTACHED 此后让 compile()
//     永远返回 nullptr，解释器接管的断点/单步机制照常。
//   - --stop 首次连接：start() 已把 pid 1 冻结在入口（VM_DEBUG_ATTACHED|VM_DEBUG_STOP）。
//     此处见已 attach 直接跳过，避免覆盖 VM_DEBUG_STOP。
//   - 重复 attach：end_session 把 pid 1 的 VM_DEBUG_ATTACHED 清掉了，这里重新置回。
void GdbServer::attach_on_connect() {
    auto v = find_task(1);
    if(!v) v = main_vm_;  // end_session/detach 后 tasks_ 里可能没 pid 1，从 main_vm_ 找回
    register_task(1, v);  // 重新登记（幂等；重复 attach 时确保 tasks_ 有 pid 1）
    if(!(v->get_flags() & vm::VM_DEBUG_ATTACHED)) {
        v->set_flags(vm::VM_DEBUG_ATTACHED | vm::VM_DEBUG_STOP);
        v->wakeup(false);
        v->sys()->host_signal(v.get(), 0);  // EINTR 阻塞 syscall，让它尽快回解释器停下
    }
}

// 每次会话结束（GDB 断开 / D 包 detach all）调：让所有被 trace 的 vm 脱离调试器恢复
// 全速 JIT 自由运行，但**保留 pid 1 在 tasks_** 以便下一次 GDB 连上时重新 attach。
//   - pid != 1：调 detach_vm（清 flag + 从 tasks_ 移除；这些子进程后续不再被本会话跟踪）。
//   - pid == 1：清 VM_DEBUG_ATTACHED/VM_DEBUG_STOP/VM_STOPPED + 清断点 + wakeup（让它恢复
//     JIT 全速），但**不** unregister——保留在 tasks_ 里，下次 attach_on_connect 会重新置 flag。
//   - 清 fork_events_：会话结束，残留条目不再有意义。
// 与 detach_all_vms() 区别：后者把 pid 1 也 unregister（用于 server 最终退出、main 返回时）。
void GdbServer::end_session() {
    auto pids = list_tasks();
    for(uint64_t pid : pids) {
        if(pid == 1) {
            auto v = find_task(1);
            if(v && !(v->get_flags() & (vm::VM_EXITED | vm::VM_KILLED))) {
                v->set_breakpoints(std::make_shared<const std::unordered_set<uint64_t>>());
                v->clear_flags(vm::VM_DEBUG_ATTACHED | vm::VM_DEBUG_STOP | vm::VM_STOPPED);
                v->wakeup(false);
            }
        } else {
            detach_vm(pid);
        }
    }
    {
        std::lock_guard<std::mutex> lk(fork_events_mutex_);
        fork_events_.clear();
    }
    // 清残留 syscall 待上报事件（会话结束，pid 1 即将脱离调试态不再被 trace）。
    {
        std::lock_guard<std::mutex> lk(syscall_events_mutex_);
        pending_syscall_events_.clear();
    }
}

// all-stop：continue/vCont 时唤醒所有被 VM_STOPPED 阻塞的 vm（放行它们）。
// 同时清残留的 VM_DEBUG_STOP：all-stop 时 stop_all_vms 给阻塞在 host syscall 的 vm
// 置过 VM_DEBUG_STOP，若该 vm 一直没回解释器（如卡在 waitpid），flag 会残留；放行时不清，
// 它下回到解释器会立刻又停。故 continue 时一并清 VM_DEBUG_STOP，让 vm 真正放行。
void GdbServer::continue_all_vms() {
    auto pids = list_tasks();
    for(uint64_t pid : pids) {
        auto v = find_task(pid);
        if(!v) continue;
        if(!(v->get_flags() & vm::VM_DEBUG_ATTACHED)) continue;  // 已 detach 的不管
        v->clear_flags(vm::VM_STOPPED | vm::VM_DEBUG_STOP);
        v->wakeup(false);
    }
    // 清残留的 syscall 待上报事件：all-stop 下 wait_any_stopped 只上报一个命中 vm
    // （try_send_syscall_stop 已消费并 erase 它的事件），其余同时停下的 vm 在此被放行，
    // 其回调（debug_park）随之返回、do_syscall 继续——它们记下的 pending 事件若不清，
    // 会在该 vm 下次因任何原因停下时被 try_send_syscall_stop 误当成 syscall 停上报，
    // 掩盖真实的断点/退出停止。故 continue 时一次性清空（命中 vm 的事件已消费，安全）。
    {
        std::lock_guard<std::mutex> lk(syscall_events_mutex_);
        pending_syscall_events_.clear();
    }
}

// all-stop：让所有仍在运行（未停止/未退出）的 vm 停下。
// 任一 vm 命中断点/单步/syscall/异常停下后调用：给其余运行中的 vm 置 VM_DEBUG_STOP，
// 解释器下个 safepoint（flags 非零）即阻塞。但 vm 可能正阻塞在 host syscall
// （poll/read/futex/wait）里不回解释器，故额外 host_signal（pthread_kill SIGUSR1）：
// SIGUSR1 是空 handler 且不带 SA_RESTART（main.cpp 设置），宿主阻塞 syscall 返回 EINTR，
// 回到解释器后 VM_DEBUG_STOP 被检查到而停下。已停（VM_DEBUG_STOP/VM_STOPPED）/已退出的 vm 跳过。
void GdbServer::stop_all_vms() {
    auto pids = list_tasks();
    for(uint64_t pid : pids) {
        auto v = find_task(pid);
        if(!v) continue;
        uint32_t f = v->get_flags();
        if(!(f & vm::VM_DEBUG_ATTACHED)) continue;  // 已 detach 的不管
        if(f & (vm::VM_DEBUG_STOP | vm::VM_STOPPED | vm::VM_EXITED | vm::VM_KILLED)) continue;
        v->set_flags(vm::VM_DEBUG_STOP);
        v->wakeup(false);   // 唤醒可能阻塞在 VM_BLOCKED 的 vm
        v->sys()->host_signal(v.get(), 0);  // EINTR 阻塞在 host syscall 的 vm
    }
}

// 清除所有 vm 的调试态。detach / GDB 断开连接 / vm 退出 时调用：
//   - VM_DEBUG_ATTACHED/VM_DEBUG_STOP：JIT 恢复、step() 不再每步查断点
//   - 软断点集合：detach 后无人消费，残留会让 vm 跑到该 pc 永久卡在 safepoint
//   - VM_STOPPED + wakeup：把卡在 safepoint wait_cv 上的 vm 放行
// 清完后进程脱离调试器，用正常 JIT 速度继续运行。
void GdbServer::detach_all_vms() {
    auto pids = list_tasks();
    for(uint64_t pid : pids) {
        detach_vm(pid);
    }
    // 清空待上报 fork 事件表：会话结束，残留条目不再有意义。下次 qSupported 协商了
    // fork-events+ 时 on_create 会重新写入。
    {
        std::lock_guard<std::mutex> lk(fork_events_mutex_);
        fork_events_.clear();
    }
}

// 清除单个 vm 的调试态。D;pid（detach 某进程）用：fork 后 GDB 决定 detach 非跟随方时，
// 该进程脱离调试器恢复 JIT 全速自由运行。detach 后从 tasks_ 移除（不再跟踪）。
void GdbServer::detach_vm(uint64_t pid) {
    auto v = find_task(pid);
    if(!v) return;
    bool exited = (v->get_flags() & (vm::VM_EXITED | vm::VM_KILLED));
    // 已退出或存活都要从 tasks_ 移除（detached 后不再跟踪）。存活 vm 还需清调试态让其
    // 恢复 JIT 自由运行；已退出的只需移除（vm 对象随后析构）。
    unregister_task(pid);
    // 已退出 vm 的待上报 fork 事件也要清，否则 fork_events_ 里残留孤儿条目。
    {
        std::lock_guard<std::mutex> lk(fork_events_mutex_);
        fork_events_.erase(pid);
    }
    // 同理清该 pid 的待上报 syscall 事件。
    {
        std::lock_guard<std::mutex> lk(syscall_events_mutex_);
        pending_syscall_events_.erase(pid);
    }
    if(exited) return;
    v->set_breakpoints(std::make_shared<const std::unordered_set<uint64_t>>());
    v->clear_flags(vm::VM_DEBUG_ATTACHED | vm::VM_DEBUG_STOP | vm::VM_STOPPED);
    v->wakeup(false);
}

// vm 派生（fork / CLONE_THREAD 线程创建）通知回调。由父 vm 的 notify_create 在 do_clone
// 内同步调用（父 vm 线程、do_clone 栈上）。thread 和 process 走同一套处理，仅 fork 事件
// 上报按 is_thread 分叉。
//
// 父未被 trace（VM_DEBUG_ATTACHED）时直接返回——非调试态 vm 派生的子不应被纳入，这也
// 覆盖了"回调被继承给子但子的某个派生方父链上某层已 detach"的情形。
void GdbServer::on_create_vm(vm* parent, vm* child, bool is_thread) {
    if(!(parent->get_flags() & vm::VM_DEBUG_ATTACHED)) return;

    // 子也置 VM_DEBUG_ATTACHED：禁 JIT、解释器每步查断点（否则子在 JIT 下跑，断点/单步失效）。
    child->set_flags(vm::VM_DEBUG_ATTACHED);
    // 继承父当前断点集快照（派生那一刻的断点；之后各自独立增删）。
    child->set_breakpoints(parent->get_breakpoints());
    // 子一启动就停在首条指令前（VM_DEBUG_STOP），对齐 attach 时主 vm 的处理（start() 置
    // VM_DEBUG_STOP，GDB 连接/continue 后放行）。all-stop 正确性要求：派生出的子必须立即
    // 停下纳入协调，否则它会在父命中断点时自由跑完，破坏 all-stop。continue_all_vms 会
    // 放行它；vCont 单进程 continue 时，wait_any_stopped 的 all_settled 把 VM_DEBUG_STOP
    // 视为就绪，不会死等（见 wait_any_stopped 注释）。
    child->set_flags(vm::VM_DEBUG_STOP);

    //    CLONE_THREAD 线程创建不报 fork 事件（ptrace 用 create: 事件，本 server 暂不报），
    //    线程靠 qfThreadInfo 自动发现。未协商 fork-events+ 时也不停父——父自然地在下个断点
    //    停下，GDB 通过 qfThreadInfo 自动发现子进程。
    if(!is_thread && report_fork_events_) {
        uint64_t parent_pid = parent->sys()->id();
        uint64_t child_pid  = child->sys()->id();
        {
            std::lock_guard<std::mutex> lk(fork_events_mutex_);
            fork_events_[parent_pid] = child_pid;
        }
        parent->set_flags(vm::VM_DEBUG_STOP);  // 让父在 fork 返回后立即停下，供 wait_any_stopped 上报
    }

    // 把子登记到自维护 tracee 表（持 shared_ptr，子退出后仍可读 r(0)/tgid 发退出回复）。
    // child 此刻已被 do_clone 的 make_shared 管理（vm 继承 enable_shared_from_this），
    // shared_from_this() 安全；child_sys 在 notify_create 前已建好（pid 已分配）。
    register_task(child->sys()->id(), child->shared_from_this());
}

// 让目标 vm 跑起来（解除调试停止），阻塞等待它再次停下或退出。
// 若当前 pc 命中断点，先 VM_DEBUG_STOP 单步越过，停下后若仍未退出则再放行真 continue。
void GdbServer::resume(vm* v, bool single_step) {
    // 第一阶段：单步越过当前断点（若有）；否则直接放行。
    bool need_step_over = (!single_step) && v->has_breakpoint(v->pc());
    v->clear_flags(vm::VM_DEBUG_STOP | vm::VM_STOPPED);
    if(single_step || need_step_over) {
        v->set_flags(vm::VM_DEBUG_STOP);
        v->wakeup(false);
        wait_stopped(v);
        if(is_vm_exited(v)) return;
    }
    // 第二阶段：单步请求到此为止（已停）；continue 请求（含越过断点后）放行真继续，
    // 并阻塞等待 vm 再次停下（断点命中）或退出。
    if(single_step) return;
    v->clear_flags(vm::VM_DEBUG_STOP | vm::VM_STOPPED);
    v->wakeup(false);
    wait_stopped(v);
}

// 'c' 专用 continue：越过断点（若命中）后放行，不阻塞等待下次停下。
// 下次的「等任一 vm 命中」由调用方走 wait_any_stopped（多进程 all-stop 协调）。
void GdbServer::resume_continue(vm* v) {
    // 若 pc 命中断点，先单步越过（阻塞到单步完成）
    if(v->has_breakpoint(v->pc())) {
        v->set_flags(vm::VM_DEBUG_STOP);
        v->clear_flags(vm::VM_STOPPED);
        v->wakeup(false);
        wait_stopped(v);
        if(is_vm_exited(v)) return;
    }
    // 放行真继续（不 wait_stopped，交给调用方的 wait_any_stopped）
    v->clear_flags(vm::VM_STOPPED | vm::VM_DEBUG_STOP);
    v->wakeup(false);
}

// 阻塞等待 vm 进入 VM_STOPPED/VM_EXITED/VM_KILLED。
// 等待期间并发窥探 client socket：GDB 在 continue/step 期间发的 async Ctrl-C
// （裸 0x03 字节，不带 $...# 框）到达时，置 VM_DEBUG_STOP + wakeup，让 vm 在下个
// 解释器步/safepoint 停下。
//
// vm 可能正阻塞在某个系统调用里（poll/read/futex/wait 等，直接阻塞在宿主 syscall），
// 此时它不回解释器步，光置 flag 不会被检查到。故额外 pthread_kill(vm 线程, SIGUSR1)：
// SIGUSR1 是空 handler 且不带 SA_RESTART（main.cpp 设置），宿主阻塞 syscall 返回 EINTR，
// syscall 返回 EINTR 回到解释器步，VM_DEBUG_STOP 即被检查到而停下。否则 Ctrl-C 对
// 阻塞中的 busybox（卡在 poll 等输入）完全无效。
void GdbServer::wait_stopped(vm* v) {
    for(;;) {
        uint32_t f = v->get_flags();
        if(f & (vm::VM_STOPPED | vm::VM_EXITED | vm::VM_KILLED)) return;
        // 非阻塞窥探 client socket 的 0x03（MSG_PEEK 不消费，下面确认是 03 再 read 掉）
        if(client_fd_ >= 0) {
            char peek;
            ssize_t n = recv(client_fd_, &peek, 1, MSG_PEEK | MSG_DONTWAIT);
            if(n == 1 && peek == '\x03') {
                recv(client_fd_, &peek, 1, MSG_DONTWAIT);  // 消费掉 0x03
                v->set_flags(vm::VM_DEBUG_STOP);
                v->sys()->host_signal(v, 0);
                continue;  // 等 vm 响应 VM_DEBUG_STOP 停下（置 VM_STOPPED）
            }
        }
        struct timespec ts{0, 2000000};  // 2ms
        nanosleep(&ts, nullptr);
    }
}

// 向 GDB 报告 vm 退出（W 包，只发一次）。
void GdbServer::send_exit_reply(vm* v) {
    if(exit_notified_) return;
    exit_notified_ = true;
    unsigned long code = (unsigned long)(v->r(0) & 0xFF);
    char buf[64];
    // multiprocess 下 W 包带 ;process:<pid>（pPID.TID 的 PID 段）
    if(multiprocess_) {
        std::snprintf(buf, sizeof(buf), "W%02lx;process:%lx",
                      code, (unsigned long)vm_tgid(v));
    } else {
        std::snprintf(buf, sizeof(buf), "W%02lx", code);
    }
    send_packet(buf);
    // 上报退出后从 tracee 表移除（释放 shared_ptr 引用）。vm 对象若再无其它引用即析构。
    // 对齐 ptrace：tracer 上报 tracee 退出后即释放 task_struct 引用。
    unregister_task(v->sys()->id());
}

// 构造并发送停止回复：T<sig> + thread:<tid>（multiprocess 用 pPID.TID）。
// fork_child 非 0 时改发 fork 事件：T<sig>fork:<child_ptid>;thread:<tid>;
// （GDB 据此应用 follow-fork-mode / detach-on-fork）。
//
// 关键：发送 stop reply 时把 current_thread_ 设为命中的 vm 的 pid。这模拟了 native
// gdbserver 的行为——stop reply 隐式地把 server 端的 "general thread"（后续无 Hg 的
// g/G/p/P 包操作的目标）设为报告的线程。若不更新，GDB 在多 inferior 场景下 stop 后
// 直接发 g 包（不带 Hg）会读到旧 current_thread_ 对应的 vm 寄存器（如 detach-on-fork
// off 时 fork 事件后 gdb 把焦点切到子，断点命中却发生在父 → g 读到子的寄存器）。
void GdbServer::send_stop_reply(vm* v, int sig, uint64_t fork_child) {
    current_thread_ = v->sys()->id();
    char buf[80];
    std::snprintf(buf, sizeof(buf), "T%02x", (unsigned)(sig & 0xFF));
    std::string pkt = buf;
    if(fork_child != 0) {
        pkt += "fork:" + encode_tid(fork_child) + ";";
    }
    pkt += "thread:" + encode_tid(v->sys()->id()) + ";";
    send_packet(pkt);
}

// 构造并发送 syscall 停止回复：T05syscall_entry/return:<hex-sysno>;thread:<tid>;。
// sysno 为 BPF_CALL_TO_ID(call)（bpf 枚举值，%x 小写变长十六进制）。同 send_stop_reply，
// 发送时把 current_thread_ 设为命中的 vm 的 pid（隐式 general thread）。
void GdbServer::send_syscall_stop_reply(vm* v, uint32_t sysno, bool is_entry) {
    current_thread_ = v->sys()->id();
    char snobuf[32];
    std::snprintf(snobuf, sizeof(snobuf), "%x", (unsigned)sysno);
    std::string reason = is_entry ? "syscall_entry:" : "syscall_return:";
    send_packet("T05" + reason + snobuf + ";thread:" + encode_tid(v->sys()->id()) + ";");
}

// 查 pending_syscall_events_ 是否有 pid 的待上报 syscall 事件。有则发 syscall 停止回复
// 并 erase（一次性消费），返回 true（已发）。无则返回 false（调用方发普通断点/fork回复）。
// 被 continue/step/vCont 在 wait_any_stopped 命中后调用：先 try_send_syscall_stop，
// 失败再 send_stop_reply/send_exit_reply，这样 syscall 停与断点/fork 停共用同一 all-stop
// 协调路径（wait_any_stopped 统一检测 VM_STOPPED 已停位），仅停止回复内容不同。
bool GdbServer::try_send_syscall_stop(vm* v) {
    uint64_t pid = v->sys()->id();
    uint32_t sysno;
    bool is_entry;
    {
        std::lock_guard<std::mutex> lk(syscall_events_mutex_);
        auto it = pending_syscall_events_.find(pid);
        if(it == pending_syscall_events_.end()) return false;
        sysno = it->second.first;
        is_entry = it->second.second;
        pending_syscall_events_.erase(it);  // 一次性消费
    }
    // 锁外发送：send_packet 可能阻塞，不应持锁
    send_syscall_stop_reply(v, sysno, is_entry);
    return true;
}

// 构建 syscall 钩子回调。在 vm 线程内同步执行（do_syscall 调用）：查 catch 配置，
// 命中则记待上报事件 + debug_park 阻塞（请求位 VM_DEBUG_STOP → 已停位 VM_STOPPED）。
// 回调阻塞即 vm 停，由 GDB 线程 wait_any_stopped 扫到 VM_STOPPED 后调 try_send_syscall_stop
// 发停止回复、continue_all_vms 清 VM_STOPPED+wakeup 放行后回调返回、do_syscall 继续。
std::function<bool(vm*, uint32_t)> GdbServer::make_syscall_cb(bool is_entry) {
    return [this, is_entry](vm* v, uint32_t call) -> bool {
        auto cfg = syscall_catch_.load();  // 原子取不可变快照
        if(!cfg->enabled) return false;                          // 未启用：直接返回，vm 继续
        uint32_t sysno = BPF_CALL_TO_ID(call);
        // 空集=catch 全部；非空=仅 catch 列表中的
        bool hit = cfg->sysnos->empty() || cfg->sysnos->count(sysno) != 0;
        if(!hit) return false;                                   // 不在列表：直接返回
        // 记待上报事件（供 wait_any_stopped 发 syscall_entry/return 回复）
        {
            std::lock_guard<std::mutex> lk(syscall_events_mutex_);
            pending_syscall_events_[v->sys()->id()] = {sysno, is_entry};
        }
        return true;
    };
}

// 构建完整 DebugHooks（create + syscall entry/return）并应用到 main_vm_ 及所有 tasks_。
// create 回调在 fork 时继承给子（notify_create 内 child->set_debug_hooks(parent 快照)），
// 故子进程的 syscall 也会被 catch（与断点继承一致）。sys 未初始化的 main_vm_（start 前）
// 也装上——do_syscall 仅在 VM_DEBUG_ATTACHED 时才调钩子，attach 前不触发。
void GdbServer::install_debug_hooks() {
    auto hooks = std::make_shared<DebugHooks>();
    hooks->create = [this](vm* p, vm* c, bool t){ this->on_create_vm(p, c, t); };
    hooks->syscall_entry = make_syscall_cb(true);
    hooks->syscall_return = make_syscall_cb(false);
    main_vm_->set_debug_hooks(hooks);
    for(uint64_t pid : list_tasks()) {
        if(auto v = find_task(pid)) v->set_debug_hooks(hooks);
    }
}

// all-stop 阻塞点：等待任一 vm 停下/退出，停下后立即让其余 vm 也停（真 all-stop）。
// 流程：
//   1. 轮询所有 vm，任一进入调试停止（VM_DEBUG_STOP）/VM_STOPPED/退出即认为「命中」。
//   2. 命中后调 stop_all_vms() 让其余运行中的 vm 也停下。
//   3. 等所有 vm 都进入停止态（all-stop 收敛）。
//   4. out_stopped_tid 写入第一个命中的 tid。
// 期间并发窥探 client socket 的 async Ctrl-C (0x03)。
void GdbServer::wait_any_stopped(uint64_t& out_stopped_tid, uint64_t preferred_pid,
                                 const std::vector<uint64_t>& watch_pids,
                                 uint64_t* out_fork_child) {
    out_stopped_tid = 0;
    if(out_fork_child) *out_fork_child = 0;
    bool propagated = false;   // 是否已对其余 vm 下过 stop
    // 快照本次「正在运行」的 watch 目标（调用方刚释放的 vm）。我们只等这些 vm 之一停下，
    // 避免被那些本来就已 stopped 的 vm 立即满足（vCont 部分线程继续、其余保持 stopped）。
    // watch_pids 为空时退化为「观察所有 attached vm」。注意：仅观察 VM_DEBUG_ATTACHED 的 vm——
    // 已被 GDB detach 的进程（如 detach-on-fork=on 时 detach 的子进程）的停止/退出绝不能上报，
    // 否则 GDB 对已移除的 inferior 取状态会 internal-error。
    std::set<uint64_t> running_watch;
    if(watch_pids.empty()) {
        auto all = list_tasks();
        for(uint64_t pid : all) {
            if(auto v = find_task(pid)) {
                if(v->get_flags() & vm::VM_DEBUG_ATTACHED) running_watch.insert(pid);
            }
        }
    } else {
        for(uint64_t pid : watch_pids) running_watch.insert(pid);
    }
    for(;;) {
        auto pids = list_tasks();
        // 找首个「本次释放后新停下」的 vm。优先级：
        //   1. preferred_pid（若已停）
        //   2. 任一调试停止（断点/单步/syscall catch 命中，已由 debug_park 转 VM_STOPPED）
        //      —— 优先于退出，避免子进程退出把父的断点命中吞掉（父命中更可操作，子退出可下一轮报）
        //   3. 任一 VM_EXITED/VM_KILLED（退出）
        uint64_t hit_pid = 0;
        std::shared_ptr<vm> hit_vm;
        auto is_settled = [](uint32_t f) {
            return (f & (vm::VM_STOPPED | vm::VM_EXITED | vm::VM_KILLED)) != 0;
        };
        auto is_bp_hit = [](uint32_t f) {
            return (f & vm::VM_STOPPED) != 0;  // 已停（断点/单步/syscall catch / POSIX SIGSTOP）
        };
        auto is_exited = [](uint32_t f) {
            return (f & (vm::VM_EXITED | vm::VM_KILLED)) != 0;
        };
        if(preferred_pid != 0 && running_watch.count(preferred_pid)) {
            if(auto pv = find_task(preferred_pid)) {
                if(is_settled(pv->get_flags())) {
                    hit_pid = preferred_pid;
                    hit_vm = pv;
                }
            }
        }
        if(!hit_vm) {
            // 第一轮：找已停命中（VM_STOPPED，非退出）
            for(uint64_t pid : pids) {
                if(!running_watch.count(pid)) continue;
                auto v = find_task(pid);
                if(!v) continue;
                if(is_bp_hit(v->get_flags())) { hit_pid = pid; hit_vm = v; break; }
            }
        }
        if(!hit_vm) {
            // 第二轮：找退出（VM_EXITED/VM_KILLED）。第一轮已扫过所有 VM_STOPPED 未中，
            // 故此处只关心退出态——用 is_exited 显式判定，与注释一致。
            for(uint64_t pid : pids) {
                if(!running_watch.count(pid)) continue;
                auto v = find_task(pid);
                if(!v) continue;
                if(is_exited(v->get_flags())) { hit_pid = pid; hit_vm = v; break; }
            }
        }
        if(hit_vm) {
            if(!propagated) {
                // 首个命中：让其余 vm 也停下（all-stop 传播）
                stop_all_vms();
                propagated = true;
            }
            // 等 all-stop 收敛。一个 vm 视为「已就绪」当它：
            //   - 已停（VM_STOPPED/退出/被 kill），或
            //   - 已被下达停止请求（VM_DEBUG_STOP）——即便它还阻塞在不可中断的 host syscall
            //     （如 waitpid 轮询 tg->cv，SIGUSR1 的 EINTR 被 musl 自动重启吞掉），它已「被
            //     告知停」，下回到解释器即会 park。不等它能避免死锁：父进程在 waitpid 阻塞等
            //     子进程，子进程在断点停被冻住，二者互相等待——此时父的 VM_DEBUG_STOP 已置，
            //     视为就绪即可向 GDB 回报，后续 continue 释放子进程后父 waitpid 自然返回。
            bool all_settled = true;
            for(uint64_t pid : pids) {
                auto v = find_task(pid);
                if(!v) continue;
                // 已 detach 的 vm 不参与 all-stop 收敛判定（它不受调试器控制）
                if(!(v->get_flags() & vm::VM_DEBUG_ATTACHED)) continue;
                uint32_t ff = v->get_flags();
                if(!(ff & (vm::VM_STOPPED | vm::VM_EXITED | vm::VM_KILLED | vm::VM_DEBUG_STOP))) {
                    all_settled = false;
                    break;
                }
            }
            if(all_settled) {
                out_stopped_tid = hit_pid;
                // 若命中的 vm 有待上报的 fork 事件（on_create 在真 fork 且协商 fork-events+ 时
                // 写入 fork_events_ 表），把子的 pid 带回给调用方发 T05fork:<child> 停止回复。
                // 一次性：命中即 erase 该条目。未命中（表无此 pid）则 *out_fork_child 保持 0，
                // 调用方发普通 T05thread: 停止回复。表里其它 vm 的 fork 事件保留——它们是合法的
                // 待上报事件（该 vm 下次被选为 hit_vm 时上报），单 all-stop 周期内多 vm 同时 fork
                // 时未中选的 fork 事件不会丢失（与 ptrace 语义一致）。
                if(out_fork_child && report_fork_events_) {
                    std::lock_guard<std::mutex> lk(fork_events_mutex_);
                    auto it = fork_events_.find(hit_pid);
                    if(it != fork_events_.end()) {
                        *out_fork_child = it->second;
                        fork_events_.erase(it);  // 一次性消费
                    }
                }
                return;
            }
            // 否则继续轮询等其他 vm 收敛
        }
        // 异步 Ctrl-C：GDB 在 continue/step 期间发的 0x03（不带 $...# 框）
        if(client_fd_ >= 0) {
            char peek;
            ssize_t n = recv(client_fd_, &peek, 1, MSG_PEEK | MSG_DONTWAIT);
            if(n == 1 && peek == '\x03') {
                recv(client_fd_, &peek, 1, MSG_DONTWAIT);  // 消费掉 0x03
                // 给所有运行中的 vm 置 VM_DEBUG_STOP + host_signal
                stop_all_vms();
                propagated = true;
            }
        }
        struct timespec ts{0, 2000000};  // 2ms
        nanosleep(&ts, nullptr);
    }
}

// vCont 处理。包形如 vCont[;action[:tid]]...，每个 action：
//   c / C<hexsig>   继续该 tid（C 带信号，bpfvm 无 ptrace-stop 信号投递，按 c 处理）
//   s / S<hexsig>   单步该 tid（S 带信号，按 s 处理）
//   t               保持该 tid 停止（不动作）
//   :tid            可选，指定该 action 的目标线程；省略则代表「其余所有线程」(default action)
// all-stop 语义：按 action 优先级（显式单线程 > 进程作用域 pPID.-1 > 全局 default）
// 决定每个 attached vm 的动作（c/s/t/无），再统一越步+放行。至少要有一个 action。
// 完成后 self_replied_=true，发送停止/退出回复。
std::string GdbServer::handle_vcont(const std::string& pkt) {
    self_replied_ = true;
    // 切分 ';'：首段是 "vCont"，其后每段一个 action。
    // 例：vCont;c:1;s:2  → ["vCont", "c:1", "s:2"]
    std::vector<std::string> actions;
    {
        size_t start = 0;
        for(;;) {
            auto semi = pkt.find(';', start);
            if(semi == std::string::npos) {
                actions.push_back(pkt.substr(start));
                break;
            }
            actions.push_back(pkt.substr(start, semi - start));
            start = semi + 1;
        }
    }
    if(actions.size() < 2) {
        // vCont 无 action（仅 "vCont"）：按 continue 处理
        actions.push_back("c");
    }

    struct ParsedAction {
        char act;          // 'c' / 's' / 't'
        uint64_t tid;      // 目标线程 pid（has_tid=true 时有效）
        bool has_tid;      // 是否作用于单个线程
        uint64_t scope_pid;  // 0=全局；>0=仅该 pid 的线程（pPID.-1 形式）
    };
    std::vector<ParsedAction> parsed;
    char default_act = 'c';   // 无 :tid 的 action 决定 default（取最后一个）
    bool has_default = false; // 是否存在无 :tid 的 action（全局 default）
    uint64_t step_tid = 0;    // 单步的目标 tid（用于 preferred）

    for(size_t i = 1; i < actions.size(); i++) {
        const std::string& a = actions[i];
        if(a.empty()) continue;
        char act = a[0];
        // 归一化：C<c> → c（带信号继续），S<c> → s（带信号单步）。信号当前不投递。
        char norm;
        if(act == 'c' || act == 'C') norm = 'c';
        else if(act == 's' || act == 'S') norm = 's';
        else if(act == 't') norm = 't';
        else continue;  // 未知 action 跳过

        // 解析可选 :tid。tid 形如 pid / pPID.TID / pPID.-1 / pPID.0 / -1 / 0。
        //   pPID.TID    → 单线程（has_tid=true, tid=TID）
        //   pPID.-1/0   → 该 PID 的所有线程（scope_pid=PID，has_tid=false）
        //   -1/0/p-1.-1 → 所有线程（全局 default，has_tid=false, scope_pid=0）
        auto colon = a.find(':');
        uint64_t tid = 0;
        bool has_tid = false;
        uint64_t scope_pid = 0;
        if(colon != std::string::npos) {
            std::string tidstr = a.substr(colon + 1);
            if(tidstr.size() > 1 && tidstr[0] == 'p') {
                // pPID.TID / pPID.-1
                std::string rest = tidstr.substr(1);
                auto dot = rest.find('.');
                std::string pid_str = (dot == std::string::npos) ? rest : rest.substr(0, dot);
                std::string tid_str = (dot == std::string::npos) ? "" : rest.substr(dot + 1);
                uint64_t pid_val = std::strtoull(pid_str.c_str(), nullptr, 16);
                if(tid_str == "-1" || tid_str == "0" || tid_str.empty()) {
                    scope_pid = pid_val;  // 该 PID 所有线程
                } else {
                    tid = std::strtoull(tid_str.c_str(), nullptr, 16);
                    has_tid = true;
                }
            } else if(tidstr == "-1" || tidstr == "0") {
                // 全局 default（所有线程）
            } else {
                tid = std::strtoull(tidstr.c_str(), nullptr, 16);
                if(tid != 0) has_tid = true;
            }
        }
        if(!has_tid && scope_pid == 0) {
            default_act = norm;
            has_default = true;
        }
        if(norm == 's' && has_tid) step_tid = tid;
        parsed.push_back({norm, tid, has_tid, scope_pid});
    }

    // 三阶段执行：
    //   第一遍：对无显式 :tid 的 vm 按 default action 放行/保持（仅有 default 时）。
    //   阶段 A：对带 :tid 的 c 动作，若 pc 命中断点先单步越过（串行，每步很快）。
    //   阶段 B：对带 :tid 的 vm 真正放行（c）/单步标记（s）。
    // 最后 wait_any_stopped 仅观察「本次释放」的 vm 停下，避免被本来就 stopped 的 vm 满足。
    auto pids = list_tasks();

    // 收集有显式 action 的 tid 集合
    std::set<uint64_t> explicit_tids;
    for(auto& pa : parsed) if(pa.has_tid) explicit_tids.insert(pa.tid);

    // 所有阶段都跳过非 VM_DEBUG_ATTACHED 的 vm——已被 GDB detach（如 detach-on-fork=on
    // 时 detach 的子进程）的 vm 不再受调试器控制，其停止/退出不应上报给 GDB（否则 GDB
    // 对已移除的 inferior 取状态会 internal-error）。
    auto is_attached = [](vm* v) { return (v->get_flags() & vm::VM_DEBUG_ATTACHED) != 0; };

    // ── 第一阶段：决定每个 attached vm 的最终动作（'c'/'s'/'t'，'\0'=不动）。
    // 优先级（与 ptrace/GDB 语义一致）：显式单线程 action > 进程作用域 action > 全局 default。
    //   vCont;c           → 所有线程 'c'（全局 default）
    //   vCont;c:p1.-1     → inferior 1 的线程 'c'（进程作用域）
    //   vCont;c:p1.1      → 线程 1 'c'（显式单线程）
    //   vCont;c:p1.-1;t:p1.1 → 线程 1 't'，inferior 1 其余线程 'c'（显式优先于作用域）
    // '\0'（无动作）的 vm 保持当前 stopped 态不动。
    std::unordered_map<uint64_t, char> action_of;
    auto set_action = [&](uint64_t pid, char act) {
        auto [it, ins] = action_of.try_emplace(pid, act);
        if(!ins) it->second = act;  // 后写覆盖（实际上优先级已在下面的循环顺序里保证）
    };
    // 先全局 default（最低优先级，仅当 has_default）
    if(has_default) {
        for(uint64_t pid : pids) {
            auto v = find_task(pid);
            if(v && !is_vm_exited(v.get()) && is_attached(v.get())) set_action(pid, default_act);
        }
    }
    // 再进程作用域 default（pPID.-1）：覆盖该 PID 的动作。跳过有显式单线程 action 的 pid
    // （显式优先）——但显式 action 在下一轮才写入，故此处用 explicit_tids 预判跳过。
    for(auto& pa : parsed) {
        if(pa.has_tid || pa.scope_pid == 0) continue;
        if(explicit_tids.count(pa.scope_pid)) continue;  // 该 pid 有显式单线程 action，留给下一轮
        set_action(pa.scope_pid, pa.act);
    }
    // 最后显式单线程 action（:tid）：最高优先级，直接覆盖。
    // 注：step_tid 已在解析循环（norm=='s' && has_tid）里记录，此处不重复。
    for(auto& pa : parsed) {
        if(!pa.has_tid) continue;
        set_action(pa.tid, pa.act);
    }

    // ── 第二阶段：对所有 c 动作且 pc 命中断点的 vm 串行 step-over。
    // 关键正确性：continue 放行前若不越过当前 pc 的断点，vm 被唤醒后第一条 step 立刻又命中
    // 同一断点 → 死循环（旧实现仅在显式单线程 c action 路径做 step-over，default/scope 路径
    // 漏做，导致 GDB 常用的 vCont;c:pPID.-1 卡死）。step-over 用 VM_DEBUG_STOP 单步一条，
    // 阻塞到单步完成（wait_stopped）。s/t 动作不需要越步（单步本就停在下一条，t 不动）。
    for(uint64_t pid : pids) {
        auto v = find_task(pid);
        if(!v || is_vm_exited(v.get()) || !is_attached(v.get())) continue;
        auto it = action_of.find(pid);
        if(it == action_of.end() || it->second != 'c') continue;
        if(v->has_breakpoint(v->pc())) {
            v->set_flags(vm::VM_DEBUG_STOP);
            v->clear_flags(vm::VM_STOPPED);
            v->wakeup(false);
            wait_stopped(v.get());  // 阻塞到单步越过完成（vm 再次停在 VM_STOPPED）
            if(is_vm_exited(v.get())) action_of.erase(it);  // 越步中退出，不再放行
        }
    }

    // ── 第三阶段：按决定的动作统一放行。
    std::vector<uint64_t> released;
    for(uint64_t pid : pids) {
        auto v = find_task(pid);
        if(!v || is_vm_exited(v.get()) || !is_attached(v.get())) continue;
        auto it = action_of.find(pid);
        if(it == action_of.end()) continue;
        char act = it->second;
        if(act == 't') continue;  // 保持 stopped
        if(act == 's') v->set_flags(vm::VM_DEBUG_STOP);
        else           v->clear_flags(vm::VM_DEBUG_STOP);
        v->clear_flags(vm::VM_STOPPED);
        v->wakeup(false);
        released.push_back(pid);
    }

    // 阻塞等待任一「本次释放的」vm 停下（断点命中/单步完成/异常/fork），all-stop 传播到其余 vm
    uint64_t hit_tid = 0, fork_child = 0;
    wait_any_stopped(hit_tid, step_tid, released, &fork_child);
    auto hit_vm = find_task(hit_tid);
    if(!hit_vm || is_vm_exited(hit_vm.get())) {
        auto cur = current_vm();
        send_exit_reply(hit_vm ? hit_vm.get() : (cur ? cur.get() : main_vm_.get()));
    } else if(!try_send_syscall_stop(hit_vm.get())) {
        // 非 syscall 停：发普通断点/fork 停止回复（syscall 事件已在 try 内发过）
        send_stop_reply(hit_vm.get(), 5, fork_child);  // SIGTRAP（fork_child!=0 时为 fork 事件）
    }
    return "";
}

// ── server 主循环 ────────────────────────────────────────────────────────
void GdbServer::server_loop() {
    // 退出守卫：任何 return 路径（含 socket/bind/listen/accept 失败）都置 running_=false
    // 并通知 stop() 可立即 join，避免它空等满 6 秒超时。
    struct LoopExitGuard {
        GdbServer* s;
        ~LoopExitGuard() {
            s->running_ = false;
            s->loop_done_.store(true, std::memory_order_release);
        }
    } guard{this};

    // 阻塞 SIGPIPE（client 断开时 send 不触发进程终止）
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &mask, nullptr);

    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_fd_ < 0) return;
    int yes = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 仅本地，安全
    addr.sin_port = htons(port_);
    if(bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::fprintf(stderr, "[gdb] bind port %u failed: %s\n", port_, std::strerror(errno));
        close(listen_fd_);
        listen_fd_ = -1;
        return;
    }
    if(listen(listen_fd_, 1) < 0) {
        close(listen_fd_);
        listen_fd_ = -1;
        return;
    }
    std::fprintf(stderr, "[gdb] listening on 127.0.0.1:%u (entry=0x%lx)\n",
                 port_, (unsigned long)info_.entry);

    // 外层 accept 循环：每来一个 GDB 连接就是一次会话，会话结束（断开 / detach all）后 detach
    // 并回 accept 等下次连接——支持重复 attach。单线程 accept 串行化保证同时只服务一个会话
    // （会话期间不调 accept，第二个连接在 listen backlog=1 里排队）。主 vm 退出后不再接会话。
    while(running_ && !is_vm_exited(main_vm_.get())) {
        client_fd_ = accept(listen_fd_, nullptr, nullptr);
        if(client_fd_ < 0) {
            // accept 失败：被 stop() 关 listen_fd 打断（running_ 已 false），或临时错误。
            // running_/vm 退出则整体退出，否则继续等下次连接。
            if(!running_ || is_vm_exited(main_vm_.get())) break;
            continue;
        }
        // 新会话：复位 per-connection 协商态（multiprocess/fork-events 等不跨会话保留）。
        reset_session_state();
        if(stop_at_start_) {
            // --stop 模式：start() 已把主 vm 冻结在入口（VM_DEBUG_ATTACHED|VM_DEBUG_STOP）。
            // 这里对 tasks_ 里所有 vm 补 VM_DEBUG_ATTACHED：覆盖 listen 期间 fork/clone 出的子 vm
            // （on_create_vm 已登记到 tasks_）——它们同样要禁 JIT 才能被精确断点/单步。
            for(uint64_t pid : list_tasks()) {
                if(auto v = find_task(pid)) v->set_flags(vm::VM_DEBUG_ATTACHED);
            }
        } else {
            // 默认模式：主 vm 此前全速 JIT 跑，现在 attach pid 1 让它停在当前 pc。
            // （连上前 fork 的子不在 tasks_，保持自由运行，对齐 QEMU -gdb 不带 -S 的语义。）
            attach_on_connect();
        }
        // 关闭 Nagle，减少小包延迟
        int one = 1;
        setsockopt(client_fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        // recv 超时：让内层循环周期性醒来检查 running_ 与 vm 退出，避免永久阻塞
        struct timeval tv{0, 200000};  // 0.2s
        setsockopt(client_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // 内层包循环：处理本会话的 RSP 包，直到 GDB 断开 / detach all / stop() / vm 退出。
        while(running_) {
            std::string pkt;
            bool got = recv_packet(pkt);
            if(!got) {
                // recv_packet 返回 false：对端关闭(EOF)/硬错误，或 running_ 被 stop() 置 false。
                // 对端关闭时，若 vm 已退出但还没发 W（例如断点停后用户直接断开），补发一次。
                if(!exit_notified_ && main_vm_ && is_vm_exited(main_vm_.get())) {
                    send_exit_reply(main_vm_.get());
                }
                break;
            }
            if(pkt.empty()) {
                send_packet("");
                continue;
            }
            // handle_packet 返回值：空串=未识别/空回复（需发空包 $#00，GDB 视为"不支持"）；
            // 非空=正常回复。c/s 等已自行 send 的命令会置 self_replied_ 且返回空串——此时跳过。
            self_replied_ = false;
            std::string reply = handle_packet(pkt);
            if(!self_replied_) send_packet(reply);
        }
        // 会话结束：detach 让被 trace 的 vm 恢复全速，但保留 pid 1 在 tasks_ 以便重新 attach。
        end_session();
        if(client_fd_ >= 0) {
            close(client_fd_);
            client_fd_ = -1;
        }
    }
    // server 整体退出（主 vm 已退出 / stop()）：最终 detach，把 pid 1 也从 tasks_ 移除。
    // 与 end_session()/detach_vm() 幂等，重复调无副作用。
    detach_all_vms();
    if(client_fd_ >= 0) {
        close(client_fd_);
        client_fd_ = -1;
    }
}

// ── 包处理 ───────────────────────────────────────────────────────────────
std::string GdbServer::handle_packet(const std::string& pkt) {
    char cmd = pkt[0];
    switch(cmd) {
    case 'q': {
        if(pkt.rfind("qSupported", 0) == 0) {
            // 协商：GDB 发的 qSupported 里若含 multiprocess+ 表示它支持，我们也广告之。
            // 仅在双方都支持时切到 pPID.TID 线程 id 格式（encode_tid/decode_tid 据此切换）。
            if(pkt.find("multiprocess+") != std::string::npos) multiprocess_ = true;
            std::string r = "PacketSize=4096;swbreak+;vContSupported+;QStartNoAckMode+";
            // QCatchSyscalls：广告支持 catch syscall。GDB 据此发 QCatchSyscalls:0/1 配置，
            // 我们在 syscall 钩子命中时发 T05syscall_entry/return:<hex>; 停止回复。无 multiprocess
            // 依赖（单进程也支持 catch syscall），故无条件广告。带 + 后缀对齐 QEMU 实践，
            // GDB 16.3 解析 qSupported 期望带 +/- 的可探测项（裸 token 被判 "unrecognized item"）。
            r += ";QCatchSyscalls+";
            if(multiprocess_) {
                r += ";multiprocess+";
                // fork-events+/vfork-events+：让 GDB 在 fork 时收到 T05fork:<child>，按
                // follow-fork-mode / detach-on-fork 决策（跟父或子、是否 detach 另一个）。
                // 关键：被 GDB detach 的进程（如 detach-on-fork=on 时的非跟随方）后续的
                // 停止/退出绝不通过 qfThreadInfo/wait_any_stopped 上报，否则 GDB 对已移除的
                // inferior 取状态会 internal-error（已在 wait_any_stopped/continue_all_vms/
                // stop_all_vms 中过滤 VM_DEBUG_ATTACHED）。
                if(pkt.find("fork-events+") != std::string::npos) {
                    r += ";fork-events+;vfork-events+";
                    report_fork_events_ = true;
                }
            }
            return r;
        }
        if(pkt == "qAttached") return "1";
        if(pkt.rfind("qfThreadInfo", 0) == 0) {
            // 枚举线程：m<tid>,<tid>,... 随后 qsThreadInfo 回 l 终止。
            // tid 格式由 multiprocess_ 决定（裸 hex 或 pPID.TID）。
            // 仅枚举仍被 GDB 跟踪的 vm（VM_DEBUG_ATTACHED）：fork 后被 detach 的进程
            // 不应再出现，否则 GDB 见到已不存在的 inferior 会 set_current_inferior(NULL) 崩。
            auto pids = list_tasks();
            std::string r = "m";
            bool first = true;
            for(uint64_t pid : pids) {
                auto v = find_task(pid);
                if(!v) continue;
                if(!(v->get_flags() & vm::VM_DEBUG_ATTACHED)) continue;
                if(!first) r += ",";
                r += encode_tid(pid);
                first = false;
            }
            // 无 attached vm 时回 l（空列表结束）——裸 m 是非法格式，GDB 会解析错误。
            return first ? "l" : r;
        }
        if(pkt.rfind("qsThreadInfo", 0) == 0) return "l";
        if(pkt.rfind("qThreadExtraInfo", 0) == 0) return "";
        if(pkt.rfind("qC", 0) == 0) {
            // 返回当前线程 id。current_thread_ 为 0 时回退到 main 线程——绝不能回 QC0，
            // 线程 id 0 是 RSP 特殊值，GDB 会 switch_to_thread(NULL) 触发 assertion。
            uint64_t tid = current_thread_ ? current_thread_ : main_thread_id();
            return "QC" + encode_tid(tid);
        }
        if(pkt.rfind("qOffsets", 0) == 0) {
            // PIE 程序的 .text/.data 运行时基址偏移。GDB 拿到后把符号/DWARF 文件内地址
            // +偏移重定位到运行时地址，否则 PIE 断点命中不了（文件内 main@0xbc728 vs
            // 运行时 0x401ce728）。app_load_base 即主程序加载基址；静态/ET_EXEC 为 0。
            // 注意：qOffsets 值是纯十六进制，不能带 0x 前缀（GDB 报 "Invalid hex digit"）。
            char buf[64];
            std::snprintf(buf, sizeof(buf), "Text=%lx;Data=%lx;Bss=%lx",
                          (unsigned long)info_.app_load_base,
                          (unsigned long)info_.app_load_base,
                          (unsigned long)info_.app_load_base);
            return buf;
        }
        return "";
    }
    case 'Q': {
        if(pkt == "QStartNoAckMode") {
            no_ack_ = true;
            return "OK";
        }
        // QCatchSyscalls:0 禁用 / :1 catch 全部 / :1;<hex>;<hex>;... catch 列表。
        // sysno 为小写变长十六进制。构造新 const SyscallCatchCfg 后原子 store（所有 vm 共用，
        // 回调闭包 load 拿不可变快照）。
        // 注意：钩子已恒挂载（install_debug_hooks），这里只更新 syscall_catch_，回调闭包查它。
        if(pkt.rfind("QCatchSyscalls:", 0) == 0) {
            std::string rest = pkt.substr(strlen("QCatchSyscalls:"));
            auto cfg = std::make_shared<SyscallCatchCfg>();
            if(rest == "0") {
                cfg->enabled = false;  // 禁用（sysnos 保持空集）
            } else if(rest == "1") {
                cfg->enabled = true;   // catch 全部（sysnos 空集=catch全部）
            } else if(rest.size() >= 2 && rest[0] == '1' && rest[1] == ';') {
                // 形如 "1;5;6;e8"：catch 列表（首段恒为 "1"，必须紧跟 ';'）
                cfg->enabled = true;
                auto set = std::make_shared<std::unordered_set<uint32_t>>();
                size_t pos = 2;  // 跳过 "1;"
                for(;;) {
                    size_t semi = rest.find(';', pos);
                    std::string tok = (semi == std::string::npos) ? rest.substr(pos) : rest.substr(pos, semi - pos);
                    if(!tok.empty()) {
                        char* endp = nullptr;
                        unsigned long val = std::strtoul(tok.c_str(), &endp, 16);
                        if(endp == tok.c_str() || *endp != '\0') return "E01";  // 非法 hex
                        set->insert((uint32_t)val);
                    }
                    if(semi == std::string::npos) break;
                    pos = semi + 1;
                }
                cfg->sysnos = set;  // shared_ptr<T> → shared_ptr<const T> 隐式转换
            } else {
                return "E01";  // 格式错误（如 "1abc"）
            }
            syscall_catch_.store(std::move(cfg));  // shared_ptr<T> → shared_ptr<const T>
            return "OK";
        }
        return "";
    }
    case '?': {
        // 报告停止原因。T05 = SIGTRAP（断点/单步/attach），带 thread:<tid> 让 GDB 切到该线程。
        auto v = current_vm();
        if(!v || is_vm_exited(v.get())) {
            unsigned long code = v ? (unsigned long)(v->r(0) & 0xFF) : 0;
            char buf[32];
            std::snprintf(buf, sizeof(buf), "W%02lx", code);
            return buf;
        }
        return "T05thread:" + encode_tid(v->sys()->id()) + ";";
    }
    case 'H': {
        // H<op><thread>：选择后续操作的目标线程。<thread> 形如 pid、pPID.TID、0、-1。
        // '0'/'-1'/'p0.0'/'p-1.-1' 是 RSP 特殊值（任意/所有线程）——必须映射到一个真实 pid，
        // 否则后续 qC 返回 0 会让 GDB switch_to_thread(NULL) 触发 assertion。
        if(pkt.size() < 2) return "E01";
        std::string t = pkt.substr(2);
        uint64_t tid = decode_tid(t);
        if(tid == 0) {
            current_thread_ = main_thread_id();
        } else {
            current_thread_ = tid;
            if(!find_task(current_thread_)) current_thread_ = main_thread_id();
        }
        return "OK";
    }
    case 'g': {
        // 读全部寄存器：r0..r10 + pc 全部 8 字节小端（共 96 字节 = 192 hex）。
        auto v = current_vm();
        if(!v) return "E01";
        std::string r;
        for(int i = 0; i < 11; i++) r += reg_to_hex(v->r(i));          // r0..r10 (8B)
        r += reg_to_hex(v->pc());                                      // pc (8B)
        return r;
    }
    case 'G': {
        // 写全部寄存器：96 字节（192 hex 字符），布局同 g。
        auto v = current_vm();
        if(!v) return "E01";
        std::string h = pkt.substr(1);
        for(int i = 0; i < 11; i++) {
            v->r(i) = hex_to_reg(h.substr(i * 16, 16));
        }
        v->pc() = hex_to_reg(h.substr(11 * 16, 16));
        return "OK";
    }
    case 'p': {
        // p<n> 读单寄存器。索引 0-10=r0-r10，11=pc，全部 8 字节（与 g 包布局一致）。
        auto v = current_vm();
        if(!v) return "E01";
        unsigned long n = std::strtoul(pkt.substr(1).c_str(), nullptr, 16);
        if(n <= 10) return reg_to_hex(v->r((int)n));
        if(n == 11) return reg_to_hex(v->pc());
        return "E01";
    }
    case 'P': {
        // P<n>=<hex> 写单寄存器（尺寸同 p）
        auto v = current_vm();
        if(!v) return "E01";
        auto eq = pkt.find('=');
        if(eq == std::string::npos) return "E02";
        unsigned long n = std::strtoul(pkt.substr(1, eq - 1).c_str(), nullptr, 16);
        std::string h = pkt.substr(eq + 1);
        if(n <= 10) v->r((int)n) = hex_to_reg(h);
        else if(n == 11) v->pc() = hex_to_reg(h);
        return "OK";
    }
    case 'm': {
        // m<addr>,<len> 读内存。跨段时按段切分；单次 mmu 请求会校验 [addr,addr+size)
        // 整段在同一映射内，请求越大越易失败，故先按剩余整段请求，失败则降到逐字节。
        auto v = current_vm();
        if(!v) return "E01";
        auto comma = pkt.find(',');
        if(comma == std::string::npos) return "E02";
        uint64_t addr = std::strtoull(pkt.substr(1, comma - 1).c_str(), nullptr, 16);
        uint64_t len = std::strtoull(pkt.substr(comma + 1).c_str(), nullptr, 16);
        if(len == 0) return "";
        std::string out;
        out.reserve(len * 2);
        uint64_t off = 0;
        while(off < len) {
            size_t want = (size_t)(len - off);
            void* p = v->mmu(addr + off, want);
            size_t step = want;
            if(!p) { p = v->mmu(addr + off, 1); step = 1; }
            if(!p) return "E14";
            out += hex_encode(p, step);
            off += step;
        }
        return out;
    }
    case 'M': {
        // M<addr>,<len>:<hex> 写内存
        auto v = current_vm();
        if(!v) return "E01";
        auto comma = pkt.find(',');
        auto colon = pkt.find(':');
        if(comma == std::string::npos || colon == std::string::npos) return "E02";
        uint64_t addr = std::strtoull(pkt.substr(1, comma - 1).c_str(), nullptr, 16);
        uint64_t len = std::strtoull(pkt.substr(comma + 1, colon - comma - 1).c_str(), nullptr, 16);
        std::string h = pkt.substr(colon + 1);
        if(h.size() < len * 2) return "E03";
        uint64_t off = 0;
        while(off < len) {
            size_t want = (size_t)(len - off);
            void* p = v->mmu_w(addr + off, want);
            size_t step = want;
            if(!p) {
                p = v->mmu_w(addr + off, 1);
                step = 1;
            }
            if(!p) return "E14";
            if(!hex_decode(h.substr(off * 2, step * 2), p, step)) return "E03";
            off += step;
        }
        return "OK";
    }
    case 'c': {
        // continue [addr]（addr 忽略，从当前 pc 继续）
        auto v = current_vm();
        if(!v) return "E01";
        self_replied_ = true;
        if(is_vm_exited(v.get())) {
            send_exit_reply(v.get());
            return "";
        }
        // all-stop：当前 vm 先越过断点并放行（resume_continue 读 v->pc()/设 flags，必须在
        // v 被放行前完成——否则 v 解释器线程并发写 pc_ 构成数据竞争），再放行其余 vm。
        // continue 不能只等当前 vm（旧 resume 路径的 bug：若另一 vm 先命中断点而当前 vm
        // 无断点长循环，wait_stopped(current) 永不返回 → all-stop 失效）。改由 wait_any_stopped
        // 统一协调：放行所有 vm 后等任一命中并传播 stop 到其余 vm。
        resume_continue(v.get());
        continue_all_vms();
        // 阻塞等待任一 vm 命中（断点/异常/fork），命中后 stop_all_vms 让其余 vm 也停
        uint64_t hit_tid = 0, fork_child = 0;
        wait_any_stopped(hit_tid, v->sys()->id(), {}, &fork_child);
        auto hit_vm = find_task(hit_tid);
        if(!hit_vm || is_vm_exited(hit_vm.get()))
            send_exit_reply(hit_vm ? hit_vm.get() : v.get());
        else if(!try_send_syscall_stop(hit_vm.get()))
            send_stop_reply(hit_vm.get(), 5, fork_child);  // SIGTRAP（fork_child!=0 时为 fork 事件）
        return "";
    }
    case 's': {
        // step [addr]：单步当前线程。其余 vm 保持 stopped（all-stop：单步是局部动作，
        // 但若单步期间有其他 vm 已先命中断点，wait_any_stopped 会回报那个 vm）。
        auto v = current_vm();
        if(!v) return "E01";
        self_replied_ = true;
        if(is_vm_exited(v.get())) {
            send_exit_reply(v.get());
            return "";
        }
        resume(v.get(), true);
        // 单步完成后当前 vm 已停（resume 内 wait_stopped）；优先回报当前线程（preferred）。
        uint64_t hit_tid = 0, fork_child = 0;
        wait_any_stopped(hit_tid, v->sys()->id(), {}, &fork_child);
        auto hit_vm = find_task(hit_tid);
        if(!hit_vm || is_vm_exited(hit_vm.get()))
            send_exit_reply(hit_vm ? hit_vm.get() : v.get());
        else if(!try_send_syscall_stop(hit_vm.get()))
            send_stop_reply(hit_vm.get(), 5, fork_child);  // SIGTRAP（fork_child!=0 时为 fork 事件）
        return "";
    }
    case 'Z':   // 设置断点
    case 'z': { // 清除断点
        // Z/z<type>,<addr>,<kind>
        auto comma1 = pkt.find(',');
        auto comma2 = pkt.rfind(',');
        if(comma1 == std::string::npos) return "E02";
        unsigned long type = std::strtoul(pkt.substr(1, comma1 - 1).c_str(), nullptr, 16);
        uint64_t addr = std::strtoull(pkt.substr(comma1 + 1, comma2 - comma1 - 1).c_str(), nullptr, 16);
        // kind 不用（BPF 指令固定 8 字节）
        if(type != 0) return "";  // 仅支持软断点(type 0)
        auto v = current_vm();
        if(!v) return "E01";
        // read-copy-write：取当前不可变快照 → 复制 → 改 → 整体替换回去（vm::set_breakpoints）。
        auto cur = v->get_breakpoints();
        auto next = std::make_shared<std::unordered_set<uint64_t>>(*cur);
        if(cmd == 'Z')
            next->insert(addr);
        else
            next->erase(addr);
        v->set_breakpoints(next);
        return "OK";
    }
    case 'k': {
        // kill：置 VM_KILLED 让 vm 在下个 safepoint 退出（r(0)=128+SIGKILL）。
        // 回 OK：GDB 期望 kill 收到确认；vm 真正退出后由 server_loop 的断开路径
        // （recv 返回 false）补发 W 包。返回空串会被 server_loop 当作未识别回复发空包。
        // host_signal（pthread_kill SIGUSR1）踢开阻塞在 host syscall 的 vm，否则它要等
        // syscall 自然返回才走到 safepoint 检查 VM_KILLED（与 vKill 行为一致）。
        auto v = current_vm();
        if(v) {
            v->set_flags(vm::VM_KILLED);
            v->wakeup(false);
            v->sys()->host_signal(v.get(), 0);
        }
        return "OK";
    }
    case 'D': {
        // detach。两种形式：
        //   D          —— detach 所有进程并结束本会话（GDB 退出/quit）。走 end_session：
        //                被跟踪的 vm 恢复全速，但 pid 1 保留在 tasks_ 以便重新 attach。
        //   D;pid      —— 仅 detach 指定 pid（GDB 在 fork 后按 follow-fork-mode /
        //                detach-on-fork 决定 detach 某进程，该进程随后自由运行）。会话继续。
        // 清对应 vm 的调试态（VM_DEBUG/断点/VM_STOPPED + wakeup），否则残留 flag/断点会让
        // vm 永久卡在 safepoint 或走慢路径。全 detach 时回 OK 后 GDB 断开连接，内层 recv
        // 返回 false 退出（end_session 在外层循环统一做，与这里幂等）。
        auto semi = pkt.find(';');
        if(semi == std::string::npos) {
            end_session();
        } else {
            uint64_t pid = decode_tid(pkt.substr(semi + 1));
            if(pid != 0) detach_vm(pid);
            else          end_session();
        }
        return "OK";
    }
    case 'v': {
        // vCont[;action[:tid]]...
        if(pkt.rfind("vCont?", 0) == 0) return "vCont;c;C;s;S;t";
        if(pkt.rfind("vCont", 0) == 0) return handle_vcont(pkt);
        if(pkt.rfind("vAttach", 0) == 0) {
            // vAttach;pid：attach 到指定 pid。pid 为裸 hex 或 pPID.TID。
            // 优先查本 server 的 tasks_（已 trace 的 vm）；找不到则从 syscall 层 pid_map
            // 兜底（尚未被 trace 的 vm，如显式 attach 到某外部 vm——理论上少见，do_clone 已让
            // fork 子进程继承 VM_DEBUG_ATTACHED 并登记到 tasks_）。取到后登记到 tasks_（幂等）。
            auto semi = pkt.find(';');
            if(semi == std::string::npos) return "E01";
            uint64_t tid = decode_tid(pkt.substr(semi + 1));
            std::shared_ptr<vm> v = (tid != 0) ? find_task(tid) : main_vm_;
            if(!v && tid != 0) v = PosixSyscall::find_task(tid);  // pid_map 兜底（未 trace 的 vm）
            if(!v) return "E01";
            // 若尚未 attached，置 attached 并请求停下（VM_DEBUG_STOP），对齐 attach 语义
            // （attach 后进程应停在当前 pc，等 GDB continue 放行）。
            if(!(v->get_flags() & vm::VM_DEBUG_ATTACHED)) {
                v->set_flags(vm::VM_DEBUG_ATTACHED | vm::VM_DEBUG_STOP);
                v->sys()->host_signal(v.get(), 0);  // EINTR 阻塞 syscall 让它尽快回解释器停下
            }
            // 登记到 tasks_（持引用；已存在则幂等覆盖）。
            register_task(v->sys()->id(), v);
            current_thread_ = v->sys()->id();
            // attach 成功停止回复：multiprocess 下用 T05thread:<tid>; 让 GDB 切到该线程，
            // 否则用旧格式 S05。
            return multiprocess_ ? ("T05thread:" + encode_tid(v->sys()->id()) + ";") : "S05";
        }
        if(pkt.rfind("vKill", 0) == 0) {
            // vKill;pid：kill 指定 pid（无 pid 参数则 kill 当前 vm）。
            // 置 VM_KILLED，vm 在下个 safepoint 退出（r(0)=128+SIGKILL）。回 OK。
            std::shared_ptr<vm> v;
            auto semi = pkt.find(';');
            if(semi != std::string::npos) {
                uint64_t tid = decode_tid(pkt.substr(semi + 1));
                v = (tid != 0) ? find_task(tid) : current_vm();
            } else {
                v = current_vm();
            }
            if(v) {
                v->set_flags(vm::VM_KILLED);
                v->wakeup(false);
                v->sys()->host_signal(v.get(), 0);  // EINTR 阻塞中的 vm 让它尽快退出
            }
            return "OK";
        }
        // vMustReplyEmpty / 其它未识别 v 包：回空串（GDB 视为不支持）
        return "";
    }
    case 'T': {
        // T<thread> 线程是否存活。<thread> 形如 pid 或 pPID.TID。
        uint64_t tid = decode_tid(pkt.substr(1));
        if(tid != 0 && find_task(tid)) return "OK";
        if(tid == 0 && main_vm_) return "OK";
        return "E01";
    }
    default:
        return "";  // 未识别，回空让 GDB 忽略
    }
}
