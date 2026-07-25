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
#include <string>
#include <vector>

// BPF 寄存器在 g/G 包里的顺序与数量（r0..r9, r10=fp, pc）。
// GDB bpf-tdep.c 把 r0..r10 + pc 列为 num_regs，每个 8 字节小端。
static constexpr int GDB_NUM_REGS = 12;  // r0-r10 + pc

GdbServer::GdbServer(std::shared_ptr<vm> main_vm, uint16_t port, const ElfLoadInfo& info)
    : main_vm_(std::move(main_vm)), port_(port), info_(info) {}

GdbServer::~GdbServer() {
    stop();
}

void GdbServer::start() {
    // 在 run() 前就把主 vm 置为调试态 + 待停：
    //   VM_DEBUG_ATTACHED：禁 JIT（compile() 见到返回 nullptr）、step() 据此每步查断点
    //   VM_DEBUG_STOP：第一条 step() 命中即置 VM_STOPPED 在 safepoint 阻塞，等 GDB 连接后
    //                  continue 才放行。必须在 run() 启动前设置，否则与首条指令竞态。
    main_vm_->set_flags(vm::VM_DEBUG_ATTACHED | vm::VM_DEBUG_STOP);
    running_ = true;
    thread_ = std::thread([this] { server_loop(); });
}

void GdbServer::stop() {
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

std::shared_ptr<vm> GdbServer::current_vm() {
    if(current_thread_ != 0) {
        if(auto v = PosixSyscall::find_task(current_thread_)) return v;
    }
    return main_vm_;
}

bool GdbServer::is_vm_exited(vm* v) {
    return v->get_flags() & (vm::VM_EXITED | vm::VM_KILLED);
}

// all-stop（部分）：continue 时唤醒所有被 VM_STOPPED 阻塞的 vm。
// 注：v1 仅在当前 vm 上精确实现断点/单步；多 vm（fork 后）场景下，其余 vm 在收到
// continue 时一并放行，但断点命中不会主动 stop 其他 vm（非严格 all-stop）。这对单线程
// 程序（绝大多数测试用例）完全正确；多线程精确 all-stop 留作后续扩展。
void GdbServer::continue_all_vms() {
    auto pids = PosixSyscall::list_pids();
    for(uint64_t pid : pids) {
        if(auto v = PosixSyscall::find_task(pid)) {
            v->clear_flags(vm::VM_STOPPED);
            v->wakeup(false);
        }
    }
}

// 清除所有 vm 的调试态。detach / GDB 断开连接 / vm 退出 时调用：
//   - VM_DEBUG_ATTACHED/VM_DEBUG_STOP：JIT 恢复、step() 不再每步查断点
//   - 软断点集合：detach 后无人消费，残留会让 vm 跑到该 pc 永久卡在 safepoint
//   - VM_STOPPED + wakeup：把卡在 safepoint wait_cv 上的 vm 放行
// 清完后进程脱离调试器，用正常 JIT 速度继续运行。
void GdbServer::detach_all_vms() {
    auto pids = PosixSyscall::list_pids();
    for(uint64_t pid : pids) {
        auto v = PosixSyscall::find_task(pid);
        if(!v) continue;
        v->clear_breakpoints();
        v->clear_flags(vm::VM_DEBUG_ATTACHED | vm::VM_DEBUG_STOP | vm::VM_STOPPED);
        v->wakeup(false);
    }
}

// 让目标 vm 跑起来（解除 VM_STOPPED），阻塞等待它再次停下（VM_STOPPED）或退出。
// 若当前 pc 命中断点，先 VM_DEBUG_STOP 单步越过，停下后若仍未退出则再放行真 continue。
void GdbServer::resume(vm* v, bool single_step) {
    // 第一阶段：单步越过当前断点（若有）；否则直接放行。
    bool need_step_over = (!single_step) && v->has_breakpoint(v->pc());
    v->clear_flags(vm::VM_STOPPED);
    if(single_step || need_step_over) {
        v->set_flags(vm::VM_DEBUG_STOP);
        v->wakeup(false);
        wait_stopped(v);
        if(is_vm_exited(v)) return;
    }
    // 第二阶段：单步请求到此为止（已停）；continue 请求（含越过断点后）放行真继续，
    // 并阻塞等待 vm 再次停下（断点命中）或退出。
    if(single_step) return;
    v->clear_flags(vm::VM_STOPPED);
    v->wakeup(false);
    wait_stopped(v);
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
    char buf[32];
    std::snprintf(buf, sizeof(buf), "W%02lx", code);
    send_packet(buf);
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

    client_fd_ = accept(listen_fd_, nullptr, nullptr);
    if(client_fd_ < 0) return;
    // attach：对 list_pids 里所有 vm 补设 VM_DEBUG_ATTACHED。start() 已对 main_vm 设过，这里覆盖
    // listen 期间 fork/clone 出的子 vm——它们同样要禁 JIT 才能被精确断点/单步。
    for(uint64_t pid : PosixSyscall::list_pids()) {
        if(auto v = PosixSyscall::find_task(pid)) v->set_flags(vm::VM_DEBUG_ATTACHED);
    }
    // 关闭 Nagle，减少小包延迟
    int one = 1;
    setsockopt(client_fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    // recv 超时：让 server_loop 周期性醒来检查 running_ 与 vm 退出，避免永久阻塞
    struct timeval tv{0, 200000};  // 0.2s
    setsockopt(client_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

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
    // 循环退出（GDB 断开 / vm 退出 / stop()）：兜底 detach。若 vm 仍在跑（如 GDB 直接断开
    // 而非 detach），清掉 VM_DEBUG_ATTACHED/断点让它恢复正常 JIT 速度；若已退出则 clear 是空操作。
    // 与 D 包的 detach_all_vms() 幂等，重复调无副作用。
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
        if(pkt.rfind("qSupported", 0) == 0)
            return "PacketSize=4096;swbreak+;QStartNoAckMode+";
        if(pkt == "qAttached") return "1";
        if(pkt.rfind("qfThreadInfo", 0) == 0) {
            // 枚举线程：m<pid>,<pid>,...l 终止
            auto pids = PosixSyscall::list_pids();
            std::string r = "m";
            for(size_t i = 0; i < pids.size(); i++) {
                if(i) r += ",";
                char buf[32];
                std::snprintf(buf, sizeof(buf), "%lx", (unsigned long)pids[i]);
                r += buf;
            }
            return r;
        }
        if(pkt.rfind("qsThreadInfo", 0) == 0) return "l";
        if(pkt.rfind("qThreadExtraInfo", 0) == 0) return "";
        if(pkt.rfind("qC", 0) == 0) {
            // 返回当前线程 id。current_thread_ 为 0 时回退到 main 线程——绝不能回 QC0，
            // 线程 id 0 是 RSP 特殊值，GDB 会 switch_to_thread(NULL) 触发 assertion。
            uint64_t tid = current_thread_ ? current_thread_ : main_thread_id();
            char buf[32];
            std::snprintf(buf, sizeof(buf), "QC%lx", (unsigned long)tid);
            return buf;
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
        return "";
    }
    case '?': {
        // 报告停止原因。S05 = SIGTRAP（断点/单步/attach）。
        auto v = current_vm();
        if(!v || is_vm_exited(v.get())) {
            unsigned long code = v ? (unsigned long)(v->r(0) & 0xFF) : 0;
            char buf[32];
            std::snprintf(buf, sizeof(buf), "W%02lx", code);
            return buf;
        }
        return "S05";
    }
    case 'H': {
        // H<op><thread>：选择后续操作的目标线程。<thread> 形如 pid 或 pid.tid。
        // '0'/'-1' 是 RSP 特殊值（任意/所有线程）——必须映射到一个真实 pid，
        // 否则后续 qC 返回 0 会让 GDB switch_to_thread(NULL) 触发 assertion。
        if(pkt.size() < 2) return "E01";
        std::string t = pkt.substr(2);
        if(t == "-1" || t == "0") {
            current_thread_ = main_thread_id();
        } else {
            current_thread_ = std::strtoull(t.c_str(), nullptr, 16);
            if(!PosixSyscall::find_task(current_thread_)) current_thread_ = main_thread_id();
        }
        return "OK";
    }
    case 'g': {
        // 读全部寄存器：r0..r10 + pc 全部 8 字节小端（共 96 字节 = 192 hex）。
        // 上游 GDB 的 bpf-tdep 缺 set_gdbarch_ptr_bit(64)，导致 r10/pc 被当 4 字节、
        // bt 后 info registers 崩（已报上游）。补丁版 GDB 把 r10/pc 修正为 8 字节，
        // g 包须按 96 字节发。本仓库 scripts/ 提供 patch 版 GDB 构建。
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
        // continue [addr]
        auto v = current_vm();
        if(!v) return "E01";
        self_replied_ = true;
        if(is_vm_exited(v.get())) {
            send_exit_reply(v.get());
            return "";
        }
        // 放行所有非当前 stop 的 vm（all-stop）
        continue_all_vms();
        resume(v.get(), false);
        if(is_vm_exited(v.get()))
            send_exit_reply(v.get());
        else
            send_packet("S05");  // 断点/单步停
        return "";
    }
    case 's': {
        // step [addr]：仅单步当前线程，其余 vm 保持 stopped。
        auto v = current_vm();
        if(!v) return "E01";
        self_replied_ = true;
        if(is_vm_exited(v.get())) {
            send_exit_reply(v.get());
            return "";
        }
        resume(v.get(), true);
        if(is_vm_exited(v.get()))
            send_exit_reply(v.get());
        else
            send_packet("S05");
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
        if(cmd == 'Z')
            v->add_breakpoint(addr);
        else
            v->remove_breakpoint(addr);
        return "OK";
    }
    case 'k': {
        // kill：置 VM_KILLED 让 vm 在下个 safepoint 退出（r(0)=128+SIGKILL）。
        // 回 OK：GDB 期望 kill 收到确认；vm 真正退出后由 server_loop 的断开路径
        // （recv 返回 false）补发 W 包。返回空串会被 server_loop 当作未识别回复发空包。
        auto v = current_vm();
        if(v) {
            v->set_flags(vm::VM_KILLED);
            v->wakeup(false);
        }
        return "OK";
    }
    case 'D': {
        // detach：GDB 分离调试器，进程应继续独立运行。清所有 vm 的调试态（VM_DEBUG/断点/
        // VM_STOPPED + wakeup），否则残留 flag/断点会让 vm 永久卡在 safepoint 或走慢路径。
        // 回 OK 后 GDB 断开连接，server_loop 的 recv 返回 false 自然退出（那条路径也会再
        // 调 detach_all_vms 兜底，幂等）。
        detach_all_vms();
        return "OK";
    }
    case 'v': {
        // vCont[;action[:tid]]...
        if(pkt.rfind("vCont?", 0) == 0) return "vCont;c;C;s;S";
        if(pkt.rfind("vCont", 0) == 0) {
            // 简化：解析第一个 action（c 或 s）
            auto semi = pkt.find(';');
            std::string action = (semi == std::string::npos) ? "c" : pkt.substr(semi + 1, 1);
            if(action == "s") return handle_packet("s");
            return handle_packet("c");
        }
        if(pkt.rfind("vKill", 0) == 0) return handle_packet("k");
        return "";
    }
    case 'T': {
        // T<thread> 线程是否存活
        std::string t = pkt.substr(1);
        uint64_t tid = std::strtoull(t.c_str(), nullptr, 16);
        if(PosixSyscall::find_task(tid)) return "OK";
        if(tid == 0 && main_vm_) return "OK";
        return "E01";
    }
    default:
        return "";  // 未识别，回空让 GDB 忽略
    }
}
