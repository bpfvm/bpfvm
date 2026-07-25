//
// GDB Remote Serial Protocol (RSP) server.
//
// 由 `bpfvm --gdb <port>` 启用。在 <port> 监听 TCP，接受 GDB 的 `target remote :<port>`
// 连接。支持软断点（Z0/z0）、单步（s）、继续（c）、寄存器读写（g/G/p/P）、内存读写
// （m/M）、线程枚举与切换（H/qfThreadInfo）等最小可用 RSP 包集。
//
// 调试会话期间 JIT 必须禁用（main.cpp 在 run() 前 setenv JIT_ENABLE=0）：解释器 step()
// 每条指令都检查断点集合 / VM_DEBUG_STOP，断点/单步语义精确；JIT 仅在循环头插 safepoint，
// 无法支持任意 pc 的断点/单步。
//
// 多进程：经全局 pid_map（PosixSyscall）跟踪所有 guest vm（fork 出的子 vm 自动登记）。
// all-stop 模型：任一 vm 命中断点，遍历 pid_map 给其余 vm 置 VM_DEBUG_STOP + wakeup，
// 各自在下个解释器 safepoint 停下；continue 时全部唤醒。
//

#ifndef GDB_SERVER_H
#define GDB_SERVER_H

#include "insn.h"
#include "elf_loader.h"

#include <atomic>
#include <memory>
#include <thread>

class GdbServer {
public:
    // main_vm：最初加载的 guest 程序 vm；port：监听端口。
    GdbServer(std::shared_ptr<vm> main_vm, uint16_t port, const ElfLoadInfo& info);
    ~GdbServer();

    // 起 server 线程：listen TCP，阻塞等 GDB 连接，进入 RSP 主循环。
    // 线程 detach；vm 析构（run() 返回）后由 stop() 退出。main 持有本对象直到 run() 返回。
    void start();

    // 关闭 server（main 在 run() 返回后调用）：关 listen/client socket，join 线程。
    void stop();

private:
    std::shared_ptr<vm> main_vm_;        // 持 shared_ptr 保证 vm 在 server 期间存活
    uint16_t port_;
    ElfLoadInfo info_;
    int listen_fd_ = -1;
    int client_fd_ = -1;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> loop_done_{false};  // server_loop 已退出；stop() 轮询它提前 join
    bool no_ack_ = false;                // QStartNoAckMode 后不再发/收 +-
    bool exit_notified_ = false;         // 已向 GDB 发过 W 包（避免重复）
    // handle_packet 内部标记：c/s/k/vCont 等已自行 send_packet，调用方据此跳过统一发送。
    bool self_replied_ = false;

    // 当前选中的线程（pid）。RSP H 包设置；g/G/p/m/c/s 等操作目标。
    uint64_t current_thread_ = 0;

    void server_loop();
    // 处理一条 RSP 包（已去 $...#cc 框），返回回复内容（不含 $#cc 框，由 send_packet 加）。
    std::string handle_packet(const std::string& pkt);

    // 取当前操作目标的 vm（current_thread_ 对应的 pid；0/无效则回退 main_vm_）。
    std::shared_ptr<vm> current_vm();
    // 主 vm 的线程 id（PosixSyscall::pid，兜底 1）。
    uint64_t main_thread_id();

    // 通知：vm 退出 / GDB 断开时清理。返回 false 表示 vm 已退出，应通知 GDB。
    bool is_vm_exited(vm* v);

    // all-stop 协调（部分，见 cpp 注释）：唤醒所有被 VM_STOPPED 阻塞的 vm。
    void continue_all_vms();
    // 清除所有 vm 的调试态（VM_DEBUG/VM_DEBUG_STOP/断点 + VM_STOPPED + wakeup）。
    // detach / GDB 断开 / vm 退出 时调用，让进程脱离调试器后用正常 JIT 速度继续跑。
    void detach_all_vms();

    // continue 越过当前断点（若 pc 命中断点，先单步一条）。
    void resume(vm* v, bool single_step);
    // 阻塞等待 vm 进入 VM_STOPPED/VM_EXITED/VM_KILLED。
    void wait_stopped(vm* v);
    // 向 GDB 报告 vm 退出（W 包，只发一次）。
    void send_exit_reply(vm* v);

    // RSP 包 I/O
    bool recv_byte(char& out);            // 单字节可靠接收（超时/中断重试，见 cpp）
    bool recv_packet(std::string& out);
    void send_packet(const std::string& payload);

    // hex 编解码（小端，BPF 寄存器 8 字节）
    static std::string to_hex2(uint8_t v);
    static std::string reg_to_hex(uint64_t v);      // 8 字节小端 hex
    static uint64_t hex_to_reg(const std::string& s);   // 8 字节
    static std::string hex_encode(const void* data, size_t len);
    static bool hex_decode(const std::string& s, void* out, size_t len);
    static int hex_val(char c);
};

#endif // GDB_SERVER_H
