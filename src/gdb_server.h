//
// GDB Remote Serial Protocol (RSP) server.
//
// 由 `bpfvm --gdb <port>` 启用（对齐 QEMU -gdb 语义）。在 <port> 监听 TCP，接受 GDB 的
// `target remote :<port>` 连接。支持软断点（Z0/z0）、单步（s）、继续（c）、vCont（含 per-thread
// action）、寄存器读写（g/G/p/P）、内存读写（m/M）、线程枚举与切换（H/qfThreadInfo）、
// vAttach（attach 到指定 pid）等多进程 RSP 包集。
//
// 启动行为（QEMU 对齐）：
//   - 默认（--gdb <port>）：主 vm 全速 JIT 运行，**GDB 连上才 attach pid 1**，停在当前 pc。
//     对应 QEMU `-gdb tcp::1234`（VM 跑起来，GDB 随时 attach）。
//   - --stop：run() 前就置 VM_DEBUG_ATTACHED+VM_STOPPED 把主 vm 冻结在入口，等 GDB 连上
//     continue 才放行。对应 QEMU `-gdb tcp::1234 -S`（启动即冻结等连接）。
//
// 可重复 attach + 单连接：GDB 断开 / detach 后，被 trace 的 vm 恢复全速 JIT，server 不退出、
// 回 accept 等下次连接；新 GDB 连上重新 attach pid 1（从 main_vm_ 找回）。同时只允许一个
// GDB 会话（单线程 accept 串行化，会话期间不接新连接）。
//
// 调试会话期间 JIT 必须禁用：被 trace 的 vm 置 VM_DEBUG_ATTACHED，compile() 见到返回 nullptr，
// step() 据此每条指令检查断点集合 / VM_DEBUG_STOP，断点/单步语义精确；JIT 仅在循环头插
// safepoint，无法支持任意 pc 的断点/单步。attach 一个正在 JIT 全速跑的 vm 时直接置 VM_STOPPED
// （JIT safepoint 只认 VM_STOPPED，非 VM_DEBUG_STOP）+ host_signal（EINTR 阻塞 syscall）。
//
// fork 跟踪语义（follow-fork-mode / detach-on-fork）：协商 fork-events+ 后，fork 时父停下
// 并上报 T05fork:<child>，GDB 据此按 follow/detach 设置决策。D;pid 单进程 detach 让被
// detach 的进程脱离调试器、恢复 JIT 全速自由运行。关键不变式：已被 detach 的进程（非
// VM_DEBUG_ATTACHED）的停止/退出绝不上报给 GDB（否则 GDB 对已移除的 inferior 取状态会
// internal-error）——wait_any_stopped / continue_all_vms / stop_all_vms / qfThreadInfo 均
// 过滤 VM_DEBUG_ATTACHED。
//
// all-stop 模型：任一 vm 命中断点/单步/异常停下后，遍历 pid_map 给其余运行中的 vm 置
// VM_DEBUG_STOP + host_signal（pthread_kill SIGUSR1，让阻塞在 host syscall 的 vm EINTR 回
// 解释器），各 vm 在下个解释器 safepoint 停下；continue/vCont 时按 action 放行。
//

#ifndef GDB_SERVER_H
#define GDB_SERVER_H

#include "insn.h"
#include "elf_loader.h"
#include "include/bpf_call.h"  // BPF_CALL_TO_ID（syscall 钩子算 sysno）

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>

class GdbServer {
public:
    // main_vm：最初加载的 guest 程序 vm；port：监听端口。
    // stop_at_start：true=run() 前冻结主 vm 等连接（--stop，对齐 QEMU -S）；
    //                false=默认，全速运行、GDB 连上才 attach。
    GdbServer(std::shared_ptr<vm> main_vm, uint16_t port, const ElfLoadInfo& info,
              bool stop_at_start = false);
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
    bool multiprocess_ = false;          // GDB 在 qSupported 里广告了 multiprocess+
    bool report_fork_events_ = false;    // GDB 在 qSupported 里广告了 fork-events+/vfork-events+
    bool exit_notified_ = false;         // 已向 GDB 发过 W 包（避免重复）
    bool stop_at_start_ = false;         // --stop：run() 前冻结主 vm 等连接
    // handle_packet 内部标记：c/s/k/vCont 等已自行 send_packet，调用方据此跳过统一发送。
    bool self_replied_ = false;

    // 待上报的 fork 事件：on_create 在真 fork（!is_thread）且协商了 fork-events+ 时写入
    // (parent_pid → child_pid)；wait_any_stopped 命中 parent 时查表取 child pid 发
    // T05fork:<child>，erase 一次性消费。mutex 保护：on_create 在父 vm 线程写、
    // wait_any_stopped 在 GDB 线程读。
    std::mutex fork_events_mutex_;
    std::unordered_map<uint64_t, uint64_t> fork_events_;  // parent_pid → child_pid

    // catch syscall 配置（会话级，GDB 用 QCatchSyscalls 设置）。enabled=false=不 catch；
    // enabled=true 且 sysnos 空=catch 全部 syscall；enabled=true 且 sysnos 非空=仅 catch 列表。
    // 由 syscall 回调闭包（make_syscall_cb）在 vm 线程读、QCatchSyscalls 在 GDB 线程写，
    // 故用 AtomicSharedPtr 整体原子替换（COW/RCU 风格）：写端构造新 const 实例 store，
    // 读端 load 拿到不可变快照——不会读到半新半旧的组合。
    struct SyscallCatchCfg {
        bool enabled = false;
        std::shared_ptr<const std::unordered_set<uint32_t>> sysnos =
            std::make_shared<const std::unordered_set<uint32_t>>();  // 空=catch全部
    };
    AtomicSharedPtr<const SyscallCatchCfg> syscall_catch_{
        std::make_shared<const SyscallCatchCfg>()};
    // 待上报的 syscall 停止事件：syscall 钩子回调（vm 线程）命中时写入 (pid → (sysno,is_entry))，
    // wait_any_stopped（GDB 线程）命中该 vm 时取出发 T05syscall_entry/return:<hex>; 回复并 erase。
    // mutex 保护：回调与 wait_any_stopped 跨线程读写。
    std::mutex syscall_events_mutex_;
    std::unordered_map<uint64_t, std::pair<uint32_t, bool>> pending_syscall_events_;

    // 本 server 跟踪的 vm 表（pid → shared_ptr<vm>）。GdbServer 自维护，不依赖 syscall 层
    // pid_map——pid_map 条目会被 guest 父进程 waitpid 回收而消失，但被 trace 的 vm 退出后
    // GdbServer 仍需读其 r(0)/tgid 发退出回复，故必须自己持引用。对齐 ptrace：tracer 持
    // task_struct 引用，不依赖内核 task list。
    //   登记：register_main_task（start 时）/ on_create_vm（fork·clone 子）/ vAttach。
    //   移除：send_exit_reply 上报退出后立即移除（释放引用）/ detach_vm。
    // 并发：on_create_vm 在父 vm 线程写、wait_any_stopped 等在 GDB 线程读，故 tasks_mutex_ 保护。
    std::mutex tasks_mutex_;
    std::unordered_map<uint64_t, std::shared_ptr<vm>> tasks_;

    // 当前选中的线程（pid）。RSP H 包设置；g/G/p/m/c/s 等操作目标。
    uint64_t current_thread_ = 0;

    void server_loop();
    // 处理一条 RSP 包（已去 $...#cc 框），返回回复内容（不含 $#cc 框，由 send_packet 加）。
    std::string handle_packet(const std::string& pkt);

    // 取当前操作目标的 vm（current_thread_ 对应的 pid；0/无效则回退 main_vm_）。
    std::shared_ptr<vm> current_vm();
    // 主 vm 的线程 id（PosixSyscall::pid，兜底 1）。
    uint64_t main_thread_id();

    // ── 自维护 tracee 表（tasks_）的访问 helper（均持 tasks_mutex_）──
    // 按 pid 查 tasks_（找不到返回 nullptr）。
    std::shared_ptr<vm> find_task(uint64_t pid);
    // tasks_ 的 key 快照（供枚举迭代）。
    std::vector<uint64_t> list_tasks();
    // 存入 tasks_（pid 由调用方提供——main_vm_ 在 run() 前 sys 尚未初始化，取不到 id()，
    // 故 start() 显式传 1；on_create_vm/vAttach 的 child sys 已建好可取 id()）。已存在则覆盖。
    void register_task(uint64_t pid, std::shared_ptr<vm> v);
    // 从 tasks_ 移除 pid（不存在则空操作）。
    void unregister_task(uint64_t pid);

    // 通知：vm 退出 / GDB 断开时清理。返回 false 表示 vm 已退出，应通知 GDB。
    bool is_vm_exited(vm* v);

    // 每次 GDB 连上（accept 成功）后调：复位 per-connection 协商态（ack/multiprocess/
    // fork-events/exit_notified/current_thread/fork_events_）。
    void reset_session_state();
    // 每次 GDB 连上后调：确保 pid 1 被 attach（默认模式首次连/重复 attach 时置
    // VM_DEBUG_ATTACHED|VM_STOPPED + host_signal 让它停在当前 pc）。--stop 首次连接时
    // pid 1 已被 start() 冻结，跳过置 flag（避免覆盖 start 的 VM_DEBUG_STOP 语义）。
    void attach_on_connect();
    // 每次会话结束（GDB 断开 / D 包）调：让所有被 trace 的 vm 脱离调试器恢复全速，
    // 但**保留 pid 1 在 tasks_**（detach_vm 会移除，这里重新 register 以便下次 attach）。
    // 与 detach_all_vms() 区别：后者把 pid 1 也 unregister（用于 server 最终退出）。
    void end_session();

    // all-stop 协调：唤醒所有被 VM_STOPPED 阻塞的 vm（放行）。
    void continue_all_vms();
    // all-stop 协调：让所有运行中的 vm 停下（置 VM_DEBUG_STOP + host_signal）。
    // 任一 vm 命中断点/异常后调用，把其余 vm 也停到 safepoint。
    void stop_all_vms();
    // 清除所有 vm 的调试态（VM_DEBUG/VM_DEBUG_STOP/断点 + VM_STOPPED + wakeup）。
    // detach / GDB 断开 / vm 退出 时调用，让进程脱离调试器后用正常 JIT 速度继续跑。
    void detach_all_vms();
    // 清除单个 vm 的调试态（同上，但只针对一个 pid）。用于 D;pid：GDB 在 fork 后按
    // follow-fork-mode / detach-on-fork 决定 detach 某个进程（如 detach-on-fork=on 时
    // detach 非跟随方），该进程脱离调试器后用正常 JIT 速度自由运行。
    void detach_vm(uint64_t pid);

    // vm 派生通知回调（注册到 main_vm_，由父 vm 的 notify_create 在 do_clone 内同步调用）。
    // thread 和 process 同一套处理（继承 VM_DEBUG_ATTACHED + 断点集 + 子停 VM_DEBUG_STOP +
    // 回调继承给子），仅真 fork（!is_thread）且协商了 fork-events+ 时停父并记 fork_events_
    // 供 wait_any_stopped 上报 T05fork:<child>。所有 GDB 协议知识集中在此处。
    void on_create_vm(vm* parent, vm* child, bool is_thread);

    // continue 越过当前断点（若 pc 命中断点，先单步一条），随后放行阻塞等待下次停下。
    // 注：仅用于 's'（单步）——单步是局部动作，resume 内 wait_stopped 等单步完成即可。
    void resume(vm* v, bool single_step);
    // 'c'（continue）专用：若 pc 命中断点先单步越过（阻塞到越过完成），随后放行（清
    // VM_STOPPED/VM_DEBUG_STOP + wakeup）但**不**阻塞等待下次停下——continue 的「等任一
    // vm 命中」由调用方统一走 wait_any_stopped 协调（多进程 all-stop 正确性：不能只等
    // 当前 vm，否则另一 vm 命中断点时本 vm 无断点会永远不停 → all-stop 失效）。
    void resume_continue(vm* v);
    // 阻塞等待 vm 进入 VM_STOPPED/VM_EXITED/VM_KILLED（单 vm，用于越过断点的单步阶段）。
    void wait_stopped(vm* v);
    // all-stop 阻塞点：等待任一 vm 停下/退出，停下后立即 stop_all_vms 让其余 vm 也停，
    // 等所有 vm 进入 VM_STOPPED 后返回命中的 tid。期间并发窥探 client socket 的
    // async Ctrl-C (0x03)。out_stopped_tid 写入命中的 tid（multiprocess 下为 pPID.TID）。
    // preferred_pid 若非 0：优先报告它（已停则直接选它），用于 s/vCont 单步场景让 GDB
    // 切到单步的那个线程而非列表里其他已停的 vm。
    // watch_pids：仅观察这些 pid 的「新停止」转换（用于 vCont——只等本次释放的 vm 停下，
    //   不被那些本来就处于 stopped 的 vm 立即满足）。为空时观察所有 vm。
    // out_fork_child：若命中的 vm 有待上报的 fork 事件（fork_events_ 表里有它作 parent 的条目），
    //   写入子的 pid；调用方据此发 T05fork:<child> 而非普通 T05thread:<tid>。命中即 erase（一次性）。
    void wait_any_stopped(uint64_t& out_stopped_tid, uint64_t preferred_pid = 0,
                          const std::vector<uint64_t>& watch_pids = {},
                          uint64_t* out_fork_child = nullptr);
    // 向 GDB 报告 vm 退出（W 包，只发一次）。
    void send_exit_reply(vm* v);
    // 构造停止回复并发送：T<sig> + thread:<tid>（multiprocess 用 pPID.TID）。
    // fork_child 非 0 时改发 fork 事件：T<sig>fork:<child_ptid>;thread:<tid>;
    // （GDB 据此应用 follow-fork-mode / detach-on-fork）。
    void send_stop_reply(vm* v, int sig, uint64_t fork_child = 0);
    // 构造 syscall 停止回复并发送：T05syscall_entry/return:<hex-sysno>;thread:<tid>;。
    // sysno 为 BPF_CALL_TO_ID(call)（bpf 枚举值，小写变长十六进制）。
    void send_syscall_stop_reply(vm* v, uint32_t sysno, bool is_entry);
    // 查 pending_syscall_events_ 是否有该 pid 的待上报 syscall 事件；有则发 syscall 停止
    // 回复并 erase（一次性），返回 true（已发）。无则返回 false（调用方发普通断点/fork回复）。
    bool try_send_syscall_stop(vm* v);

    // 构建 syscall 钩子回调（entry/return）：命中 catch 配置则记事件 + debug_park 阻塞。
    std::function<bool(vm*, uint32_t)> make_syscall_cb(bool is_entry);
    // 构建完整 DebugHooks（create + syscall entry/return）并应用到所有 attached vm。
    void install_debug_hooks();

    // vCont 处理：解析 vCont[;action[:tid]]... 多 action，按 per-tid 分派。
    // 返回空串（已自行 send_packet，self_replied_=true）。
    std::string handle_vcont(const std::string& pkt);

    // ── multiprocess 线程 id 编解码 ──
    // multiprocess 关闭时：裸 hex pid（如 "1"）；开启时：pPID.TID（如 "p1.1"）。
    // bpfvm 里每个 vm 的 pid 即 tid（leader pid==tgid==tid；非 leader 线程 pid 即 tid），
    // 故 PID 取 vm 所属线程组 tgid、TID 取 vm 自身 pid。
    std::string encode_tid(uint64_t pid);
    // 解析线程 id 字符串为 vm 的 pid（无论 multiprocess 与否，统一返回 pid）。
    // 0 / -1 / p0.0 / p-1.-1 等特殊值返回 0（由调用方映射到主线程）。
    static uint64_t decode_tid(const std::string& s);
    // 取 vm 的线程组 id（tgid）；sys 非 PosixSyscall 时退化为 pid。
    static uint64_t vm_tgid(vm* v);

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
