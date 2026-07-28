//
// GDB Remote Serial Protocol (RSP) server。
//
// 由 `bpfvm --gdb <port>` 启用（对齐 QEMU -gdb）。在 <port> 监听 TCP，接受 GDB 的
// `target remote :<port>` 连接。支持：软断点（Z0/z0）、单步（s）、继续（c）、vCont（含
// per-thread action）、寄存器读写（g/G/p/P）、内存读写（m/M）、线程枚举与切换
// （H/qfThreadInfo）、vAttach、catch syscall 等多进程 RSP 包集。
//
// 启动行为（QEMU 对齐）：
//   - 默认（--gdb）：主 vm 全速 JIT 跑，GDB 连上才 attach pid 1 停在当前 pc。
//   - --stop：run() 前冻结主 vm 在入口（VM_DEBUG_ATTACHED + mark_stepping(1)），GDB 连上
//     后 continue 才放行。
// 可重复 attach + 单连接：断开/detach 后被 trace 的 vm 恢复全速，server 回 accept 等下次连接；
// 新 GDB 连上重新 attach pid 1。同一时刻只允许一个 GDB 会话。
//
// ── 停止模型（核心，各处不再重复）──
// 被调试 vm 置 VM_DEBUG_ATTACHED：compile() 据此返回 nullptr（禁 JIT——JIT 只在循环头插
// safepoint，无法支持任意 pc 的断点/单步）；step() 取指后调 DebugHooks::breakpoint 钩子
// 判定是否停。钩子统一回答「该 vm 在当前 pc 是否该停」：
//   • TaskEntry::stepping 为真 → 请求停（一次性，查中即清），命中；
//   • 否则查 TaskEntry::breakpoints（per-vm 软断点集），命中则停。
// 钩子返回 true 即 debug_park：设 VM_DEBUG_STOP（阻塞位）+ cond_wait，等 GDB continue
// 清 VM_DEBUG_STOP + wakeup 放行。所有「请求停」（单步 s / step-over / attach / all-stop
// 协调 / Ctrl-C / fork）由 GDB 线程经 mark_stepping 写入 stepping，由 vm 线程在钩子内消费——
// vm 停下即消费，下次 continue 不误停。
//   VM_DEBUG_STOP 是 GDB 专属阻塞位，与 POSIX 作业控制 VM_STOPPED（SIGSTOP/SIGCONT）完全
// 独立：continue 只清 VM_DEBUG_STOP，不清 VM_STOPPED。
//   vm 可能阻塞在 host syscall（poll/read/futex/wait）不回解释器，此时 stepping 不被检查到，
// 故配合 host_signal（pthread_kill SIGUSR1，空 handler 不带 SA_RESTART）让宿主阻塞 syscall
// 返回 EINTR 回解释器，钩子才消费。
//
// ── fork 跟踪（follow-fork-mode / detach-on-fork）──
// 协商 fork-events+ 后，fork 时父停下并上报 T05fork:<child>，GDB 据此按 follow/detach 决策。
// D;pid 单进程 detach 让该进程脱离调试器、恢复全速。不变式：已被 detach 的进程
// （非 VM_DEBUG_ATTACHED）的停止/退出绝不上报给 GDB（否则 GDB 对已移除 inferior 取状态会
// internal-error）。
//
// ── exec 跟踪 ──
// 协商 exec-events+ 后，execveat 替换地址空间后该 vm 停下并上报 T05exec:<hex-host-path>，
// GDB 据此重载符号、重插断点（新程序地址空间与旧断点无关，旧断点位置已失效）。路径用宿主视角
// 绝对路径（v->image().exe，load_elf 设置）——GDB 在宿主机跑、用它 open 文件读符号，chroot 模式
// 下宿主路径与 guest 视角路径不同。复用 syscall_return 钩子检测（execveat 成功即 r(0)==0 时），
//
// ── all-stop ──
// 任一 vm 命中断点/单步/异常停下后，stop_all_vms 对其余运行中 vm mark_stepping + host_signal，
// 各 vm 在下个 step() 钩子消费即停；continue/vCont 时按 action 放行。
//

#ifndef GDB_SERVER_H
#define GDB_SERVER_H

#include "insn.h"
#include "include/bpf_call.h"  // BPF_CALL_TO_ID（syscall 钩子算 sysno）

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

class GdbServer {
public:
    // main_vm：最初加载的 guest 程序 vm；port：监听端口。
    // stop_at_start：true=run() 前冻结主 vm 等连接（--stop，对齐 QEMU -S）；
    //                false=默认，全速运行、GDB 连上才 attach。
    GdbServer(std::shared_ptr<vm> main_vm, uint16_t port,
              bool stop_at_start = false);
    ~GdbServer();

    // 起 server 线程：listen TCP，阻塞等 GDB 连接，进入 RSP 主循环。
    // 线程 detach；GdbServer 析构时 join 退出。main 持有本对象直到 run() 返回。
    void start();

private:
    std::shared_ptr<vm> main_vm;        // 主 vm（根进程）。构造后不可变、恒非空；持 shared_ptr 保证 vm 在 server 期间存活
    std::shared_ptr<vm> current_vm;     // 当前选中的焦点 vm（RSP H 包设置；g/G/p/m/c/s 等操作目标）。
    uint16_t port_;
    int listen_fd_ = -1;
    int client_fd_ = -1;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> loop_done_{false};  // server_loop 已退出；stop() 轮询它提前 join
    bool no_ack_ = false;                // QStartNoAckMode 后不再发/收 +-
    bool multiprocess_ = false;          // GDB 在 qSupported 里广告了 multiprocess+
    bool report_fork_events_ = false;    // GDB 在 qSupported 里广告了 fork-events+/vfork-events+
    bool report_exec_events_ = false;    // GDB 在 qSupported 里广告了 exec-events+
    bool stop_at_start_ = false;         // --stop：run() 前冻结主 vm 等连接
    // handle_packet 内部标记：c/s/k/vCont 等已自行 send_packet，调用方据此跳过统一发送。
    bool self_replied_ = false;

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

    // 跟踪表条目。所有以 pid 为 key 的状态都收敛于此，由唯一的 tasks_mutex_ 保护；所有访问走
    // for_each_task / with_task 两个接口（见下）。详细停止语义见文件头。
    // 不变量：vmp 恒非空——所有 register 路径传入的 shared_ptr<vm> 都已校验非空。
    struct TaskEntry {
        std::shared_ptr<vm> vmp;                                // 该 task 的 vm 引用
        std::unordered_set<uint64_t> breakpoints;               // per-vm 软断点集（见文件头 per-pspace 说明）
        std::string exec_path;                                  // 待上报 exec 事件（空=无）
        bool stepping = false;                                  // GDB 临时停止请求位（一次性，见文件头）
        vm* fork_child = nullptr;                               // 待上报 fork 事件（子 vm*，nullptr=无）
        std::pair<uint32_t, bool> syscall_event = {0, false};   // 待上报 syscall 事件（{0,false}=无）
    };
    // pid → TaskEntry。GdbServer 自维护，不依赖 syscall 层 pid_map——pid_map 条目会被 guest 父
    // 进程 waitpid 回收，但被 trace 的 vm 退出后 GdbServer 仍需读其 r(0)/tgid 发退出回复，故自己
    // 持引用（对齐 ptrace）。
    //   登记：register_task（start 时 pid=1）/ on_create_vm（fork·clone 子）/ vAttach。
    //   移除：send_exit_reply 上报退出后 / detach_vm。
    // 并发：on_create_vm 在父 vm 线程写、wait_any_stopped 等在 GDB 线程读，tasks_mutex_ 统一保护。
    mutable std::mutex tasks_mutex_;
    std::unordered_map<uint64_t, TaskEntry> tasks_;

    void server_loop();
    // 处理一条 RSP 包（已去 $...#cc 框），返回回复内容（不含 $#cc 框，由 send_packet 加）。
    std::string handle_packet(const std::string& pkt);

    // ── tasks_ 访问 helper ──
    // 两个核心接口统管所有访问（tasks_ 内部仍以 pid 为 key，helper 用 v->sys()->id() 取 key）：
    //   for_each_task(fn)：锁内遍历全表，对每个 entry 执行 fn。
    //   with_task(v,fn)：锁内对单个 vm 的 entry 执行 fn。
    // fn 内可读写 TaskEntry 字段、调 vm 的不阻塞方法（get/set/clear_flags 原子；wakeup 持 vm
    // 自己的锁；host_signal 是 pthread_kill，都不持 tasks_mutex_，锁内调安全）。**fn 内禁止**：
    //   1) 阻塞操作（send_packet / wait_stopped / recv 等）——需收集目标后锁外做；
    //   2) 重锁 tasks_mutex_ 的函数（find_task / has_breakpoint / mark_stepping / register_task
    //      等薄封装及 for_each_task/with_task 自身）——非递归锁，重锁会死锁。
    // 不变量：对某 vm 写状态字段前必须先 register（调用方保证）。
    void for_each_task(std::function<void(TaskEntry&)> fn);
    bool with_task(vm* v, std::function<void(TaskEntry&)> fn);

    // with_task 薄封装（调用点更直白）：
    std::shared_ptr<vm> find_task(uint64_t pid);           // 取 vm 引用（持锁，找不到返回 nullptr）
    bool has_breakpoint(vm* v, uint64_t addr) const;       // step-over 判定用
    void mark_stepping(vm* v);                             // 记请求停（GDB 线程）
    // 存入 tasks_（key = v->sys()->id()）。bps 为初始断点集（主 vm/attach 传空集，fork 子传父的
    // 快照）。已存在则整体覆盖。
    void register_task(std::shared_ptr<vm> v,
                       std::unordered_set<uint64_t> bps = {});

    // vm 退出/GDB 断开时清理。返回 false 表示 vm 已退出。
    bool is_vm_exited(vm* v);

    // 确保 pid 1 被 attach 并停在当前 pc（默认模式首次连 / 重复 attach 时）。
    void attach_on_connect();
    // 会话结束：所有被 trace 的 vm 脱离调试器恢复全速，清空 tasks_，复位 RSP 协商态
    // （multiprocess/fork-events 等不跨会话保留）。下次 attach_on_connect 从 main_vm 重新登记。
    void end_session();

    // all-stop 协调：
    void continue_all_vms();   // 放行所有被 VM_DEBUG_STOP 阻塞的 vm
    void stop_all_vms();       // 让所有运行中 vm 停下（mark_stepping + host_signal）
    void detach_vm(vm* v);  // D;pid：detach 单进程，脱离调试器恢复全速

    // vm 派生通知回调（父 vm 在 do_clone 内同步调用）。子继承 VM_DEBUG_ATTACHED + 断点集快照 +
    // mark_stepping 停首条；真 fork 且协商了 fork-events+ 时另写父的 fork_child 字段供上报。
    void on_create_vm(vm* parent, vm* child, bool is_thread);
    // 构建 syscall 钩子回调（entry/return）：命中 catch 配置则记事件 + debug_park 阻塞。
    std::function<bool(vm*, uint32_t)> make_syscall_cb(bool is_entry);

    // 单步/越步放行（resume 用于 's'；resume_continue 用于 'c'，不阻塞等下次停下，交给 wait_any_stopped）。
    void resume(vm* v, bool single_step);
    void resume_continue(vm* v);
    // 阻塞等 vm 进入 VM_DEBUG_STOP/VM_EXITED/VM_KILLED（越步单步阶段用）。
    void wait_stopped(vm* v);
    // all-stop 阻塞点：等任一 vm 停下/退出，停下后 stop_all_vms 让其余也停，等全部收敛后返回命中 vm。
    // preferred：优先报告它（单步场景让 GDB 切到单步线程）。
    // watch_vms：仅观察这些 vm 的新停止（vCont 用，避免被本就 stopped 的 vm 满足）；空=观察全部。
    // out_fork_child：命中 vm 有 fork 事件时写入子 vm*（供发 T05fork:<child>），一次性消费。
    void wait_any_stopped(std::shared_ptr<vm>& out_hit_vm, vm* preferred = nullptr,
                          const std::vector<vm*>& watch_vms = {},
                          vm** out_fork_child = nullptr);
    void send_exit_reply(vm* v);   // W 包（退出，只发一次）
    // T<sig> + thread:<tid>；fork_child 非 null 时改发 fork 事件（T<sig>fork:<child>;thread:<tid>;）。
    void send_stop_reply(vm* v, int sig, vm* fork_child = nullptr);
    // 命中 vm 的 syscall_event 字段有待上报事件则发回复并清字段，返回 true。
    bool try_send_syscall_stop(vm* v);
    // 命中 vm 的 exec_path 字段有待上报事件则发 T05exec:<hex-path>;thread:<tid>; 并清字段，返回 true。
    bool try_send_exec_stop(vm* v);

    // vCont 处理：解析 vCont[;action[:tid]]... 多 action，按 per-tid 分派。
    // 返回空串（已自行 send_packet，self_replied_=true）。
    std::string handle_vcont(const std::string& pkt);

    // ── multiprocess 线程 id 编解码 ──
    // multiprocess 关闭时：裸 hex pid（如 "1"）；开启时：pPID.TID（如 "p1.1"）。
    // bpfvm 里每个 vm 的 pid 即 tid（leader pid==tgid==tid；非 leader 线程 pid 即 tid），
    // 故 PID 取 vm 所属线程组 tgid、TID 取 vm 自身 pid。
    std::string encode_tid(vm* v);
    // 解析线程 id 字符串为 vm。无论 multiprocess 与否，TID 段即 vm 的 pid。
    // "0"/"-1"/"p0.0"/"p-1.-1" 等特殊值（任意/所有）或查表不到返回 nullptr（由调用方处理）。
    // search_pid_map=true 时，tasks_ 查不到再查 syscall 层 pid_map（vAttach 用来 attach 尚未被
    // trace 的存活 vm）；其余入口默认 false（只认已被 GDB attach 的 vm）。
    std::shared_ptr<vm> decode_tid(const std::string& s, bool search_pid_map = false);
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
