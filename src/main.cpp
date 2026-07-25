#include "insn.h"
#include "pty.h"
#include "gdb_server.h"
#include "posix/posix_syscall.h"

#include <iostream>
#include <filesystem>

#include <libgen.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>


static struct option long_options[] = {
    {"verbose", no_argument, nullptr, 'v'},
    {"insn-limit", required_argument, nullptr, 'l'},
    {"stack-size", required_argument, nullptr, 'S'},
    {"root", required_argument, nullptr, 'R'},
    {"env", required_argument, nullptr, 'e'},
    {"pty", no_argument, nullptr, 't'},
    {"no-pty", no_argument, nullptr, 'T'},
    {"gdb", required_argument, nullptr, 'g'},
    {nullptr, 0, nullptr, 0}
};

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " [options] <elf-file> [args...]\n"
        << "\n"
        << "Options:\n"
        << "  -v, --verbose               verbose output\n"
        << "  -l, --insn-limit <N>        max instructions before exit 255 (0 = unlimited)\n"
        << "  -S, --stack-size <N>        per-frame stack bytes (default 16384)\n"
        << "  -R, --root <dir>            chroot into <dir>; guest paths resolved under it\n"
        << "  -e, --env <KEY=VALUE>       inject env var for guest (repeatable; overrides default)\n"
        << "  -t, --pty                   force PTY mode for stdio\n"
        << "  -T, --no-pty                disable PTY mode (raw stdio passthrough)\n"
        << "  -g, --gdb <port>            start GDB RSP server on <port> (disables JIT)\n";
}

int main(int argc, char** argv) {
    std::shared_ptr<vmOptions> options = std::make_shared<vmOptions>();
    options->verbose = false; // 默认值
    options->raw_stack = false; // 默认值
    options->sys = std::make_shared<PosixSyscall>();

    // PTY 三态：默认 auto（stdin 是 tty 则开，贴近真实终端行为；管道/CI 下关，保持既有
    // 测试行为）；-t/--pty 强制开；-T/--no-pty 强制关（即便在真 tty 里也走纯透传 stdio）。
    enum class PtyMode { Auto, On, Off };
    PtyMode pty_mode = PtyMode::Auto;

    // -e KEY=VALUE 收集：命令行显式注入的环境变量，覆盖 HOME/PATH 等默认（命令行优先）。
    // 存 {key, value}（已拆出 VALUE，不含 '='），合并阶段用 key 做覆盖匹配。
    std::map<std::string, std::string> extra_envp;

    // --gdb <port>：启用 GDB RSP server。>0 表示启用，0 表示禁用。
    uint16_t gdb_port = 0;

    int opt;
    while ((opt = getopt_long(argc, argv, "vl:S:R:e:tTg:", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'v':
            options->verbose = true;
            break;
        case 'l':
            options->insn_limit = std::stoull(optarg, nullptr, 0);
            break;
        case 'S':
            options->stack_limit = std::stoull(optarg, nullptr, 0);
            break;
        case 'R':
            options->root = optarg;
            break;
        case 'e': {
            std::string e(optarg);
            auto eq = e.find('=');
            if (eq == std::string::npos || eq == 0) {
                std::cerr << "Invalid -e argument: '" << optarg
                          << "' (expected KEY=VALUE)" << std::endl;
                print_usage(basename(argv[0]));
                return 1;
            }
            extra_envp.emplace(e.substr(0, eq), e.substr(eq + 1));
            break;
        }
        case 't':
            pty_mode = PtyMode::On;
            break;
        case 'T':
            pty_mode = PtyMode::Off;
            break;
        case 'g': {
            int p = std::stoi(optarg);
            if(p <= 0 || p > 65535) {
                std::cerr << "Invalid --gdb port: " << optarg << std::endl;
                print_usage(basename(argv[0]));
                return 1;
            }
            gdb_port = (uint16_t)p;
            break;
        }
        default:
            print_usage(basename(argv[0]));
            return 1;
        }
    }

    if (optind >= argc) {
        print_usage(basename(argv[0]));
        return 1;
    }

    // 创建 syscall handler；指定了 --root 则进入 chroot（cwd 重置为 /）。
    if(!options->root.empty()) {
        set_loader_root(options->root);
    }
    // ELF 路径解析：chroot 模式下 argv[optind] 是 guest 视角路径（如 /bin/dash），
    // 需拼上 root 前缀再解析为宿主路径；非 chroot 模式直接按宿主路径解析。
    const char* elf_file_path;
    if(!options->root.empty()) {
        auto elf_resolved_storage = std::filesystem::path(options->root + argv[optind]);
        elf_file_path = realpath(elf_resolved_storage.lexically_normal().c_str(), nullptr);
    } else {
        elf_file_path = realpath(argv[optind], nullptr);
    }
    if(elf_file_path == nullptr) {
        std::cerr << "Failed to resolve path: " << argv[optind] << std::endl;
        return 1;
    }
    // Pty 总是建：PTY 模式开真 pty（fd 0/1/2 接 slave）；非 PTY 模式退化为仅信号路由。
    // 两种模式都起 pump 线程读 signalfd 做 host 信号路由（见下 block）。
    bool use_pty = (pty_mode == PtyMode::On) ||
                   (pty_mode == PtyMode::Auto && isatty(STDIN_FILENO));
    options->pty = std::make_shared<Pty>();
    options->pty->setup(use_pty);

    auto vm = vm::create();
    // load_elf 从 envp 解析 LD_LIBRARY_PATH 做库搜索；extra_envp 是 map（key→value），
    // load_elf 直接消费，无需展平。
    ElfLoadInfo load_info = vm->load_elf(elf_file_path, extra_envp);
    if(load_info.entry == 0) {
        return 1;
    }

    struct sigaction sa = {};

    // Ignore SIGTRAP
    sa.sa_handler = SIG_IGN;
    sigaction(SIGTRAP, &sa, nullptr);

    // SIGUSR1 for internal wakeup (no SA_RESTART)
    sa.sa_handler = [](int) {};
    sigaction(SIGUSR1, &sa, nullptr);

    // 宿主侧信号进程级 block：block 后这些信号不走 sa_handler，内核排队到 signalfd
    sigset_t block_mask;
    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGINT);
    sigaddset(&block_mask, SIGQUIT);
    sigaddset(&block_mask, SIGTSTP);
    sigaddset(&block_mask, SIGHUP);
    sigaddset(&block_mask, SIGTERM);
    // PTY 模式额外 block SIGWINCH：pump 线程靠 signalfd 读 SIGWINCH 同步 pty 尺寸，
    // 须进程级 block（仅 pump 线程内 block 不够——信号会投给主线程/clone worker 走默认动作）。
    if(use_pty) sigaddset(&block_mask, SIGWINCH);
    sigprocmask(SIG_BLOCK, &block_mask, nullptr);

    // PTY 模式做字节转发 + 信号路由；非 PTY 模式仅信号路由。
    options->pty->start_pump(options->sys.get(), vm.get());
    options->entry = load_info.entry;
    options->argv.reserve(argc - optind);
    for(int i = optind; i < argc; i++) {
        options->argv.emplace_back(argv[i]);
    }
    // /proc 用的 exe 路径：经 vmOptions 传给 handler（PosixSyscall::init 消费）。
    // main 不感知具体 handler 实现，只填 options.exe；comm 由 PosixSyscall 自己派生。
    // elf_file_path 是 realpath(argv[optind])（宿主绝对路径）。guest 视角的 exe 应是
    // guest 能看到的路径：chroot 模式用 argv[optind]（如 /bin/dash），否则用 realpath。
    options->exe = options->root.empty()
                  ? (elf_file_path ? std::string(elf_file_path) : std::string(argv[optind]))
                  : std::string(argv[optind]);
    // HOME / PATH：chroot 模式下 guest 看到的是 root 内的路径（cwd=/），故 HOME 用 guest cwd，
    if(!options->root.empty()) {
        options->envp["HOME"] = "/";
        // argv[optind] 是 guest 视角路径，dirname 得其所在 guest 目录（如 /bin）。
        options->envp["PATH"] = dirname((char*)argv[optind]);
    } else {
        char* cwd = getcwd(nullptr, 0);
        options->envp["HOME"] = cwd;
        free(cwd);
        const char* dir = dirname((char*)elf_file_path);
        options->envp["PATH"] = dir;
    }
    for (const auto& [k, val] : extra_envp) {
        options->envp[k] = val;
    }
    umask(0);

    // --gdb：启动 GDB RSP server（独立线程，listen <gdb_port>，阻塞等 GDB 连接）。server 对象
    // 生命周期覆盖 run()；持 shared_ptr<vm> 保证 vm 在 server 线程访问期间存活。
    // JIT 的禁用由 per-vm 的 VM_DEBUG_ATTACHED flag 控制（GdbServer attach 时设置，detach 时清除），
    // 不再用全局 setenv——detach 后 JIT 可恢复，且不影响同进程其他 vm。
    std::unique_ptr<GdbServer> gdb_server;
    if(gdb_port != 0) {
        gdb_server = std::make_unique<GdbServer>(vm, gdb_port, load_info);
        gdb_server->start();
    }
    std::cout<<(int)vm->run(options.get(), load_info)<<std::endl;
    // _Exit 不跑析构，必须按依赖顺序手动释放，否则 PTY 模式下 termios 不恢复（终端留
    // 在 raw 模式）。顺序：先停 GDB server（join 线程）→ 释放 gdb_server（它持 shared_ptr<vm>，
    // 不先释放会让下面的 vm.reset 不析构）→ vm.reset（vm 析构释放其 options.pty 引用）
    // → options.reset（pty 引用计数归 0，~Pty 恢复 termios）。
    if(gdb_server) {
        gdb_server->stop();
        gdb_server.reset();
    }
    free((void*)elf_file_path);
    auto ret = vm->r(0);
    vm.reset();
    options.reset();
    _Exit(ret);
}
