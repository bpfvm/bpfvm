#include "insn.h"
#include "pty.h"
#include "gdb_server.h"
#include "posix/posix_syscall.h"

#include <iostream>

#include <libgen.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>


// --stop 标志：getopt_long 匹配到 --stop 时通过 flag 字段自动置 1，无需 switch case。
static int gdb_stop_flag = 0;

static struct option long_options[] = {
    {"verbose", no_argument, nullptr, 'v'},
    {"insn-limit", required_argument, nullptr, 'l'},
    {"stack-size", required_argument, nullptr, 'S'},
    {"root", required_argument, nullptr, 'R'},
    {"env", required_argument, nullptr, 'e'},
    {"pty", no_argument, nullptr, 't'},
    {"no-pty", no_argument, nullptr, 'T'},
    {"gdb", required_argument, nullptr, 'g'},
    {"stop", no_argument, &gdb_stop_flag, 1},
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
        << "  -g, --gdb <port>            start GDB RSP server on <port>\n"
        << "                              (VM runs at full speed; GDB attaches on connect)\n"
        << "      --stop                  with --gdb: freeze VM at start until GDB connects\n";
}

int real_main(int argc, char** argv) {
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
        case 0:
            // flag 字段置位的选项（如 --stop）：getopt_long 直接写变量、返回 0，无需处理。
            break;
        default:
            print_usage(basename(argv[0]));
            return 1;
        }
    }

    if (optind >= argc) {
        print_usage(basename(argv[0]));
        return 1;
    }

    // --stop 仅与 --gdb 搭配才有意义。
    if(gdb_stop_flag && gdb_port == 0) {
        std::cerr << "--stop requires --gdb <port>" << std::endl;
        print_usage(basename(argv[0]));
        return 1;
    }

    // 创建 syscall handler；指定了 --root 则进入 chroot（cwd 重置为 /）。
    if(!options->root.empty()) {
        set_loader_root(options->root);
    }
    // ELF 路径解析：chroot 模式下 argv[optind] 是 guest 视角路径（如 /bin/dash），需拼上
    // root 前缀得到宿主路径；非 chroot 模式 root 为空，拼接退化为 argv[optind] 本身。
    std::string elf_path;
    {
        char* resolved = realpath((options->root + argv[optind]).c_str(), nullptr);
        if(resolved == nullptr) {
            std::cerr << "Failed to resolve path: " << argv[optind] << std::endl;
            return 1;
        }
        elf_path = resolved;
        free(resolved);
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
    ElfLoadInfo load_info = vm->load_elf(elf_path.c_str(), extra_envp);
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
    options->argv.reserve(argc - optind);
    for(int i = optind; i < argc; i++) {
        options->argv.emplace_back(argv[i]);
    }
    // HOME / PATH：chroot 模式下 guest 看到的是 root 内的路径（cwd=/），故 HOME 用 guest cwd，
    if(!options->root.empty()) {
        options->envp["HOME"] = "/";
        // argv[optind] 是 guest 视角路径，dirname 得其所在 guest 目录（如 /bin）。
        options->envp["PATH"] = dirname((char*)argv[optind]);
    } else {
        char* cwd = getcwd(nullptr, 0);
        options->envp["HOME"] = cwd;
        free(cwd);
        // dirname 原地改写入参产出目录名；elf_path 在此后不再使用，原地破坏安全。
        options->envp["PATH"] = dirname(elf_path.data());
    }
    for (const auto& [k, val] : extra_envp) {
        options->envp[k] = val;
    }
    umask(0);

    // --gdb：启动 GDB RSP server（独立线程，listen <gdb_port>，阻塞等 GDB 连接）。server 对象
    // 生命周期覆盖 run()；持 shared_ptr<vm> 保证 vm 在 server 线程访问期间存活。
    // JIT 的禁用由 per-vm 的 VM_DEBUG_ATTACHED flag 控制（GdbServer attach 时设置，detach 时清除），
    // 不再用全局 setenv——detach 后 JIT 可恢复，且不影响同进程其他 vm。
    // gdb_stop_flag（--stop）：run() 前就 attach + 冻结主 vm，等 GDB 连上后 continue 才放行
    // （对齐 QEMU -S）；默认（不带 --stop）让主 vm 全速 JIT 跑，GDB 连上才 attach 停在当前 pc。
    std::unique_ptr<GdbServer> gdb_server;
    if(gdb_port != 0) {
        gdb_server = std::make_unique<GdbServer>(vm, gdb_port, gdb_stop_flag != 0);
        gdb_server->start();
    }
    return vm->run(options.get(), load_info);
}

int main(int argc, char** argv) {
    // 不跑析构：real_main 返回值即可代表程序退出码，main 直接 _Exit，跳过全局对象/静态
    // 析构，与旧实现行为一致。real_main 内部栈对象正常析构（PTY termios 恢复等已处理）。
    _Exit(real_main(argc, argv));
}
