#include "insn.h"
#include "pty.h"
#include "posix/posix_syscall.h"

#include <iostream>

#include <libgen.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>


static struct option long_options[] = {
    {"verbose", no_argument, nullptr, 'v'},
    {"breakpoint", required_argument, nullptr, 'b'},
    {"step", no_argument, nullptr, 's'},
    {"insn-limit", required_argument, nullptr, 'l'},
    {"stack-size", required_argument, nullptr, 'S'},
    {"pty", no_argument, nullptr, 't'},
    {"no-pty", no_argument, nullptr, 'T'},
    {nullptr, 0, nullptr, 0}
};

int main(int argc, char** argv) {
    vmOptions options;
    options.verbose = false; // 默认值
    options.breakpoint = 0;   // 默认值
    options.step_run = false; // 默认值
    options.raw_stack = false; // 默认值
    options.sys = std::make_shared<PosixSyscall>();

    // PTY 三态：默认 auto（stdin 是 tty 则开，贴近真实终端行为；管道/CI 下关，保持既有
    // 测试行为）；-t/--pty 强制开；-T/--no-pty 强制关（即便在真 tty 里也走纯透传 stdio）。
    enum class PtyMode { Auto, On, Off };
    PtyMode pty_mode = PtyMode::Auto;

    int opt;
    while ((opt = getopt_long(argc, argv, "vb:sl:S:tT", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'v':
            options.verbose = true;
            break;
        case 'b':
            options.breakpoint = std::stoul(optarg, nullptr, 0);
            break;
        case 's':
            options.step_run = true;
            break;
        case 'l':
            options.insn_limit = std::stoull(optarg, nullptr, 0);
            break;
        case 'S':
            options.stack_limit = std::stoull(optarg, nullptr, 0);
            break;
        case 't':
            pty_mode = PtyMode::On;
            break;
        case 'T':
            pty_mode = PtyMode::Off;
            break;
        default:
            std::cerr << "Usage: " << basename(argv[0]) << " [-v] [-b breakpoint_address] [-s] [-l insn_limit] [-S stack_size] [-t|--pty|-T|--no-pty] <elf-file>" << std::endl;
            return 1;
        }
    }

    if (optind >= argc) {
        std::cerr << "Usage: " << basename(argv[0]) << " [-v] [-b breakpoint_address] [-s] [-l insn_limit] [-S stack_size] [-t|--pty|-T|--no-pty] <elf-file>" << std::endl;
        return 1;
    }

    const char* elf_file_path = realpath(argv[optind], nullptr);
    if(elf_file_path == nullptr) {
        std::cerr << "Failed to resolve path: " << argv[optind] << std::endl;
        return 1;
    }
    // Pty 总是建：PTY 模式开真 pty（fd 0/1/2 接 slave）；非 PTY 模式退化为仅信号路由。
    // 两种模式都起 pump 线程读 signalfd 做 host 信号路由（见下 block）。
    bool use_pty = (pty_mode == PtyMode::On) ||
                   (pty_mode == PtyMode::Auto && isatty(STDIN_FILENO));
    auto pty = std::make_shared<Pty>();
    pty->setup(use_pty);
    options.pty = pty;

    auto vm = vm::create();
    ElfLoadInfo load_info = vm->load_elf(elf_file_path);
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
    options.pty->start_pump(options.sys.get(), vm.get());
    options.entry = load_info.entry;
    options.argv.reserve(argc - optind);
    for(int i = optind; i < argc; i++) {
        options.argv.emplace_back(argv[i]);
    }
    char* cwd = getcwd(nullptr, 0);
    options.envp.emplace_back(std::string("HOME=") + cwd);
    free(cwd);
    const char* dir = dirname((char*)elf_file_path);
    options.envp.emplace_back(std::string("PATH=") + dir);
    // 透传 LD_LIBRARY_PATH 给 guest：bpfvm 自身（elf_loader）和 guest ldso 都用它搜库，
    if (const char* lp = getenv("LD_LIBRARY_PATH")) {
        options.envp.emplace_back(std::string("LD_LIBRARY_PATH=") + lp);
    }
    // 透传 BPF_ 开头的宿主环境变量（如 BPF_TEST_VARIANT），
    extern char **environ;
    for (char **e = environ; *e; e++) {
        std::string s(*e);
        if (s.rfind("BPF_", 0) == 0) options.envp.emplace_back(s);
    }
    umask(0);
    std::cout<<(int)vm->run(&options, load_info)<<std::endl;
    free((void*)elf_file_path);
    return vm->r(0);
}
