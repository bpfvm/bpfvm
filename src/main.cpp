#include "insn.h"
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
    {nullptr, 0, nullptr, 0}
};

int main(int argc, char** argv) {
    vmOptions options;
    options.verbose = false; // 默认值
    options.breakpoint = 0;   // 默认值
    options.step_run = false; // 默认值
    options.raw_stack = false; // 默认值
    options.sys = std::make_shared<PosixSyscall>();

    int opt;
    while ((opt = getopt_long(argc, argv, "vb:sl:", long_options, nullptr)) != -1) {
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
        default:
            std::cerr << "Usage: " << basename(argv[0]) << " [-v] [-b breakpoint_address] [-s] [-l insn_limit] <elf-file>" << std::endl;
            return 1;
        }
    }

    if (optind >= argc) {
        std::cerr << "Usage: " << basename(argv[0]) << " [-v] [-b breakpoint_address] [-s] [-l insn_limit] <elf-file>" << std::endl;
        return 1;
    }

    const char* elf_file_path = realpath(argv[optind], nullptr);
    if(elf_file_path == nullptr) {
        std::cerr << "Failed to resolve path: " << argv[optind] << std::endl;
        return 1;
    }

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

    // Logical signals for the VM
    static class vm* g_vm = vm.get();
    static SyscallHandler* g_sys = options.sys.get();
    sa.sa_handler = [](int sig) {
        g_sys->queue_signal(g_vm, sig);
    };
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
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
    // 仅透传 BPF_ 开头的宿主环境变量（如 BPF_TEST_VARIANT、BPF_LIB_PATH），
    // 避免把宿主侧的敏感变量（TOKEN*、*_SECRET 等）泄漏进 guest envp。
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
