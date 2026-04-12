#include "insn.h"
#include "posix_syscall.h"

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
    while ((opt = getopt_long(argc, argv, "vb:s", long_options, nullptr)) != -1) {
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
        default:
            std::cerr << "Usage: " << basename(argv[0]) << " [-v] [-b breakpoint_address] [-s] <elf-file>" << std::endl;
            return 1;
        }
    }

    if (optind >= argc) {
        std::cerr << "Usage: " << basename(argv[0]) << " [-v] [-b breakpoint_address] [-s] <elf-file>" << std::endl;
        return 1;
    }
    const char* elf_file_path = realpath(argv[optind], nullptr);
    if(elf_file_path == nullptr) {
        std::cerr << "Failed to resolve path: " << argv[optind] << std::endl;
        return 1;
    }

    auto vm = vm::create();
    uint64_t entry = vm->load_elf(elf_file_path);
    if(entry == 0) {
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
    options.entry = entry;
    options.argv.reserve(argc - optind);
    for(int i = optind; i < argc; i++) {
        options.argv.emplace_back(argv[i]);
    }
    char* cwd = getcwd(nullptr, 0);
    options.envp.emplace_back(std::string("HOME=") + cwd);
    free(cwd);
    const char* dir = dirname((char*)elf_file_path);
    options.envp.emplace_back(std::string("PATH=") + dir);
    umask(0);
    std::cout<<(int)vm->run(&options)<<std::endl;
    free((void*)elf_file_path);
    return vm->r(0);
}
