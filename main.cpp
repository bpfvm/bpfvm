#include <iostream>
#include <algorithm>

#include <libgen.h>
#include <string.h>
#include <getopt.h>

#include <signal.h>

#include "insn.h"

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
    const char* elf_file_path = argv[optind];

    std::unordered_map<int, std::shared_ptr<fd_handle>> fd_table;
    fd_table.emplace(0, std::make_shared<fd_handle>(0));
    fd_table.emplace(1, std::make_shared<fd_handle>(1));
    fd_table.emplace(2, std::make_shared<fd_handle>(2));
    auto vm = vm::create(0, fd_table);
    uint64_t entry = vm->load_elf(elf_file_path);
    if(entry == 0) {
        return 1;
    }

    signal(SIGTRAP, SIG_IGN);
    options.entry = entry;
    options.argv.reserve(argc - optind);
    for(int i = optind; i < argc; i++) {
        options.argv.emplace_back(argv[i]);
    }
    extern char **environ;
    if(environ != nullptr) {
        for(size_t i = 0; environ[i] != nullptr; i++) {
            options.envp.emplace_back(environ[i]);
        }
    }
    std::cout<<(int)vm->run(&options)<<std::endl;
}
