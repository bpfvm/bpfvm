#include <iostream>
#include <algorithm>

#include <libgen.h>
#include <string.h>
#include <getopt.h>

#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>

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

    if (elf_version(EV_CURRENT) == EV_NONE) {
        std::cerr << "Failed to initialize libelf: " << elf_errmsg(-1) << std::endl;
        return 1;
    }
    int fd = open(elf_file_path, O_RDONLY);
    if(fd < 0) {
        std::cerr << "Failed to open: "<<elf_file_path<<": " << strerror(errno) << std::endl;
    }
    Elf* elf = elf_begin(fd, ELF_C_READ, NULL);
    if(elf == NULL) {
        std::cerr << "Failed to open ELF file: " << elf_errmsg(-1) << std::endl;
        return 1;
    }
    if(elf_kind(elf) != ELF_K_ELF) {
        std::cerr << "Not an ELF file" << std::endl;
        return 1;
    }
    GElf_Ehdr ehdr;
    if(gelf_getehdr(elf, &ehdr) != &ehdr) {
        std::cerr << "Failed to get ELF header: " << elf_errmsg(-1) << std::endl;
        return 1;
    }
    if(ehdr.e_type != ET_EXEC) {
        std::cerr << "Not an executable ELF file: " << ehdr.e_type << std::endl;
        return 1;
    }
    if(ehdr.e_machine != 0xf7) {
        std::cerr << "Not an bpf ELF file: "<<ehdr.e_machine << std::endl;
        return 1;
    }
    vm vm;
    for(size_t i = 0; i < ehdr.e_phnum; i++) {
        GElf_Phdr phdr;
        if(gelf_getphdr(elf, i, &phdr) != &phdr) {
            std::cerr << "Failed to get program header: " << elf_errmsg(-1) << std::endl;
            return 1;
        }
        if(phdr.p_type != PT_LOAD) {
            continue;
        }

        //std::cout << "Program header " << i << ":" << std::endl;
        //std::cout << "  Type: " << phdr.p_type << std::endl;
        //std::cout << "  Offset: " << phdr.p_offset << std::endl;
        //std::cout << "  Virtual Address: " << phdr.p_vaddr << std::endl;
        //std::cout << "  Physical Address: " << phdr.p_paddr << std::endl;
        //std::cout << "  File Size: " << phdr.p_filesz << std::endl;
        //std::cout << "  Memory Size: " << phdr.p_memsz << std::endl;
        //std::cout << "  Flags: " << phdr.p_flags << std::endl;
        //std::cout << "  Alignment: " << phdr.p_align << std::endl;
        memmap map;
        map.paddr = phdr.p_vaddr;
        map.size = phdr.p_memsz;
        if(phdr.p_flags & PF_W) {
            map.data = (unsigned char*)malloc(map.size);
            if(pread(fd, map.data, phdr.p_filesz, phdr.p_offset) != phdr.p_filesz) {
                std::cerr << "Failed to read section: " << strerror(errno) << std::endl;
                return 1;
            }
        }else {
            map.data = (unsigned char*)mmap(nullptr, map.size, PROT_READ, MAP_PRIVATE, fd, phdr.p_offset);
            if(map.data == MAP_FAILED) {
                std::cerr << "Failed to mmap section: " << strerror(errno) << std::endl;
                return 1;
            }
        }
        map.flags = phdr.p_flags;
        vm.addmem(std::move(map));
    }
    elf_end(elf);
    close(fd);

    signal(SIGTRAP, SIG_IGN);
    vm.r(1) = 10;
    vm.r(2) = 20;
    options.entry = ehdr.e_entry;
    std::cout<<(int)vm.run(&options)<<std::endl;
}
