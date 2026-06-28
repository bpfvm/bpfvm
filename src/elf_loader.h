//
// elf_loader.h — BPF ELF 加载与库搜索公共逻辑
//
// ld_main（构建期 -l 解析）和 VM（运行期加载 ELF）共用。
//
// 搜索顺序：命令行 -L 目录 → BPF_LIB_PATH → 内置默认（libc/lib64, libc/lib, lib, .）
//
// load_elf 通过 std::function 回调把映射好的 memmap 交给调用方，
//

#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <sys/mman.h>
#include <vector>

// unique_ptr deleter：own=true 时 munmap；也用作 CoW 共享页的 deleter。
// 单一 `owned` flag 控制是否 munmap，两种角色用同一路径。
struct DataDeleter {
    size_t size = 0;
    bool owned = false;
    DataDeleter() = default;
    DataDeleter(size_t sz, bool own) : size(sz), owned(own) {}
    void operator()(unsigned char* p) {
        if (owned && p && p != (unsigned char*)MAP_FAILED)
            munmap(p, size);
    }
};

// guest 内存映射描述：paddr 是 guest 虚拟地址，data 指向 host mmap 区。
struct memmap {
    std::unique_ptr<unsigned char, DataDeleter> data{nullptr, DataDeleter{0, false}};
    size_t size = 0;
    uint64_t paddr = 0;
    uint32_t flags = 0;
    // non-null: CoW page shared across VMs; DataDeleter owns the actual munmap call.
    std::shared_ptr<unsigned char> cow_data;
    memmap() = default;
    memmap(memmap&&) = default;
    ~memmap() = default;
    void set_data(unsigned char* p, size_t sz, bool own = true) {
        data = std::unique_ptr<unsigned char, DataDeleter>(p, DataDeleter{sz, own});
    }
    static memmap static_map(void* addr, size_t size, uint64_t paddr);
};

// 在 extra_dirs + 默认路径里找 name（dir + "/" + name）。
// name 若是绝对路径或当前目录可直接访问的文件，原样返回。找不到返回空串。
std::string find_library(const std::vector<std::string>& extra_dirs, const std::string& name);

// 主程序加载结果：除入口地址外，还带 auxv 启动所需的信息（musl/glibc 的
// __init_tls 靠 AT_PHDR/AT_PHENT/AT_PHNUM/AT_ENTRY 定位 program headers 与 TLS）。
// entry 为 0 表示加载失败；phdr 为 0 表示主程序无 PT_PHDR（lib/动态链接器场景）。
struct ElfLoadInfo {
    uint64_t entry = 0;
    uint64_t phdr = 0;     // program header table 的运行时 guest 虚拟地址
    uint64_t phent = 0;    // 单个 program header 字节数（通常 56）
    uint64_t phnum = 0;    // program header 个数
};

// 加载 ELF（主程序 + DT_NEEDED 依赖的 .so），为每个 PT_LOAD 段构造 memmap
// 并通过 add 回调交给调用方（如 vm::addmem）。返回加载信息（entry 为 0 表失败）。
ElfLoadInfo load_elf(const char* path, std::function<void(memmap&&)> add);

#endif // ELF_LOADER_H
