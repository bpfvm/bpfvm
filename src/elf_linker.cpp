//
// elf_linker.cpp — BPF 离线链接器核心（bpfvm-ld 专用）
//
// Linker 类把多个 .o/archive 合并到一个
// 连续 host pool，应用重定位，导出 ET_EXEC ELF（静态）或带 DT_NEEDED 的动态产物。
// VM 端的加载（含 DT_NEEDED 动态加载）统一在 elf_loader.cpp 的 load_elf 处理。
//
// 流程：
//   1. 加载主 .o：解析所有 section、符号、重定位。
//   2. 依赖来自命令行 -l archive（由 ld_main 解析为完整路径），全展开。
//   3. 聚合所有 GLOBAL 符号到全局符号表。
//   4. 应用所有重定位（R_BPF_64_64 / R_BPF_64_ABS64 / R_BPF_64_32 / R_BPF_64_NODYLD32）。
//   5. 找入口（_start / main），写出 ET_EXEC。
//
// 简化：
//   - archive 全加载（不做按需提取）
//   - 依赖路径由 ld_main 的 -L/-l 解析为完整路径传入（本文件不做搜索）
//   - 不处理 weak 符号优先级
//

#include "elf_linker.h"

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <set>
#include <optional>
#include <cstring>
#include <cctype>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <libelf.h>
#include <gelf.h>

namespace {

// section 所属的输出段：按 SHF_EXECINSTR/SHF_WRITE 分流到 R-X / R-- / RW- 三个 PT_LOAD
enum SegClass : uint8_t { SEG_TEXT, SEG_RODATA, SEG_DATA };

// 单个 PLT 桩的字节大小（lddw + ldx，与 emit_plt_stub 输出一致）。
// 运行期加载器（elf_loader.cpp）也用同一定值定位 PLT 桩。
constexpr size_t kPltStubSize = 40;

// 后缀匹配（按扩展名分流输入文件类型时用）
bool ends_with(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() &&
           s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

// 单个加载后的 section
struct LoadedSection {
    std::string name;
    uint64_t guest_addr = 0;   // 加载到 VM 内的地址（layout_segments 后按所在段计算）
    size_t offset = 0;         // 在 host pool 内的偏移（相对 obj.host_mem；.bss 指向段尾之后）
    size_t size = 0;
    Elf64_Word type = 0;
    bool writable = false;
    bool executable = false;
    SegClass seg = SEG_RODATA;
    bool loadable = false;     // PROGBITS 或 NOBITS（.bss）
};

// 符号
struct LoadedSym {
    std::string name;
    size_t sec_idx = SIZE_MAX;  // 所属 section 在 LoadedObject::sections 的下标；UND → SIZE_MAX
    uint64_t value = 0;         // section 内偏移
    uint64_t size = 0;
    int binding = 0;
    int type = 0;
    bool defined = false;       // sec_idx != SIZE_MAX
};

// 重定位
struct LoadedReloc {
    size_t target_sec;          // 要 patch 的 section 下标
    uint64_t offset;            // 在该 section 内的偏移
    int type;
    size_t sym_idx;             // LoadedObject::symbols 下标
    int64_t addend = 0;         // SHT_RELA: 来自 r_addend；SHT_REL: 加载时从 patch 点读取
};

// 加载后的 .o
struct LoadedObject {
    std::string source;         // 路径或 "archive:member"
    std::vector<LoadedSection> sections;
    std::vector<LoadedSym> symbols;
    std::vector<LoadedReloc> relocations;
    uint64_t base = 0;          // 该 .o 在 VM 内的加载基址
    size_t pool_offset = 0;     // 在 Linker::pool_ 里的偏移
    size_t total_size = 0;      // 在 pool 里占用的字节数
    unsigned char* host_mem = nullptr;  // 指向 pool_ + pool_offset（不拥有）
    size_t host_mem_size = 0;
};

// 全局符号表
struct GlobalSymbol {
    size_t obj_idx;
    size_t sym_idx;
};

// 写 ELF 时构建的非段 section（symtab/strtab/dyn*/interp/shstrtab）
struct SecBuf {
    std::string name;
    Elf64_Word type = 0;
    Elf64_Xword flags = 0;
    std::vector<uint8_t> data;
    Elf64_Word link = 0;
    Elf64_Word info = 0;
    Elf64_Xword addralign = 1;
    Elf64_Xword entsize = 0;
};

// build_dynamic_sections 的输出：6 个动态相关 section 在 extras[] 的索引
struct DynSecOut {
    size_t dynstr_idx = SIZE_MAX;
    size_t dynsym_idx = SIZE_MAX;
    size_t hash_idx = SIZE_MAX;
    size_t reladyn_idx = SIZE_MAX;
    size_t relaplt_idx = SIZE_MAX;
    size_t dynamic_idx = SIZE_MAX;
    size_t dynamic_sym_off = SIZE_MAX;  // _DYNAMIC 符号在 .dynsym 数据中的字节偏移（st_value 字段），SIZE_MAX=未合成
};

// compute_file_layout 的输出：ELF 文件布局的关键尺寸/偏移
struct FileLayout {
    Elf64_Half phnum = 0;
    Elf64_Half shnum = 0;
    Elf64_Half shstrndx = 0;
    bool has_phdr = false;          // DYNAMIC_EXE: 是否生成 PT_PHDR 条目
    uint64_t seg_data_off = 0;     // 段数据区在文件中的起点（页对齐）
    uint64_t sh_off = 0;           // section header 表在文件中的偏移
    uint64_t seg_file_off[3] = {0, 0, 0};  // text/rodata/data 段的文件 offset
    std::vector<uint64_t> extra_offs;       // 每个 extra section 的文件 offset
};

// build_shstrtab 的输出：shstrtab 自身索引 + 各 section 名在 shstrtab 中的 offset
struct ShstrtabOut {
    size_t shstrtab_idx = SIZE_MAX;
    Elf64_Word text_name_off = 0;
    Elf64_Word plt_name_off = 0;
    Elf64_Word rodata_name_off = 0;
    Elf64_Word data_name_off = 0;
    Elf64_Word gotplt_name_off = 0;
    Elf64_Word bss_name_off = 0;
    std::vector<Elf64_Word> extra_name_offs;  // 与 extras 一一对应
};

// ELF section 名 → 是否需要加载到 VM
bool is_loadable_section(Elf64_Word type) {
    return type == SHT_PROGBITS || type == SHT_NOBITS;
}

// 按 section 属性分流到输出段：可写（含 .bss）→ data；可执行 → text；只读 → rodata。
// 可写优先于可执行：W^X 要求代码不可写，即便异常地同时带 EXECINSTR|WRITE 也归 data。
SegClass classify_section(bool executable, bool writable) {
    if (writable) return SEG_DATA;
    if (executable) return SEG_TEXT;
    return SEG_RODATA;
}

// 判断 section 是否需要跳过（调试信息等）
bool is_debug_section(const std::string& name) {
    if (name.empty()) return false;
    if (name.rfind(".debug", 0) == 0) return true;
    if (name.rfind(".rel.debug", 0) == 0) return true;
    if (name == ".BTF" || name == ".BTF.ext") return true;
    if (name.rfind(".rel.BTF", 0) == 0) return true;
    if (name == ".llvm_addrsig") return true;
    return false;
}

// 各重定位类型在 patch 点写入的字节数（用于越界校验）
size_t reloc_write_len(int type) {
    switch (type) {
    case 1:  return 16;  // R_BPF_64_64   (lddw 双槽，imm @ +4/+12)
    case 2:  return 8;   // R_BPF_64_ABS64
    case 10: return 8;   // R_BPF_64_32   (call 8B，imm @ +4)
    case 4:  return 4;   // R_BPF_64_NODYLD32
    default: return 0;   // 未知/不写入
    }
}

// SHT_REL 的 addend 嵌入在 patch 点原值里，按重定位类型读取。
// SHT_RELA 不调用本函数（addend 在 Elf64_Rela::r_addend 里）。
// type 10 (call) 的 imm 是 clang 占位符（-1），非真实 addend，返回 0。
int64_t read_embedded_addend(const unsigned char* patch, int type) {
    switch (type) {
    case 1: {  // R_BPF_64_64 lddw: lo imm @ +4, hi imm @ +12
        int32_t lo = 0, hi = 0;
        memcpy(&lo, patch + 4, 4);
        memcpy(&hi, patch + 12, 4);
        return ((int64_t)hi << 32) | (uint32_t)lo;
    }
    case 2: {  // R_BPF_64_ABS64: 8 字节
        int64_t a = 0;
        memcpy(&a, patch, 8);
        return a;
    }
    case 4: {  // R_BPF_64_NODYLD32: 4 字节
        int32_t a = 0;
        memcpy(&a, patch, 4);
        return a;
    }
    default:  // type 10 (call) 等：无 embedded addend
        return 0;
    }
}

// 标准 SysV ELF hash 函数（用于 .hash section 的符号查找）
uint32_t elf_hash(const char* name) {
    uint32_t h = 0, g;
    while (*name) {
        h = (h << 4) + (uint8_t)*name++;
        g = h & 0xf0000000;
        if (g) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

#ifndef ELF64_R_INFO
#define ELF64_R_INFO(sym, type) (((uint64_t)(sym) << 32) + (uint64_t)(type))
#endif

// 进度日志统一由 BPF_DEBUG 守护（错误信息仍无条件输出）
static const bool g_debug = getenv("BPF_DEBUG") != nullptr;

// 让 file/readelf 把 DYNAMIC_EXE 产物识别为 PIE 可执行的关键标志：
//   file 源码 dodynamic() 看 DT_FLAGS_1 的 DF_1_PIE 位决定 "pie executable" vs "shared object"
//   （PT_INTERP 只用于显示 "interpreter /xxx"，不参与 PIE 判定）
#ifndef DT_FLAGS_1
#define DT_FLAGS_1 0x6ffffffb
#endif
#ifndef DF_1_PIE
#define DF_1_PIE 0x08000000
#endif

// AR archive 解包（GNU/System V 风格）
struct ArMember {
    std::string name;
    const uint8_t* data;
    size_t size;
};

bool parse_archive(const uint8_t* data, size_t size, std::vector<ArMember>& out) {
    const char magic[8] = {'!', '<', 'a', 'r', 'c', 'h', '>', '\n'};
    if (size < 8 || memcmp(data, magic, 8) != 0) return false;

    const uint8_t* p = data + 8;
    const uint8_t* end = data + size;
    std::string long_names;

    while (p + 60 <= end) {
        // header layout (60 bytes):
        //   name[16], mtime[12], uid[6], gid[6], mode[8], size[10], fmag[2]("\n")
        std::string raw_name((const char*)p, 16);
        std::string size_str((const char*)p + 48, 10);
        if (memcmp(p + 58, "`\n", 2) != 0) break;

        // 去掉 size_str 尾部空格
        while (!size_str.empty() && isspace(size_str.back())) size_str.pop_back();
        size_t member_size = 0;
        try {
            member_size = std::stoul(size_str);
        } catch (...) { break; }

        const uint8_t* member_data = p + 60;
        if (member_data + member_size > end) break;

        // 解析名字
        std::string name;
        if (raw_name[0] == '/') {
            if (raw_name[1] == '/') {
                // // long name table
                long_names.assign((const char*)member_data, member_size);
            } else if (raw_name[1] >= '0' && raw_name[1] <= '9') {
                // /N long name reference
                size_t off = 0;
                try { off = std::stoul(raw_name.substr(1, 15)); } catch (...) {}
                if (off < long_names.size()) {
                    size_t end_off = off;
                    while (end_off < long_names.size() && long_names[end_off] != '/' && long_names[end_off] != '\n')
                        end_off++;
                    name = long_names.substr(off, end_off - off);
                }
                out.push_back({name, member_data, member_size});
            }
            // else: "/" 单独 = symbol index, 跳过
        } else {
            // 普通名字，以 '/' 结尾（System V 风格）
            size_t slash = raw_name.find('/');
            name = (slash == std::string::npos) ? raw_name : raw_name.substr(0, slash);
            // 去尾部空格
            while (!name.empty() && isspace(name.back())) name.pop_back();
            if (!name.empty()) {
                out.push_back({name, member_data, member_size});
            }
        }

        // 下一个成员（对齐 2 字节）
        p = member_data + member_size;
        if ((reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(data)) & 1) p++;
    }
    return true;
}

// 读整个文件到内存（archive 文件用）
bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streampos sz = f.tellg();
    if (sz < 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(sz);
    if (sz > 0) f.read((char*)out.data(), sz);
    return f.good() || f.eof();
}

class Linker {
public:
    enum class Mode {
        STATIC_EXE,   // 输入 .o + 命令行 -l archive，输出完全自包含的 ET_EXEC
        SHARED_LIB,   // -shared：输入 .a/.o，输出 .so（ET_DYN + .dynsym 导出表 + DT_SONAME，PIE）
        DYNAMIC_EXE,  // 默认：输入 .o + -l .so，输出 PIE ET_DYN + DT_NEEDED
    };

private:
    unsigned char* pool_ = nullptr;
    size_t pool_size_ = 64 * 1024 * 1024;  // 固定 64MB 池子
    size_t pool_used_ = 0;
    uint64_t guest_base_;  // STATIC_EXE 固定地址；SHARED_LIB/DYNAMIC_EXE 为 0（PIE，运行时分配）
    uint64_t entry_ = 0;
    Mode mode_;
    std::string soname_;                // SHARED_LIB: DT_SONAME
    std::string entry_name_ = "_start"; // 入口符号名（对齐标准 ld -e，默认 _start）
    std::vector<std::string> needed_;   // DYNAMIC_EXE: DT_NEEDED soname 列表
    std::vector<std::string> dep_paths_;// DYNAMIC_EXE: .so 文件路径列表
    // === 运行时 GOT/PLT 合成状态（DYNAMIC_EXE 默认对所有 UND 函数启用）===
    struct GotPltLoc { size_t obj_idx; size_t offset; };
    std::unordered_map<std::string, GotPltLoc> got_slots_;   // sym → GOT 槽（合成 .got 内偏移）
    std::unordered_map<std::string, GotPltLoc> plt_entries_; // sym → PLT 桩（合成 .plt 内偏移）
    std::unordered_map<std::string, uint64_t> plt_addr_;     // sym → 桩 guest_addr（layout 后回填）
    bool got_enabled_ = false;
    size_t got_obj_idx_ = SIZE_MAX;  // 合成 .got.plt 的 obj idx（DT_PLTGOT 指向它）
    size_t plt_obj_idx_ = SIZE_MAX;  // 合成 .plt 的 obj idx（运行时按 section 名定位）
    std::vector<std::string> got_syms_;  // PLT/GOT 符号顺序（.rela.plt 按此顺序生成）
    std::vector<std::string> explicit_archives_;  // STATIC_EXE: 命令行 -l archive（完整路径）
    std::vector<LoadedObject> objects_;
    std::unordered_map<std::string, GlobalSymbol> globals_;

    // 3 段布局结果（layout_segments 填充，write_elf 使用）
    struct SegInfo {
        bool used = false;
        uint64_t vaddr = 0;
        uint64_t filesz = 0;   // PROGBITS 字节（含段内 8 字节对齐 padding）
        uint64_t memsz = 0;    // 含 .bss
        uint32_t flags = 0;    // PF_R|PF_X / PF_R / PF_R|PF_W
        uint64_t file_off = 0; // 在输出文件中的起点 offset
        std::vector<std::pair<size_t,size_t>> secs;  // 段内 section (obj_idx, sec_idx)，按 guest 顺序
    };
    SegInfo segs_[3];

public:
    // STATIC_EXE 用 fixed_base（默认 0x40000000）；SHARED_LIB/DYNAMIC_EXE 传 0（PIE）
    explicit Linker(Mode mode = Mode::STATIC_EXE, uint64_t fixed_base = 0x40000000ULL)
        : guest_base_(mode == Mode::STATIC_EXE ? fixed_base : 0), mode_(mode) {
        pool_ = (unsigned char*)mmap(nullptr, pool_size_, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pool_ == MAP_FAILED) {
            std::cerr << "[elf_linker] pool mmap failed\n";
            pool_ = nullptr;
        }
    }
    ~Linker() {
        if (pool_) {
            munmap(pool_, pool_size_);
            pool_ = nullptr;
        }
    }
    Linker(const Linker&) = delete;
    Linker& operator=(const Linker&) = delete;

    void set_soname(const std::string& s) { soname_ = s; }
    void set_entry_name(const std::string& e) { entry_name_ = e; }
    void set_needed(std::vector<std::string> n) { needed_ = std::move(n); }
    void set_deps(std::vector<std::string> d) { dep_paths_ = std::move(d); }
    void set_archives(std::vector<std::string> a) { explicit_archives_ = std::move(a); }

    // 按扩展名加载一个输入：.a→归档(全展开)、.so→动态符号(读 dynsym+DT_NEEDED)、.o(及其它)→目标文件
    bool load_input(const std::string& in) {
        if (ends_with(in, ".a")) { load_archive_file(in); return true; }
        if (ends_with(in, ".so")) { return load_bpfso_symbols(in); }
        return load_rel_file(in) != SIZE_MAX;
    }

    // 执行链接
    bool run(const std::vector<std::string>& inputs) {
        if (!pool_) return false;

        if (elf_version(EV_CURRENT) == EV_NONE) {
            std::cerr << "[elf_linker] libelf init failed\n";
            return false;
        }

        if (mode_ == Mode::STATIC_EXE) {
            // 静态：加载所有输入（.o/.a，按类型分流）
            for (const auto& in : inputs) {
                if (!load_input(in)) {
                    std::cerr << "[elf_linker] failed to load: " << in << "\n";
                    return false;
                }
            }
            // 依赖来自命令行 -l（由 ld_main 解析为完整路径）
            for (const auto& path : explicit_archives_) {
                load_archive_file(path);
            }
        } else if (mode_ == Mode::SHARED_LIB) {
            // 加载依赖 .so 作为符号提供者（UND 符号由 loader 运行时解析，
            // 这里加载只为读 DT_SONAME → needed_，从而输出 DT_NEEDED）。
            for (const auto& dep : dep_paths_) {
                if (!load_bpfso_symbols(dep)) {
                    std::cerr << "[elf_linker] failed to load dep: " << dep << "\n";
                    return false;
                }
            }
            // 库：加载所有输入（.a/.o/.so，按类型分流）
            for (const auto& in : inputs) {
                if (!load_input(in)) {
                    std::cerr << "[elf_linker] failed to load: " << in << "\n";
                    return false;
                }
            }
        } else if (mode_ == Mode::DYNAMIC_EXE) {
            // 动态主程序：依赖按扩展名分流（对齐标准 ld 行为）——
            //   .a → 静态拉入归档成员（符号进 globals_，调用按内部相对 call 解析）；
            //   .o → 当作附加对象静态链入；
            //   .so → 动态依赖（只读 dynsym + DT_NEEDED，跨模块调用走 PLT/GOT）。
            // 再加载主 .o。
            for (const auto& dep : dep_paths_) {
                if (ends_with(dep, ".a")) {
                    load_archive_file(dep);
                } else if (ends_with(dep, ".o")) {
                    if (load_rel_file(dep) == SIZE_MAX) {
                        std::cerr << "[elf_linker] failed to load dep: " << dep << "\n";
                        return false;
                    }
                } else if (!load_bpfso_symbols(dep)) {
                    std::cerr << "[elf_linker] failed to load dep: " << dep << "\n";
                    return false;
                }
            }
            // 加载所有输入（.o/.a/.so，按类型分流）
            for (const auto& in : inputs) {
                if (!load_input(in)) {
                    std::cerr << "[elf_linker] failed to load: " << in << "\n";
                    return false;
                }
            }
        }

        // 注册全局符号（须在 synthesize_got_plt 前，让 DYNAMIC_EXE 的入口符号
        // 主程序是否已定义的判断生效；合成 .got/.plt 无 symbol，对 register 无影响）
        for (size_t i = 0; i < objects_.size(); i++) {
            register_globals(i);
        }

        // 校验未定义符号（static + dynamic；shared 允许导出 UND 给消费者，跳过）。
        // UND 符号必须由 .o/.a（globals_）或 .so（bpfso_symbols_）提供，否则报错（对齐标准 ld）。
        if (mode_ != Mode::SHARED_LIB && !check_undefined_symbols()) return false;

        // 运行时 GOT/PLT 合成（DYNAMIC_EXE + SHARED_LIB 默认对所有 UND 函数）：
        // BPF call 是相对偏移，跨模块调用必须经 PLT/GOT 间接（callx）。
        // 主程序和 .so 各有自己的 PLT/GOT，供内部对 UND 函数的调用用。
        if ((mode_ == Mode::DYNAMIC_EXE || mode_ == Mode::SHARED_LIB) && !synthesize_got_plt()) return false;

        // 全局 3 段布局：分配 guest vaddr（必须在 apply_relocations 前，重定位读 guest_addr）
        layout_segments();

        // layout 后 .got/.plt 的 guest_addr 已定：回填 PLT 桩字节码（lddw imm = GOT 槽地址）
        if (got_enabled_ && !finalize_plt_stubs()) return false;

        // 应用重定位
        for (size_t i = 0; i < objects_.size(); i++) {
            if (!apply_relocations(i)) {
                std::cerr << "[elf_linker] relocations failed for " << objects_[i].source << "\n";
                return false;
            }
        }

        // 找入口（对齐标准 ld：默认 _start，支持 -e 指定；找不到告警不 fatal）。
        // SHARED_LIB 不需要 entry（保持 0）。
        // STATIC_EXE: entry 符号在主程序 globals_ 里。
        // DYNAMIC_EXE: entry 符号（_start）通常在 .so，主程序通过 PLT/GOT 调用；
        //   entry_ 指向主程序 PLT 里 _start 的桩（相对主程序基址的偏移，PIE）。
        if (mode_ != Mode::SHARED_LIB) {
            // 1. 主程序内的全局符号（STATIC_EXE 的 _start，或 DYNAMIC_EXE 主程序自带入口）
            auto it = globals_.find(entry_name_);
            if (it != globals_.end()) {
                const auto& obj = objects_[it->second.obj_idx];
                const auto& sym = obj.symbols[it->second.sym_idx];
                const auto& sec = obj.sections[sym.sec_idx];
                entry_ = sec.guest_addr + sym.value;
                if (g_debug) std::cerr << "[elf_linker] entry: " << entry_name_
                          << " @ 0x" << std::hex << entry_ << std::dec
                          << " from " << obj.source << "\n";
            } else if (mode_ == Mode::DYNAMIC_EXE) {
                // 2. DYNAMIC_EXE：_start 在 .so，走 PLT/GOT，entry 指向 PLT 桩
                auto pit = plt_addr_.find(entry_name_);
                if (pit != plt_addr_.end()) {
                    entry_ = pit->second;
                    if (g_debug) std::cerr << "[elf_linker] entry: " << entry_name_
                              << " @ 0x" << std::hex << entry_ << std::dec
                              << " (PLT stub)\n";
                } else {
                    std::cerr << "[elf_linker] warning: entry symbol '" << entry_name_
                              << "' not found; e_entry will be 0\n";
                }
            } else {
                std::cerr << "[elf_linker] warning: entry symbol '" << entry_name_
                          << "' not found; e_entry will be 0\n";
            }
        }
        return true;
    }

    // 全局 3 段布局：把所有 object 的 loadable section 按 SEG_TEXT/RODATA/DATA 分流到
    // 三个 PT_LOAD，分配 guest vaddr（每段页对齐、互不重叠），更新 ls.guest_addr。
    // host pool 布局保持不变（section 数据仍在 load 时的位置）；输出时按段拼接。
    // .bss(NOBITS) 排在 data 段 PROGBITS 之后，不占 filesz，只计入 memsz。
    void layout_segments() {
        for (int c = 0; c < 3; c++) segs_[c] = SegInfo{};
        // 分桶（保持 object/section 出现顺序 → 段内顺序稳定）
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            for (size_t si = 1; si < objects_[oi].sections.size(); si++) {
                LoadedSection& ls = objects_[oi].sections[si];
                if (!ls.loadable) continue;
                segs_[ls.seg].secs.push_back({oi, si});
            }
        }
        segs_[SEG_TEXT].flags   = PF_R | PF_X;
        segs_[SEG_RODATA].flags = PF_R;
        segs_[SEG_DATA].flags   = PF_R | PF_W;

        auto align8 = [](uint64_t v){ return (v + 7) & ~7ULL; };
        // 每段分两遍布局：先 PROGBITS（决定 filesz），再 NOBITS(.bss) 排在其后（仅计 memsz）。
        // 不能单遍交替——否则 .bss 在 .data 之前处理时 progbits_end 还没累加到最终值，
        // .bss 的 guest 地址会落进 PROGBITS 区，运行时被 .data 数据覆盖。
        for (int c = 0; c < 3; c++) {
            SegInfo& s = segs_[c];
            uint64_t pe = 0;
            for (auto& pr : s.secs) {  // 第一遍：PROGBITS
                LoadedSection& ls = objects_[pr.first].sections[pr.second];
                if (ls.type == SHT_NOBITS) continue;
                pe = align8(pe);
                ls.guest_addr = pe;          // 暂存段内偏移
                pe += ls.size;
            }
            s.filesz = pe;
            uint64_t bss = 0;
            for (auto& pr : s.secs) {  // 第二遍：NOBITS，紧接 PROGBITS 之后
                LoadedSection& ls = objects_[pr.first].sections[pr.second];
                if (ls.type != SHT_NOBITS) continue;
                bss = align8(bss);
                ls.guest_addr = pe + bss;    // 暂存段内偏移（在 filesz 之外）
                bss += ls.size;
            }
            s.memsz = pe + bss;
            s.used = !s.secs.empty();
        }
        // vaddr 链式分配（页对齐，跳过空段）
        // 可执行文件（STATIC_EXE + DYNAMIC_EXE）首段从 guest_base_+0x1000 开始预留 vaddr：
        // 给 ELF header + phdr table（文件 offset [0, 0x1000)）让出位置。write_phdrs 会把
        // 首段 p_offset 扩展到 0、p_vaddr 减 0x1000，让 phdr 表（vaddr 64）被首段 LOAD 覆盖
        //（供 PT_PHDR），且模块从 guest_base_ 起、offset≡vaddr 严格成立。
        //（SHARED_LIB 是 .so 无 PT_PHDR 需求，从 guest_base_ 起。）
        uint64_t cur = guest_base_;
        if (mode_ != Mode::SHARED_LIB) cur += 0x1000;
        for (int c = 0; c < 3; c++) {
            if (!segs_[c].used) continue;
            segs_[c].vaddr = cur;
            cur = (cur + segs_[c].memsz + 0xFFF) & ~0xFFFULL;
        }
        // 加 vaddr 得到最终 guest_addr
        for (int c = 0; c < 3; c++) {
            for (auto& pr : segs_[c].secs) {
                objects_[pr.first].sections[pr.second].guest_addr += segs_[c].vaddr;
            }
        }
        if (g_debug) {
            std::cerr << "[elf_linker] segments:";
            for (int c = 0; c < 3; c++) {
                if (!segs_[c].used) continue;
                const char* nm = c == SEG_TEXT ? "text" : (c == SEG_RODATA ? "rodata" : "data");
                std::cerr << " " << nm << "@0x" << std::hex << segs_[c].vaddr << "+0x"
                          << segs_[c].filesz << "/0x" << segs_[c].memsz << std::dec;
            }
            std::cerr << "\n";
        }
    }

    uint64_t entry() const { return entry_; }

    bool write_elf(const std::string& path) const {
        if (!pool_ || pool_used_ == 0) return false;

        FILE* f = fopen(path.c_str(), "wb");
        if (!f) {
            std::cerr << "[elf_linker] cannot write " << path << ": " << strerror(errno) << "\n";
            return false;
        }
        bool ok = write_elf_impl(f);
        fclose(f);
        if (ok) chmod(path.c_str(), 0755);  // 输出是可执行文件，设执行位（对齐 bpf-ld；build 脚本按 perm 识别）
        return ok;
    }

private:
    // .so 提供的符号表（DYNAMIC_EXE 模式用）：symbol name → 已固定地址
    std::unordered_map<std::string, uint64_t> bpfso_symbols_;
    // 从文件加载一个 ET_REL .o
    size_t load_rel_file(const std::string& path) {
        std::vector<uint8_t> data;
        if (!read_file(path, data)) return SIZE_MAX;
        return load_rel_memory(data.data(), data.size(), path);
    }

    // 从内存加载一个 .o（主文件和 archive 成员都用这个）
    size_t load_rel_memory(const uint8_t* data, size_t size, const std::string& name) {
        Elf* elf = elf_memory((char*)data, size);
        if (!elf) {
            std::cerr << "[elf_linker] elf_memory failed for " << name
                      << ": " << elf_errmsg(-1) << "\n";
            return SIZE_MAX;
        }
        if (elf_kind(elf) != ELF_K_ELF) {
            std::cerr << "[elf_linker] not ELF_K_ELF: " << name << "\n";
            elf_end(elf);
            return SIZE_MAX;
        }
        GElf_Ehdr ehdr;
        if (gelf_getehdr(elf, &ehdr) != &ehdr) {
            std::cerr << "[elf_linker] gelf_getehdr failed for " << name
                      << ": " << elf_errmsg(-1) << "\n";
            elf_end(elf);
            return SIZE_MAX;
        }
        if (ehdr.e_type != ET_REL) {
            elf_end(elf);
            return SIZE_MAX;
        }

        LoadedObject obj;
        obj.source = name;

        // ELF section 0 是 NULL，占位保持 sections[] 下标和 ELF section index 对齐
        LoadedSection null_sec;
        null_sec.type = SHT_NULL;
        null_sec.loadable = false;
        obj.sections.push_back(null_sec);

        // 第一遍：列出所有 section 信息（暂不计算 total_size）
        Elf_Scn* scn = nullptr;
        size_t shstrndx = 0;
        elf_getshdrstrndx(elf, &shstrndx);

        while ((scn = elf_nextscn(elf, scn)) != nullptr) {
            GElf_Shdr shdr;
            gelf_getshdr(scn, &shdr);
            LoadedSection ls;
            ls.type = shdr.sh_type;
            char* nm = elf_strptr(elf, shstrndx, shdr.sh_name);
            ls.name = nm ? nm : "";
            ls.size = shdr.sh_size;
            ls.loadable = is_loadable_section(shdr.sh_type) && !is_debug_section(ls.name);
            ls.writable = (shdr.sh_flags & SHF_WRITE) != 0;
            ls.executable = (shdr.sh_flags & SHF_EXECINSTR) != 0;
            ls.seg = classify_section(ls.executable, ls.writable);
            obj.sections.push_back(ls);
        }

        // 计算 total_size（所有 loadable section 进 pool，.so 的 _start 也在 .so 内部，
        // 主程序通过 PLT/GOT 调用，不再需要把 _start 代码单独移出）
        size_t total_size = 0;
        for (size_t i = 1; i < obj.sections.size(); i++) {
            LoadedSection& ls = obj.sections[i];
            if (!ls.loadable) continue;
            total_size = (total_size + 7) & ~size_t(7);
            ls.offset = total_size;
            total_size += ls.size;
        }

        // 至少 page align
        total_size = (total_size + 0xFFF) & ~size_t(0xFFF);
        if (total_size == 0) total_size = 0x1000;

        // 从 pool_ 分配（不是独立 mmap，保证 host/guest 偏移一致）
        if (pool_used_ + total_size > pool_size_) {
            std::cerr << "[elf_linker] pool exhausted\n";
            elf_end(elf);
            return SIZE_MAX;
        }
        unsigned char* mem = pool_ + pool_used_;
        memset(mem, 0, total_size);
        obj.host_mem = mem;
        obj.host_mem_size = total_size;
        obj.base = guest_base_ + pool_used_;
        obj.pool_offset = pool_used_;
        obj.total_size = total_size;
        pool_used_ += total_size;

        // 第二遍：拷贝 PROGBITS 数据
        scn = nullptr;
        size_t sec_idx = 1;  // 从 1 开始，跳过 NULL 占位
        while ((scn = elf_nextscn(elf, scn)) != nullptr) {
            GElf_Shdr shdr;
            gelf_getshdr(scn, &shdr);
            LoadedSection& ls = obj.sections[sec_idx++];
            if (!ls.loadable) {
                continue;
            }
            ls.guest_addr = obj.base + ls.offset;
            if (shdr.sh_type != SHT_PROGBITS) {
                // SHT_NOBITS (.bss) 已经 zero 了
                continue;
            }
            Elf_Data* d = elf_getdata(scn, nullptr);
            if (d && d->d_size > 0) {
                memcpy(obj.host_mem + ls.offset, d->d_buf, d->d_size);
            }
        }

        // 收集符号
        size_t symtab_idx = SIZE_MAX;
        for (size_t i = 0; i < obj.sections.size(); i++) {
            if (obj.sections[i].type != SHT_SYMTAB) {
                continue;
            }
            symtab_idx = i;
            break;
        }
        if (g_debug) std::cerr << "[elf_linker] " << name << ": sections=" << obj.sections.size()
                  << " symbols loaded\n";

        if (symtab_idx != SIZE_MAX) {
            scn = nullptr;
            size_t cur_idx = 0;
            while ((scn = elf_nextscn(elf, scn)) != nullptr) {
                GElf_Shdr shdr;
                gelf_getshdr(scn, &shdr);
                // ELF section index 是 cur_idx+1（因为 elf_nextscn 跳过了 NULL section 0）
                if (cur_idx + 1 != symtab_idx) {
                    cur_idx++;
                    continue;
                }
                Elf_Data* d = elf_getdata(scn, nullptr);
                if (!d) {
                    break;
                }
                size_t sym_count = d->d_size / sizeof(GElf_Sym);
                for (size_t i = 0; i < sym_count; i++) {
                    GElf_Sym sym;
                    gelf_getsym(d, i, &sym);
                    LoadedSym ls;
                    char* nm = elf_strptr(elf, shdr.sh_link, sym.st_name);
                    ls.name = nm ? nm : "";
                    ls.value = sym.st_value;
                    ls.size = sym.st_size;
                    ls.binding = GELF_ST_BIND(sym.st_info);
                    ls.type = GELF_ST_TYPE(sym.st_info);
                    if (sym.st_shndx == SHN_UNDEF || sym.st_shndx >= SHN_LORESERVE) {
                        ls.defined = false;
                        ls.sec_idx = SIZE_MAX;
                    } else {
                        ls.defined = true;
                        // sym.st_shndx 是真实 ELF section index；
                        // 因为我们在 obj.sections 开头加了 NULL 占位，下标和 ELF index 对齐
                        ls.sec_idx = sym.st_shndx;
                    }
                    obj.symbols.push_back(ls);
                }
                break;
            }
        }
        if (g_debug) std::cerr << "[elf_linker] " << name << ": symbols=" << obj.symbols.size() << "\n";

        // 收集重定位（所有 SHT_REL/SHT_RELA）
        scn = nullptr;
        while ((scn = elf_nextscn(elf, scn)) != nullptr) {
            GElf_Shdr shdr;
            gelf_getshdr(scn, &shdr);
            if (shdr.sh_type != SHT_REL && shdr.sh_type != SHT_RELA) {
                continue;
            }
            // sh_info: 要 patch 的 section index
            size_t target_sec = shdr.sh_info;
            Elf_Data* d = elf_getdata(scn, nullptr);
            if (!d) continue;
            size_t rel_count = d->d_size / (shdr.sh_type == SHT_RELA ? sizeof(GElf_Rela) : sizeof(GElf_Rel));
            for (size_t i = 0; i < rel_count; i++) {
                LoadedReloc r;
                r.target_sec = target_sec;
                if (shdr.sh_type == SHT_RELA) {
                    GElf_Rela rela;
                    gelf_getrela(d, i, &rela);
                    r.offset = rela.r_offset;
                    r.type = GELF_R_TYPE(rela.r_info);
                    r.sym_idx = GELF_R_SYM(rela.r_info);
                    r.addend = rela.r_addend;
                } else {
                    GElf_Rel rel;
                    gelf_getrel(d, i, &rel);
                    r.offset = rel.r_offset;
                    r.type = GELF_R_TYPE(rel.r_info);
                    r.sym_idx = GELF_R_SYM(rel.r_info);
                    // SHT_REL：addend 嵌入在 patch 点原值里，按类型读取。
                    // 仅对已定义符号读（UND 符号的 patch 点是 clang 占位符，非真实 addend）。
                    bool sym_defined = (r.sym_idx < obj.symbols.size() && obj.symbols[r.sym_idx].defined);
                    if (sym_defined && target_sec < obj.sections.size() && obj.sections[target_sec].loadable) {
                        const unsigned char* patch = obj.host_mem + obj.sections[target_sec].offset + r.offset;
                        r.addend = read_embedded_addend(patch, r.type);
                    }
                }
                obj.relocations.push_back(r);
            }
        }

        elf_end(elf);

        size_t obj_idx = objects_.size();
        if (g_debug) {
            std::cerr << "[elf_linker] loaded " << name
                      << " base=0x" << std::hex << obj.base << std::dec
                      << " size=0x" << std::hex << obj.total_size << std::dec << "\n";
        }
        objects_.push_back(std::move(obj));
        return obj_idx;
    }

    // 加载一个 archive（全展开）。path 须为完整路径（由 ld_main 的 -L/-l 解析）。
    void load_archive_file(const std::string& path) {
        std::vector<uint8_t> data;
        if (!read_file(path, data)) {
            std::cerr << "[elf_linker] cannot find archive: " << path << "\n";
            return;
        }
        std::vector<ArMember> members;
        if (!parse_archive(data.data(), data.size(), members)) {
            std::cerr << "[elf_linker] invalid archive: " << path << "\n";
            return;
        }
        if (g_debug) std::cerr << "[elf_linker]   " << members.size() << " members in " << path << "\n";
        for (const auto& m : members) {
            load_rel_memory(m.data, m.size, path + ":" + m.name);
        }
    }

    // 把 obj 的所有 GLOBAL 符号注册到 globals_
    void register_globals(size_t obj_idx) {
        const auto& obj = objects_[obj_idx];
        for (size_t i = 0; i < obj.symbols.size(); i++) {
            const auto& sym = obj.symbols[i];
            if (!sym.defined) continue;
            if (sym.binding != STB_GLOBAL && sym.binding != STB_WEAK) continue;
            if (sym.type != STT_FUNC && sym.type != STT_OBJECT) continue;
            if (sym.name.empty()) continue;
            auto it = globals_.find(sym.name);
            if (it == globals_.end()) {
                globals_[sym.name] = {obj_idx, i};
            } else {
                // strong(STB_GLOBAL) 覆盖 weak(STB_WEAK)——标准 ld 行为。
                // 典型场景：musl libc.a 同时含 lite_malloc.o（weak __libc_malloc_impl）
                // 和 mallocng/malloc.o（strong __libc_malloc_impl）。archive 拉入顺序不定，
                // 若 weak 先注册而 strong 不覆盖，malloc 会错误地链到 lite_malloc（brk 分配
                // 器），与 mallocng 的 free 配对立刻崩溃。weak 不覆盖 strong；两个 strong
                // 保留先到的（与原行为一致，不新增报错）。
                const auto& existing = objects_[it->second.obj_idx].symbols[it->second.sym_idx];
                if (existing.binding == STB_WEAK && sym.binding == STB_GLOBAL) {
                    globals_[sym.name] = {obj_idx, i};
                }
            }
        }
    }

    // DYNAMIC_EXE：扫描所有重定位引用的 UND 符号，既不在 globals_（.o/.a 提供）也不在
    // bpfso_symbols_（.so 提供）的视为真正未定义，报错（对齐标准 ld）。
    // 例外：weak 未定义符号（如 __init_array_start/__fini_array_start/_DYNAMIC）允许
    // 不被定义——标准 ld 把它们解析为 0；musl/glibc 启动代码用 weak 引用这些「可能不
    // 存在」的边界符号，遍历时空范围安全。重定位时这类符号走 resolve_symbol 返回 0。
    // FP 虚拟指令的 extern __ksym 符号识别（见 BpfSoftFp pass 的编码链路）。
    // 符号名形如 `__bpf_fp_<ID>`，尾部 <ID> 是十进制 BPF_FP_* 编号。
    // 这些符号由 pass 合成、无真实定义，VM 在运行时按 src_reg=2 解释——故 linker
    // 既不报"未定义"，也不走 PLT，而是在 R_BPF_64_32 处把 call 改写为
    // src_reg=2 + imm=<ID>。
    static constexpr const char* kFpKsymPrefix = "__bpf_fp_";

    // 是否 FP ksym 符号。
    static bool is_fp_ksym(const std::string& name) {
        return name.rfind(kFpKsymPrefix, 0) == 0;  // 以 prefix 开头
    }

    // 从符号名解析 FP_ID；非法返回 false。
    static bool parse_fp_ksym_id(const std::string& name, uint32_t& out_id) {
        const char* s = name.c_str() + std::strlen(kFpKsymPrefix);
        if (*s == '\0') return false;
        char* end = nullptr;
        unsigned long v = std::strtoul(s, &end, 10);
        if (*end != '\0' || end == s) return false;   // 必须全是数字
        out_id = (uint32_t)v;
        return true;
    }

    bool check_undefined_symbols() {
        std::set<std::string> reported;
        for (const auto& obj : objects_) {
            for (const auto& r : obj.relocations) {
                if (r.sym_idx >= obj.symbols.size()) continue;
                const auto& sym = obj.symbols[r.sym_idx];
                if (sym.defined) continue;                       // 本对象内定义
                if (sym.name.empty()) continue;
                if (sym.binding == STB_WEAK) continue;           // weak 未定义 → 解析为 0
                if (globals_.count(sym.name)) continue;          // .o/.a 提供（resolve_symbol 可解析）
                if (bpfso_symbols_.count(sym.name)) continue;    // .so 提供（运行时解析）
                if (is_fp_ksym(sym.name)) continue;              // FP 虚拟指令符号（VM 运行时解释）
                if (reported.insert(sym.name).second) {
                    std::cerr << "[elf_linker] undefined symbol '" << sym.name
                              << "' referenced by " << obj.source << "\n";
                }
            }
        }
        return reported.empty();
    }

    // 解析符号的最终 guest 地址；找不到返回 nullopt（调用方据此报错）
    //
    // 设计：globals_ 是符号解析的唯一真理来源。register_globals 已按标准 ld 语义
    // 填好表（strong 覆盖 weak，两个 strong 保留先到的）。这里只查表，不做二次
    // 优先级判断——无论符号是 defined 还是 UND、是 strong 还是 weak，只要它参与
    // 全局链接（非 STB_LOCAL），最终地址都由 globals_ 决定。
    //
    // 例外 STB_LOCAL：文件私有符号（如 static 函数、section 符号），不进 globals_，
    // 直接用本 obj 定义。
    std::optional<uint64_t> resolve_symbol(size_t obj_idx, size_t sym_idx) const {
        const auto& sym = objects_[obj_idx].symbols[sym_idx];

        // STB_LOCAL：本 obj 私有，直接用本 obj 定义
        if (sym.binding == STB_LOCAL) {
            const auto& sec = objects_[obj_idx].sections[sym.sec_idx];
            return sec.guest_addr + sym.value;
        }

        // STB_GLOBAL / STB_WEAK（defined 或 UND）：统一查 globals_
        auto it = globals_.find(sym.name);
        if (it != globals_.end()) {
            const auto& def_obj = objects_[it->second.obj_idx];
            const auto& def_sym = def_obj.symbols[it->second.sym_idx];
            const auto& def_sec = def_obj.sections[def_sym.sec_idx];
            return def_sec.guest_addr + def_sym.value;
        }

        // 查不到（仅 UND 符号会走到这里；defined 的 non-local 符号必然在 globals_ 中）：
        //   - weak UND + 链接可执行（STATIC_EXE/DYNAMIC_EXE）：按标准 ld 解析为 0
        //     （musl/glibc 用 weak 引用 __init_array_start/_DYNAMIC 等「可能不存在」的
        //      边界符号，空范围 start==end==0 的遍历是安全的 no-op）。
        //   - SHARED_LIB：保持 UND 返回 nullopt，留给运行期经 PLT/GOT 解析（如 PDCLib
        //      的 main 是 weak UND，.so 里 _start 调它必须走 PLT 桩，由消费者在链接期
        //      填入 main 地址）。
        if (sym.binding == STB_WEAK && mode_ != Mode::SHARED_LIB)
            return 0;
        return std::nullopt;
    }

    // 加载 .so 文件，提取其 symtab 中所有 GLOBAL 符号 → 地址映射
    // 不加载内容到 pool_，只读符号信息
    bool load_bpfso_symbols(const std::string& path) {
        std::vector<uint8_t> data;
        if (!read_file(path, data)) return false;

        Elf* elf = elf_memory((char*)data.data(), data.size());
        if (!elf || elf_kind(elf) != ELF_K_ELF) {
            if (elf) elf_end(elf);
            return false;
        }
        GElf_Ehdr ehdr;
        if (gelf_getehdr(elf, &ehdr) != &ehdr) {
            elf_end(elf);
            return false;
        }

        size_t shstrndx = 0;
        elf_getshdrstrndx(elf, &shstrndx);

        // 找 .dynsym（SHT_DYNSYM）+ .dynstr + .dynamic
        Elf_Scn* dynsym_scn = nullptr;
        size_t dynsym_link = 0;
        Elf_Scn* dynstr_scn = nullptr;
        Elf_Scn* dynamic_scn = nullptr;
        Elf_Scn* scn = nullptr;
        while ((scn = elf_nextscn(elf, scn)) != nullptr) {
            GElf_Shdr shdr;
            gelf_getshdr(scn, &shdr);
            char* nm = elf_strptr(elf, shstrndx, shdr.sh_name);
            std::string name(nm ? nm : "");
            if (shdr.sh_type == SHT_DYNSYM) { dynsym_scn = scn; dynsym_link = shdr.sh_link; }
            else if (shdr.sh_type == SHT_STRTAB && name == ".dynstr") { dynstr_scn = scn; }
            else if (shdr.sh_type == SHT_DYNAMIC) { dynamic_scn = scn; }
        }
        if (!dynsym_scn) {
            std::cerr << "[elf_linker] .so has no .dynsym: " << path << "\n";
            elf_end(elf);
            return false;
        }

        Elf_Data* d = elf_getdata(dynsym_scn, nullptr);
        size_t sym_count = d->d_size / sizeof(GElf_Sym);
        size_t loaded = 0;
        for (size_t i = 0; i < sym_count; i++) {
            GElf_Sym sym;
            gelf_getsym(d, i, &sym);
            int binding = GELF_ST_BIND(sym.st_info);
            int type = GELF_ST_TYPE(sym.st_info);
            if (binding != STB_GLOBAL && binding != STB_WEAK) continue;
            if (type != STT_FUNC && type != STT_OBJECT) continue;
            if (sym.st_shndx == SHN_UNDEF) continue;  // 导入符号，不是导出
            char* nm = elf_strptr(elf, dynsym_link, sym.st_name);
            if (!nm || !*nm) continue;
            bpfso_symbols_[nm] = sym.st_value;
            loaded++;
        }
        if (g_debug) std::cerr << "[elf_linker] loaded " << loaded << " symbols from " << path << "\n";

        // 读 DT_SONAME（标准 .dynamic）用于输出 .so 的 DT_NEEDED
        Elf_Data* dd = dynamic_scn ? elf_getdata(dynamic_scn, nullptr) : nullptr;
        Elf_Data* ds = dynstr_scn ? elf_getdata(dynstr_scn, nullptr) : nullptr;
        if (!dd || !ds) {
            elf_end(elf);
            return true;
        }
        size_t ndyn = dd->d_size / sizeof(Elf64_Dyn);
        for (size_t i = 0; i < ndyn; i++) {
            Elf64_Dyn dyn;
            memcpy(&dyn, (const uint8_t*)dd->d_buf + i * sizeof(Elf64_Dyn), sizeof(dyn));
            if (dyn.d_tag != DT_SONAME) continue;
            if (dyn.d_un.d_val < ds->d_size) {
                needed_.push_back(std::string((const char*)ds->d_buf + dyn.d_un.d_val));
            }
            break;
        }
        elf_end(elf);
        return true;
    }

    // 实际写 ELF 文件。根据 mode_ 决定输出哪些段：
    //   STATIC_EXE:  ELF header + PT_LOAD（极简，无 section headers）
    //   SHARED_LIB:  ELF header + PT_LOAD + .bpf_soname + .symtab + .strtab + .shstrtab + section headers
    //   DYNAMIC_EXE: ELF header + PT_LOAD + .dynamic + section headers
    // ===== write_elf_impl：把 pool + extras 写成 ELF 文件 =====
    // 流程：构建 extras → 计算布局 → 回填动态段 vaddr → 写 header/phdr/payload/shdr。
    // 各阶段拆到 build_*/compute_*/backfill_*/write_* helper，本函数仅编排。
    bool write_elf_impl(FILE* f) const {
        // 1. section index 布局：NULL(0) → .text → .plt? → .rodata → .data → .got.plt? → .bss? → extras
        Elf64_Half seg_shndx[3] = {0,0,0};
        Elf64_Half bss_shndx = 0;
        bool has_bss = segs_[SEG_DATA].used && segs_[SEG_DATA].memsz > segs_[SEG_DATA].filesz;
        bool has_plt = (plt_obj_idx_ < objects_.size());
        bool has_gotplt = (got_obj_idx_ < objects_.size());
        Elf64_Half next_sh = 1;
        if (segs_[SEG_TEXT].used) {
            seg_shndx[SEG_TEXT] = next_sh++;
            if (has_plt) ++next_sh;  // .plt 占一个 section index（emit_synthetic 写表时用到）
        }
        if (segs_[SEG_RODATA].used) {
            seg_shndx[SEG_RODATA] = next_sh++;
        }
        if (segs_[SEG_DATA].used) {
            seg_shndx[SEG_DATA] = next_sh++;
            if (has_gotplt) ++next_sh;  // .got.plt 占一个 section index
            if (has_bss) bss_shndx = next_sh++;
        }
        Elf64_Half extras_base = next_sh;  // 第一个 extra 的 section index

        // 2. 构建 extras（按 mode_ 条件追加）
        std::vector<SecBuf> extras;
        if (mode_ == Mode::SHARED_LIB) {
            build_static_symtab(extras, extras_base, bss_shndx, seg_shndx);
        }
        DynSecOut dyn_idx;
        const bool need_dynamic = (mode_ == Mode::SHARED_LIB || mode_ == Mode::DYNAMIC_EXE);
        if (need_dynamic) {
            dyn_idx = build_dynamic_sections(extras, extras_base, bss_shndx, seg_shndx);
        }
        size_t interp_idx = SIZE_MAX;
        if (mode_ == Mode::DYNAMIC_EXE) {
            interp_idx = build_interp(extras);
        }
        ShstrtabOut names = build_shstrtab(extras, has_plt, has_gotplt, has_bss);

        // 3. 计算文件布局
        FileLayout layout = compute_file_layout(extras, extras_base, next_sh,
                                                 names.shstrtab_idx, interp_idx, need_dynamic);

        // 4. 回填动态 section 的 vaddr 并 patch DT_*
        std::unordered_map<size_t, uint64_t> dyn_vaddr_map;
        if (need_dynamic) {
            dyn_vaddr_map = backfill_dynamic_vaddrs(extras, layout.extra_offs, dyn_idx, interp_idx);
        }

        // 5. 写出
        if (!write_ehdr(f, layout)) return false;
        if (!write_phdrs(f, extras, layout, dyn_vaddr_map, dyn_idx, interp_idx, need_dynamic)) return false;
        if (!write_payload(f, extras, layout)) return false;
        if (!write_shdrs(f, extras, layout, dyn_vaddr_map, names)) return false;
        return true;
    }

    // 符号所在 section → 输出 ELF 的 section index（text/rodata/data/bss/ABS）
    Elf64_Half sym_to_shndx(const LoadedObject& obj, size_t sec_idx,
                             Elf64_Half bss_shndx, const Elf64_Half seg_shndx[3]) const {
        if (sec_idx == SIZE_MAX || sec_idx >= obj.sections.size()) return SHN_ABS;
        const LoadedSection& ls = obj.sections[sec_idx];
        if (ls.type == SHT_NOBITS && ls.seg == SEG_DATA) return bss_shndx ? bss_shndx : SHN_ABS;
        return seg_shndx[ls.seg] ? seg_shndx[ls.seg] : SHN_ABS;
    }

    // SHARED_LIB：构建 .strtab + .symtab（完整符号表，调试用；运行时用 .dynsym）
    void build_static_symtab(std::vector<SecBuf>& extras, Elf64_Half extras_base,
                              Elf64_Half bss_shndx, const Elf64_Half seg_shndx[3]) const {
        SecBuf strtab;
        strtab.name = ".strtab";
        strtab.type = SHT_STRTAB;
        strtab.data.push_back(0);
        strtab.addralign = 1;

        SecBuf symtab;
        symtab.name = ".symtab";
        symtab.type = SHT_SYMTAB;
        symtab.addralign = 8;
        symtab.entsize = sizeof(Elf64_Sym);
        symtab.info = 1;

        Elf64_Sym zsym = {};
        symtab.data.insert(symtab.data.end(), (uint8_t*)&zsym, (uint8_t*)&zsym + sizeof(zsym));

        for (const auto& kv : globals_) {
            const auto& obj = objects_[kv.second.obj_idx];
            const auto& sym = obj.symbols[kv.second.sym_idx];
            Elf64_Sym s = {};
            Elf64_Word name_off = (Elf64_Word)strtab.data.size();
            strtab.data.insert(strtab.data.end(), sym.name.begin(), sym.name.end());
            strtab.data.push_back(0);
            s.st_name = name_off;
            s.st_info = GELF_ST_INFO(STB_GLOBAL, sym.type == 0 ? STT_FUNC : sym.type);
            s.st_shndx = sym_to_shndx(obj, sym.sec_idx, bss_shndx, seg_shndx);
            s.st_value = sec_guest_addr_of(obj, sym.sec_idx) + sym.value;
            s.st_size = sym.size;
            symtab.data.insert(symtab.data.end(), (uint8_t*)&s, (uint8_t*)&s + sizeof(s));
        }
        symtab.info = 1;

        size_t strtab_idx = extras.size();
        extras.push_back(std::move(strtab));
        size_t symtab_idx = extras.size();
        extras.push_back(std::move(symtab));
        extras[symtab_idx].link = extras_base + (Elf64_Word)strtab_idx;
    }

    // 收集所有 UND 符号名（跨模块重定位引用的未定义符号 → .dynsym 的导入部分）。
    // DYNAMIC_EXE：入口符号若不在 globals_ 也加入，让 .rela.plt 能引用（PLT 桩作 e_entry）。
    // 同时跟踪每个名字是否「纯 weak UND」：某名字的所有 UND 引用都是 STB_WEAK（且无 globals_
    // 定义、不是 _DYNAMIC/入口）时，标记为 weak——输出到 .dynsym 时写 STB_WEAK，loader 对其
    // 解析失败静默处理（weak UND → 0 是标准 ld 语义，如 musl 的 __init_array_start 等边界符号）。
    struct UndNames {
        std::vector<std::string> names;
        std::unordered_map<std::string, size_t> idx;            // name → names 下标
        std::unordered_map<std::string, bool> is_weak;          // name → 是否纯 weak UND
    };
    UndNames collect_und_names() const {
        UndNames out;
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            for (const auto& r : objects_[oi].relocations) {
                if (r.sym_idx >= objects_[oi].symbols.size()) continue;
                const auto& sym = objects_[oi].symbols[r.sym_idx];
                if (sym.defined || sym.name.empty()) continue;
                if (sym.name == "_DYNAMIC") continue;  // 由 build_dynamic_sections 合成为 defined 符号
                bool inserted = out.idx.find(sym.name) == out.idx.end();
                if (inserted) {
                    out.idx[sym.name] = out.names.size();
                    out.names.push_back(sym.name);
                    out.is_weak[sym.name] = (sym.binding == STB_WEAK);
                } else if (sym.binding != STB_WEAK) {
                    // 同名符号只要存在一个 strong 引用，就不再算纯 weak
                    out.is_weak[sym.name] = false;
                }
            }
        }
        if (mode_ == Mode::DYNAMIC_EXE && !entry_name_.empty() &&
            out.idx.find(entry_name_) == out.idx.end() &&
            globals_.find(entry_name_) == globals_.end()) {
            out.idx[entry_name_] = out.names.size();
            out.names.push_back(entry_name_);
            out.is_weak[entry_name_] = false;  // 入口符号由运行期解析，必须走 strong 导入
        }
        return out;
    }

    // SHARED_LIB/DYNAMIC_EXE：构建 .dynstr/.dynsym/.hash/.rela.dyn/.rela.plt?/.dynamic
    // 对齐标准 ELF .so：DT_NEEDED/DT_SONAME 声明依赖和自身名；DYNAMIC_EXE 额外写
    // DT_FLAGS_1=DF_1_PIE（让 readelf/file 识别为 PIE 可执行，见文件顶部说明）。
    // VM 构建期 patch 完，运行时不读这些 section（只 mmap 占位以满足 readelf）。
    DynSecOut build_dynamic_sections(std::vector<SecBuf>& extras, Elf64_Half extras_base,
                                       Elf64_Half bss_shndx, const Elf64_Half seg_shndx[3]) const {
        DynSecOut out;
        auto und = collect_und_names();
        const auto& und_names = und.names;

        // .dynstr：\0 + und 名 + soname/needed + 导出符号名
        SecBuf dynstr;
        dynstr.name = ".dynstr";
        dynstr.type = SHT_STRTAB;
        dynstr.addralign = 1;
        dynstr.data.push_back(0);
        std::vector<Elf64_Word> und_name_offs;
        for (const auto& n : und_names) {
            und_name_offs.push_back((Elf64_Word)dynstr.data.size());
            dynstr.data.insert(dynstr.data.end(), n.begin(), n.end());
            dynstr.data.push_back(0);
        }
        Elf64_Word soname_off = 0;
        if (mode_ == Mode::SHARED_LIB && !soname_.empty()) {
            soname_off = (Elf64_Word)dynstr.data.size();
            dynstr.data.insert(dynstr.data.end(), soname_.begin(), soname_.end());
            dynstr.data.push_back(0);
        }
        std::vector<Elf64_Word> needed_offs;
        for (const auto& n : needed_) {
            needed_offs.push_back((Elf64_Word)dynstr.data.size());
            dynstr.data.insert(dynstr.data.end(), n.begin(), n.end());
            dynstr.data.push_back(0);
        }
        std::unordered_map<std::string, Elf64_Word> export_name_off;
        for (const auto& kv : globals_) {
            const auto& sym = objects_[kv.second.obj_idx].symbols[kv.second.sym_idx];
            if (sym.name.empty()) continue;
            if (export_name_off.find(sym.name) != export_name_off.end()) continue;
            Elf64_Word off = (Elf64_Word)dynstr.data.size();
            dynstr.data.insert(dynstr.data.end(), sym.name.begin(), sym.name.end());
            dynstr.data.push_back(0);
            export_name_off[sym.name] = off;
        }
        // _DYNAMIC：标准 ld 在 PIE/.so 上合成的符号，指向 .dynamic section 起始。
        // musl __init_tls/dl_iterate_phdr 用它（weak 引用）反推加载基址。bpfvm-ld
        // 这里合成 defined 符号，避免运行时加载器报 "unresolved symbol '_DYNAMIC'"
        // （虽然 weak UND → 0 语义上安全，musl 走 PT_PHDR 兜底，但消掉噪音更干净）。
        // st_value 在 backfill_dynamic_vaddrs 里回填（.dynamic vaddr 那时才确定）。
        Elf64_Word dynamic_name_off = (Elf64_Word)dynstr.data.size();
        const std::string dynamic_name = "_DYNAMIC";
        dynstr.data.insert(dynstr.data.end(), dynamic_name.begin(), dynamic_name.end());
        dynstr.data.push_back(0);
        out.dynstr_idx = extras.size();
        extras.push_back(std::move(dynstr));

        // .dynsym：NULL + und 符号 + 导出符号
        SecBuf dynsym;
        dynsym.name = ".dynsym";
        dynsym.type = SHT_DYNSYM;
        dynsym.addralign = 8;
        dynsym.entsize = sizeof(Elf64_Sym);
        dynsym.link = extras_base + (Elf64_Word)out.dynstr_idx;
        Elf64_Sym zsym = {};
        dynsym.data.insert(dynsym.data.end(), (uint8_t*)&zsym, (uint8_t*)&zsym + sizeof(zsym));
        std::unordered_map<std::string, size_t> dynsym_idx;  // name → .dynsym index (0-based)
        for (size_t i = 0; i < und_names.size(); i++) {
            Elf64_Sym s = {};
            s.st_name = und_name_offs[i];
            const std::string& nm = und_names[i];
            bool weak = und.is_weak.count(nm) && und.is_weak.at(nm);
            // 纯 weak UND（如 __init_array_start/__fini_array_start）：保留 STB_WEAK，loader
            // 对其解析失败静默处理（weak UND → 0，标准 ld 语义）；其余 UND 保持 STB_GLOBAL。
            s.st_info = GELF_ST_INFO(weak ? STB_WEAK : STB_GLOBAL, STT_NOTYPE);
            s.st_shndx = SHN_UNDEF;
            dynsym.data.insert(dynsym.data.end(), (uint8_t*)&s, (uint8_t*)&s + sizeof(s));
            dynsym_idx[nm] = 1 + i;
        }
        Elf64_Word first_global = 1 + (Elf64_Word)und_names.size();
        for (const auto& kv : globals_) {
            const auto& obj = objects_[kv.second.obj_idx];
            const auto& sym = obj.symbols[kv.second.sym_idx];
            Elf64_Sym s = {};
            auto it = export_name_off.find(sym.name);
            if (it != export_name_off.end()) s.st_name = it->second;
            s.st_info = GELF_ST_INFO(STB_GLOBAL, sym.type == 0 ? STT_FUNC : sym.type);
            s.st_shndx = sym_to_shndx(obj, sym.sec_idx, bss_shndx, seg_shndx);
            s.st_value = sec_guest_addr_of(obj, sym.sec_idx) + sym.value;
            s.st_size = sym.size;
            dynsym.data.insert(dynsym.data.end(), (uint8_t*)&s, (uint8_t*)&s + sizeof(s));
            dynsym_idx[sym.name] = dynsym.data.size() / sizeof(Elf64_Sym) - 1;
        }
        // _DYNAMIC 合成条目：STB_GLOBAL / STT_OBJECT，st_value 占位 0（backfill 回填），
        // st_shndx=SHN_ABS（.dynamic 是 extras section，不对应 obj 的 section，用 ABS
        // 让加载器视为 defined 即可——exports 收集只判 != SHN_UNDEF）。
        {
            Elf64_Sym s = {};
            s.st_name = dynamic_name_off;
            s.st_info = GELF_ST_INFO(STB_GLOBAL, STT_OBJECT);
            s.st_shndx = SHN_ABS;
            s.st_value = 0;
            size_t off = dynsym.data.size();
            dynsym.data.insert(dynsym.data.end(), (uint8_t*)&s, (uint8_t*)&s + sizeof(s));
            dynsym_idx["_DYNAMIC"] = dynsym.data.size() / sizeof(Elf64_Sym) - 1;
            out.dynamic_sym_off = off;  // st_value 在 Elf64_Sym 偏移 8 处，backfill 直接 +8 写
        }
        dynsym.info = first_global;
        out.dynsym_idx = extras.size();
        extras.push_back(std::move(dynsym));

        // .hash（SysV 风格：nbucket + nchain + buckets[] + chains[]）
        {
            size_t nsym = extras[out.dynsym_idx].data.size() / sizeof(Elf64_Sym);
            SecBuf hashbuf;
            hashbuf.name = ".hash";
            hashbuf.type = SHT_HASH;
            hashbuf.addralign = 8;
            hashbuf.entsize = sizeof(Elf64_Word);
            hashbuf.link = extras_base + (Elf64_Word)out.dynsym_idx;
            size_t nbucket = nsym > 1 ? nsym : 2;
            size_t nchain = nsym;
            auto w32 = [&](uint32_t v) {
                hashbuf.data.insert(hashbuf.data.end(), (uint8_t*)&v, (uint8_t*)&v + 4);
            };
            w32((uint32_t)nbucket);
            w32((uint32_t)nchain);
            std::vector<uint32_t> buckets(nbucket, 0);
            std::vector<uint32_t> chains(nchain, 0);
            std::vector<uint32_t> bucket_last(nbucket, 0);  // 每个 bucket 当前链尾
            const auto& dynstr_data = extras[out.dynstr_idx].data;
            for (size_t i = 1; i < nsym; i++) {
                Elf64_Sym s;
                memcpy(&s, &extras[out.dynsym_idx].data[i * sizeof(Elf64_Sym)], sizeof(s));
                if (s.st_name == 0) continue;
                const char* nm = (const char*)dynstr_data.data() + s.st_name;
                uint32_t h = elf_hash(nm) % nbucket;
                if (bucket_last[h] == 0) buckets[h] = i;
                else chains[bucket_last[h]] = i;
                bucket_last[h] = i;
            }
            for (uint32_t b : buckets) w32(b);
            for (uint32_t c : chains) w32(c);
            out.hash_idx = extras.size();
            extras.push_back(std::move(hashbuf));
        }

        // .rela.dyn：PIC 模式下需要运行时重定位的项（lddw/数据指针绝对地址）。
        //   - R_BPF_64_64 (lddw, type 1) / R_BPF_64_ABS64 (数据指针, type 2) / R_BPF_64_NODYLD32 (type 4)
        //   - 本模块符号：用 NULL 符号(idx 0) + addend = 符号相对地址，VM resolve 返回 load_base
        //   - UND 符号：查 .dynsym 索引，VM 按名解析
        // call (type 10) 不记：构建期已处理（内部相对 call / UND 走 PLT）
        SecBuf reladyn;
        reladyn.name = ".rela.dyn";
        reladyn.type = SHT_RELA;
        reladyn.addralign = 8;
        reladyn.entsize = sizeof(Elf64_Rela);
        reladyn.link = extras_base + (Elf64_Word)out.dynsym_idx;
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            for (const auto& r : objects_[oi].relocations) {
                if (r.sym_idx >= objects_[oi].symbols.size()) continue;
                const auto& sym = objects_[oi].symbols[r.sym_idx];
                if (r.target_sec >= objects_[oi].sections.size()) continue;
                if (r.type == 10) continue;
                const auto& target = objects_[oi].sections[r.target_sec];
                if (!target.loadable) continue;
                Elf64_Rela rela = {};
                rela.r_offset = target.guest_addr + r.offset;
                if (sym.defined) {
                    // 用 globals_ 解析后的地址（resolve_symbol），而非本 obj 内的局部定义地址。
                    // 否则 weak 符号被 strong 覆盖时（如 musl __stdio_exit.o 的 weak
                    // __stdout_used 被 stdout.o 的 strong 覆盖），addend 仍指向 weak 的
                    // .bss.dummy_file（值 0），运行时 __stdio_exit 读到 NULL 不刷新 stdout。
                    auto resolved = resolve_symbol(oi, r.sym_idx);
                    uint64_t sym_addr = resolved.value_or(
                        sec_guest_addr_of(objects_[oi], sym.sec_idx) + sym.value);
                    rela.r_info = ELF64_R_INFO(0, r.type);
                    rela.r_addend = sym_addr + r.addend;
                } else {
                    auto it = dynsym_idx.find(sym.name);
                    uint64_t si = (it != dynsym_idx.end()) ? it->second : 0;
                    rela.r_info = ELF64_R_INFO(si, r.type);
                    rela.r_addend = r.addend;
                }
                reladyn.data.insert(reladyn.data.end(), (uint8_t*)&rela, (uint8_t*)&rela + sizeof(rela));
            }
        }
        out.reladyn_idx = extras.size();
        extras.push_back(std::move(reladyn));

        // .rela.plt：GOT 槽重定位（运行期由加载器解析填入函数地址）。
        // r_offset 指向 GOT 槽 guest_addr；type R_BPF_64_64（64 位绝对地址写入）。
        // 仅 --got-sym 启用时生成；.dynamic 的 DT_JMPREL 指向本段。
        if (got_enabled_) {
            SecBuf relaplt;
            relaplt.name = ".rela.plt";
            relaplt.type = SHT_RELA;
            relaplt.addralign = 8;
            relaplt.entsize = sizeof(Elf64_Rela);
            relaplt.link = extras_base + (Elf64_Word)out.dynsym_idx;
            for (const auto& sym : got_syms_) {
                auto it = got_slots_.find(sym);
                if (it == got_slots_.end()) continue;
                const LoadedSection& got_sec = objects_[it->second.obj_idx].sections[1];
                Elf64_Rela rela = {};
                rela.r_offset = got_sec.guest_addr + it->second.offset;
                auto dit = dynsym_idx.find(sym);
                uint64_t si = (dit != dynsym_idx.end()) ? dit->second : 0;
                rela.r_info = ELF64_R_INFO(si, 1);  // R_BPF_64_64：写 64 位绝对地址
                rela.r_addend = 0;
                relaplt.data.insert(relaplt.data.end(), (uint8_t*)&rela, (uint8_t*)&rela + sizeof(rela));
            }
            out.relaplt_idx = extras.size();
            extras.push_back(std::move(relaplt));
        }

        // .dynamic：DT_* entries。DT_SYMTAB/DT_STRTAB/DT_HASH/DT_RELA/DT_JMPREL/DT_PLTGOT
        // 的 vaddr 在 extra_offs 算完后回填（backfill_dynamic_vaddrs 负责）。
        SecBuf dynamic;
        dynamic.name = ".dynamic";
        dynamic.type = SHT_DYNAMIC;
        dynamic.addralign = 8;
        dynamic.entsize = sizeof(Elf64_Dyn);
        dynamic.link = extras_base + (Elf64_Word)out.dynstr_idx;  // .dynamic.sh_link → .dynstr
        auto add_dyn = [&](int64_t tag, uint64_t val) {
            Elf64_Dyn d;
            d.d_tag = tag;
            d.d_un.d_val = val;
            dynamic.data.insert(dynamic.data.end(), (uint8_t*)&d, (uint8_t*)&d + sizeof(d));
        };
        if (mode_ == Mode::SHARED_LIB && soname_off != 0) add_dyn(DT_SONAME, soname_off);
        for (Elf64_Word off : needed_offs) add_dyn(DT_NEEDED, off);
        if (mode_ == Mode::DYNAMIC_EXE) add_dyn(DT_FLAGS_1, DF_1_PIE);
        add_dyn(DT_SYMTAB, 0);
        add_dyn(DT_STRTAB, 0);
        add_dyn(DT_STRSZ, extras[out.dynstr_idx].data.size());
        add_dyn(DT_SYMENT, sizeof(Elf64_Sym));
        add_dyn(DT_HASH, 0);
        add_dyn(DT_RELA, 0);
        add_dyn(DT_RELASZ, extras[out.reladyn_idx].data.size());
        add_dyn(DT_RELAENT, sizeof(Elf64_Rela));
        if (got_enabled_ && out.relaplt_idx != SIZE_MAX) {
            add_dyn(DT_JMPREL, 0);
            add_dyn(DT_PLTRELSZ, extras[out.relaplt_idx].data.size());
            add_dyn(DT_PLTREL, DT_RELA);  // PLT 重定位类型 = RELA
            add_dyn(DT_PLTGOT, 0);
        }
        add_dyn(DT_NULL, 0);
        out.dynamic_idx = extras.size();
        extras.push_back(std::move(dynamic));

        return out;
    }

    // DYNAMIC_EXE：构建 .interp（虚拟 interpreter 路径，让 file/readelf 把产物识别为 PIE
    // 可执行；VM 不读 PT_INTERP，自己加载 .so。后续若拆 bpfvm-loader 为独立程序，改这里）
    size_t build_interp(std::vector<SecBuf>& extras) const {
        static const char interp_path[] = "/lib/ld-bpf.so";
        SecBuf interp;
        interp.name = ".interp";
        interp.type = SHT_PROGBITS;
        interp.addralign = 1;
        interp.data.insert(interp.data.end(), interp_path, interp_path + sizeof(interp_path));  // 含末尾 \0
        size_t idx = extras.size();
        extras.push_back(std::move(interp));
        return idx;
    }

    // 构建 .shstrtab + 各 section 名在 shstrtab 中的 offset
    ShstrtabOut build_shstrtab(std::vector<SecBuf>& extras, bool has_plt, bool has_gotplt, bool has_bss) const {
        SecBuf shstrtab;
        shstrtab.name = ".shstrtab";
        shstrtab.type = SHT_STRTAB;
        shstrtab.data.push_back(0);
        shstrtab.addralign = 1;

        ShstrtabOut out;
        out.shstrtab_idx = extras.size();
        extras.push_back(std::move(shstrtab));
        // 通过 extras[idx].data 继续追加名字（push 时 SecBuf 已 move 走，但 vector 仍持有新对象）
        auto add_name = [&](const std::string& n) -> Elf64_Word {
            auto& str = extras[out.shstrtab_idx].data;
            Elf64_Word off = (Elf64_Word)str.size();
            str.insert(str.end(), n.begin(), n.end());
            str.push_back(0);
            return off;
        };
        out.text_name_off   = segs_[SEG_TEXT].used   ? add_name(".text")   : 0;
        out.plt_name_off    = has_plt                ? add_name(".plt")    : 0;
        out.rodata_name_off = segs_[SEG_RODATA].used ? add_name(".rodata") : 0;
        out.data_name_off   = segs_[SEG_DATA].used   ? add_name(".data")   : 0;
        out.gotplt_name_off = has_gotplt             ? add_name(".got.plt"): 0;
        out.bss_name_off    = has_bss                ? add_name(".bss")    : 0;
        for (const auto& e : extras) out.extra_name_offs.push_back(add_name(e.name));
        return out;
    }

    // 计算文件布局：phnum/shnum/shstrndx/段文件 offset/extra 文件 offset/sh_off
    // 文件结构：[ELF header][PT_LOAD phdrs][padding to page][段数据][extras][section headers]
    // seg_data_off 页对齐：保证 p_offset ≡ p_vaddr (mod 0x1000) 对所有 PT_LOAD 成立
    FileLayout compute_file_layout(const std::vector<SecBuf>& extras, Elf64_Half extras_base,
                                    Elf64_Half next_sh, size_t shstrtab_idx, size_t interp_idx,
                                    bool need_dynamic) const {
        FileLayout L;
        for (int c = 0; c < 3; c++) if (segs_[c].used) L.phnum++;
        if (need_dynamic) L.phnum += 2;  // PT_LOAD (动态 section) + PT_DYNAMIC
        if (interp_idx != SIZE_MAX) L.phnum += 1;  // PT_INTERP
        // 所有可执行文件（STATIC_EXE + DYNAMIC_EXE）都生成 PT_PHDR。PT_PHDR 描述
        // 「phdr 表自身在内存中的位置」，让 loader 纯靠它就能算出 auxv AT_PHDR，
        // 不必依赖「phdr 表恰好被某个 PT_LOAD 覆盖」这类文件布局假设。这让 loader
        // 侧只有一条 phdr_addr 解析路径（见 elf_loader.cpp），无需 ET_EXEC/PIE 分支。
        //（SHARED_LIB 是 .so，无入口、不被 auxv 直接消费，不需要。）
        if (mode_ != Mode::SHARED_LIB) { L.has_phdr = true; L.phnum += 1; }
        L.shnum = next_sh + (Elf64_Half)extras.size();  // NULL + 段secs + bss + extras
        L.shstrndx = extras_base + (Elf64_Half)shstrtab_idx;

        uint64_t eh_size = sizeof(Elf64_Ehdr);
        uint64_t ph_size = sizeof(Elf64_Phdr) * L.phnum;
        L.seg_data_off = (eh_size + ph_size + 0xFFF) & ~0xFFFULL;
        uint64_t cur = L.seg_data_off;
        for (int c = 0; c < 3; c++) {
            if (!segs_[c].used) continue;
            L.seg_file_off[c] = cur;
            cur += segs_[c].filesz;
        }
        for (const auto& e : extras) {
            cur = (cur + (e.addralign - 1)) & ~(e.addralign - 1);
            L.extra_offs.push_back(cur);
            cur += e.data.size();
        }
        L.sh_off = cur;
        return L;
    }

    // 回填动态 section 的 vaddr：在所有 PT_LOAD 段的 vaddr 范围之后分配，
    // 且 vaddr ≡ offset (mod 0x1000)（满足 PT_LOAD 的 p_offset ≡ p_vaddr 对齐约束）。
    // 段间有 vaddr gap（页对齐）但文件无 gap，所以不能用 offset+delta 简单映射
    // （会落到段内）。这里独立分配：page_base = 段尾页对齐 + (first_off mod 0x1000)。
    // 同时 patch .dynamic 里的 DT_SYMTAB/DT_STRTAB/DT_HASH/DT_RELA/DT_JMPREL/DT_PLTGOT 指针。
    std::unordered_map<size_t, uint64_t> backfill_dynamic_vaddrs(
        std::vector<SecBuf>& extras, const std::vector<uint64_t>& extra_offs,
        const DynSecOut& dyn_idx, size_t interp_idx) const {
        std::unordered_map<size_t, uint64_t> dyn_vaddr_map;

        uint64_t max_end = guest_base_;
        for (int c = 0; c < 3; c++) {
            if (!segs_[c].used) continue;
            uint64_t end = segs_[c].vaddr + segs_[c].memsz;
            if (end > max_end) max_end = end;
        }
        uint64_t first_off = extra_offs[dyn_idx.dynstr_idx];
        uint64_t page_base = ((max_end + 0xFFF) & ~0xFFFULL) + (first_off & 0xFFF);
        auto assign = [&](size_t idx) {
            if (idx != SIZE_MAX)
                dyn_vaddr_map[idx] = page_base + (extra_offs[idx] - first_off);
        };
        assign(dyn_idx.dynstr_idx);
        assign(dyn_idx.dynsym_idx);
        assign(dyn_idx.hash_idx);
        assign(dyn_idx.reladyn_idx);
        assign(dyn_idx.relaplt_idx);
        assign(dyn_idx.dynamic_idx);
        assign(interp_idx);

        // 回填 _DYNAMIC 符号的 st_value = .dynamic section 的 vaddr
        //（st_value 在 Elf64_Sym 偏移 8 处）。让 musl __init_tls 走 PT_DYNAMIC 分支
        // 反推 base，结果与 PT_PHDR 路径一致；同时消掉运行时 "unresolved _DYNAMIC" 警告。
        if (dyn_idx.dynamic_sym_off != SIZE_MAX && dyn_idx.dynamic_idx != SIZE_MAX &&
            dyn_vaddr_map.count(dyn_idx.dynamic_idx)) {
            auto& dynsym_data = extras[dyn_idx.dynsym_idx].data;
            uint64_t dyn_vaddr = dyn_vaddr_map[dyn_idx.dynamic_idx];
            memcpy(dynsym_data.data() + dyn_idx.dynamic_sym_off + 8, &dyn_vaddr, 8);
        }

        // 回填 .dynamic 的 DT_* 指针
        auto& dyn_data = extras[dyn_idx.dynamic_idx].data;
        for (size_t off = 0; off + sizeof(Elf64_Dyn) <= dyn_data.size(); off += sizeof(Elf64_Dyn)) {
            Elf64_Dyn d;
            memcpy(&d, dyn_data.data() + off, sizeof(d));
            switch (d.d_tag) {
            case DT_SYMTAB: d.d_un.d_ptr = dyn_vaddr_map[dyn_idx.dynsym_idx]; break;
            case DT_STRTAB: d.d_un.d_ptr = dyn_vaddr_map[dyn_idx.dynstr_idx]; break;
            case DT_HASH:   d.d_un.d_ptr = dyn_vaddr_map[dyn_idx.hash_idx]; break;
            case DT_RELA:   d.d_un.d_ptr = dyn_vaddr_map[dyn_idx.reladyn_idx]; break;
            case DT_JMPREL: d.d_un.d_ptr = dyn_vaddr_map[dyn_idx.relaplt_idx]; break;
            case DT_PLTGOT:
                // 标准 ELF：DT_PLTGOT 指向 .got.plt（PLT 用的 GOT）。
                // 运行时加载器通过 section 表按名字找 .plt 来 patch 桩的 lddw imm。
                if (got_obj_idx_ < objects_.size())
                    d.d_un.d_ptr = objects_[got_obj_idx_].sections[1].guest_addr;
                break;
            default: continue;
            }
            memcpy(dyn_data.data() + off, &d, sizeof(d));
        }
        return dyn_vaddr_map;
    }

    // ELF header。STATIC_EXE → ET_EXEC（固定地址）；SHARED_LIB/DYNAMIC_EXE → ET_DYN（PIE）
    bool write_ehdr(FILE* f, const FileLayout& L) const {
        Elf64_Ehdr ehdr = {};
        ehdr.e_ident[EI_MAG0] = ELFMAG0;
        ehdr.e_ident[EI_MAG1] = ELFMAG1;
        ehdr.e_ident[EI_MAG2] = ELFMAG2;
        ehdr.e_ident[EI_MAG3] = ELFMAG3;
        ehdr.e_ident[EI_CLASS] = ELFCLASS64;
        ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
        ehdr.e_ident[EI_VERSION] = EV_CURRENT;
        ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
        ehdr.e_type = (mode_ == Mode::STATIC_EXE) ? ET_EXEC : ET_DYN;
        ehdr.e_machine = EM_BPF;
        ehdr.e_version = EV_CURRENT;
        ehdr.e_entry = entry_;
        ehdr.e_phoff = sizeof(Elf64_Ehdr);
        ehdr.e_shoff = L.sh_off;
        ehdr.e_flags = 0;
        ehdr.e_ehsize = sizeof(Elf64_Ehdr);
        ehdr.e_phentsize = sizeof(Elf64_Phdr);
        ehdr.e_phnum = L.phnum;
        ehdr.e_shentsize = sizeof(Elf64_Shdr);
        ehdr.e_shnum = L.shnum;
        ehdr.e_shstrndx = L.shstrndx;
        return fwrite(&ehdr, sizeof(ehdr), 1, f) == 1;
    }

    // 程序头表：PT_LOAD（每段一个；首段在 has_phdr 时向前扩展覆盖文件头）+
    // PT_PHDR（可执行文件）+ 动态区 PT_LOAD + PT_INTERP（DYNAMIC_EXE）+ PT_DYNAMIC。
    bool write_phdrs(FILE* f, const std::vector<SecBuf>& extras, const FileLayout& L,
                      const std::unordered_map<size_t, uint64_t>& dyn_vaddr_map,
                      const DynSecOut& dyn_idx, size_t interp_idx, bool need_dynamic) const {
        // 首个 PT_LOAD：has_phdr 时向前扩展，把 ELF header + phdr table（文件 offset [0, head)）
        // 纳入映射。PT_PHDR 要求它描述的 phdr 表区域被某个 PT_LOAD 覆盖，否则不可读。
        // layout_segments 已给首段 vaddr 预留 head（首段 vaddr = guest_base_ + head），
        // 这里 p_offset 减到 0、p_vaddr 同步前移 head 回到 guest_base_，filesz/memsz 补 head。
        // phdr_load_vaddr 记录扩展后首段 vaddr，供下方 PT_PHDR 复用（phdr 表在其内偏移 64）。
        uint64_t phdr_load_vaddr = 0;  // 扩展后首段 vaddr（PT_PHDR.p_vaddr 的基准）
        bool first_load = true;
        for (int c = 0; c < 3; c++) {
            if (!segs_[c].used) continue;
            Elf64_Phdr ph = {};
            ph.p_type = PT_LOAD;
            ph.p_flags = segs_[c].flags;
            ph.p_offset = L.seg_file_off[c];
            ph.p_vaddr = segs_[c].vaddr;
            ph.p_paddr = segs_[c].vaddr;
            ph.p_filesz = segs_[c].filesz;
            ph.p_memsz = segs_[c].memsz;
            ph.p_align = 0x1000;
            if (L.has_phdr && first_load && ph.p_offset != 0) {
                uint64_t head = ph.p_offset;
                ph.p_offset  = 0;
                ph.p_vaddr  -= head;
                ph.p_paddr  -= head;
                ph.p_filesz += head;
                ph.p_memsz  += head;
                phdr_load_vaddr = ph.p_vaddr;
            }
            first_load = false;
            if (fwrite(&ph, sizeof(ph), 1, f) != 1) return false;
        }
        // PT_PHDR：phdr 表在文件 offset sizeof(Elf64_Ehdr)=64，对应内存 vaddr = 首段 vaddr + 64。
        // loader 据此算 auxv AT_PHDR = load_base + p_vaddr，无需依赖文件布局假设。
        if (L.has_phdr) {
            Elf64_Phdr ph = {};
            ph.p_type = PT_PHDR;
            ph.p_flags = PF_R;
            ph.p_offset = sizeof(Elf64_Ehdr);
            ph.p_vaddr = phdr_load_vaddr + sizeof(Elf64_Ehdr);
            ph.p_paddr = ph.p_vaddr;
            ph.p_filesz = sizeof(Elf64_Phdr) * L.phnum;
            ph.p_memsz = ph.p_filesz;
            ph.p_align = 8;
            if (fwrite(&ph, sizeof(ph), 1, f) != 1) return false;
        }
        // PT_LOAD 覆盖动态 section 区：vaddr = offset + delta（页对齐），
        // 满足 p_offset ≡ p_vaddr (mod 0x1000) 让 readelf 不报 "not located in any PT_LOAD"。
        // VM 不读这些 section（构建期 patch 完），mmap 它们只是占位。
        if (need_dynamic) {
            uint64_t first_off = L.extra_offs[dyn_idx.dynstr_idx];
            uint64_t last_off = L.extra_offs[dyn_idx.dynamic_idx] + extras[dyn_idx.dynamic_idx].data.size();
            if (interp_idx != SIZE_MAX) {  // .interp 在 dynamic 之后，扩展覆盖范围以含它
                last_off = L.extra_offs[interp_idx] + extras[interp_idx].data.size();
            }
            Elf64_Phdr ph = {};
            ph.p_type = PT_LOAD;
            ph.p_flags = PF_R;
            ph.p_offset = first_off;
            ph.p_vaddr = dyn_vaddr_map.at(dyn_idx.dynstr_idx);
            ph.p_paddr = ph.p_vaddr;
            ph.p_filesz = last_off - first_off;
            ph.p_memsz = ph.p_filesz;
            ph.p_align = 0x1000;
            if (fwrite(&ph, sizeof(ph), 1, f) != 1) return false;
        }
        // PT_INTERP：仅让 readelf/file 把 PIE 产物识别为可执行（VM 不消费）
        if (interp_idx != SIZE_MAX) {
            Elf64_Phdr ph = {};
            ph.p_type = PT_INTERP;
            ph.p_flags = PF_R;
            ph.p_offset = L.extra_offs[interp_idx];
            ph.p_vaddr = dyn_vaddr_map.at(interp_idx);
            ph.p_paddr = ph.p_vaddr;
            ph.p_filesz = extras[interp_idx].data.size();
            ph.p_memsz = ph.p_filesz;
            ph.p_align = 1;
            if (fwrite(&ph, sizeof(ph), 1, f) != 1) return false;
        }
        // PT_DYNAMIC（指向 .dynamic section；readelf -d 等工具靠它定位）
        if (need_dynamic) {
            Elf64_Phdr ph = {};
            ph.p_type = PT_DYNAMIC;
            ph.p_flags = PF_R;
            ph.p_offset = L.extra_offs[dyn_idx.dynamic_idx];
            ph.p_vaddr = dyn_vaddr_map.at(dyn_idx.dynamic_idx);
            ph.p_paddr = ph.p_vaddr;
            ph.p_filesz = extras[dyn_idx.dynamic_idx].data.size();
            ph.p_memsz = ph.p_filesz;
            ph.p_align = 8;
            if (fwrite(&ph, sizeof(ph), 1, f) != 1) return false;
        }
        return true;
    }

    // 文件 payload：padding 到段数据区 → 段数据（按段顺序拼接各 section）→ extras
    bool write_payload(FILE* f, const std::vector<SecBuf>& extras, const FileLayout& L) const {
        long pos = ftell(f);
        if ((uint64_t)pos < L.seg_data_off) {
            std::vector<uint8_t> pad(L.seg_data_off - pos, 0);
            if (fwrite(pad.data(), 1, pad.size(), f) != pad.size()) return false;
        }
        // 段数据：按段顺序拼接各 section（section 数据仍在 host pool 的 load 位置）
        for (int c = 0; c < 3; c++) {
            if (!segs_[c].used) continue;
            uint64_t written = 0;
            for (const auto& pr : segs_[c].secs) {
                const LoadedSection& ls = objects_[pr.first].sections[pr.second];
                if (ls.type == SHT_NOBITS) continue;  // bss 不写文件
                uint64_t sec_in_seg = ls.guest_addr - segs_[c].vaddr;
                if (sec_in_seg > written) {
                    std::vector<uint8_t> pad(sec_in_seg - written, 0);
                    if (fwrite(pad.data(), 1, pad.size(), f) != pad.size()) return false;
                    written = sec_in_seg;
                }
                const unsigned char* src = objects_[pr.first].host_mem + ls.offset;
                if (fwrite(src, 1, ls.size, f) != ls.size) return false;
                written += ls.size;
            }
            if (segs_[c].filesz > written) {
                std::vector<uint8_t> pad(segs_[c].filesz - written, 0);
                if (fwrite(pad.data(), 1, pad.size(), f) != pad.size()) return false;
            }
        }
        // extras
        for (size_t i = 0; i < extras.size(); i++) {
            long now = ftell(f);
            uint64_t target = L.extra_offs[i];
            if ((uint64_t)now < target) {
                std::vector<uint8_t> pad(target - now, 0);
                if (fwrite(pad.data(), 1, pad.size(), f) != pad.size()) return false;
            }
            if (fwrite(extras[i].data.data(), 1, extras[i].data.size(), f) != extras[i].data.size())
                return false;
        }
        return true;
    }

    // section headers: NULL → .text → .plt? → .rodata → .data → .got.plt? → .bss? → extras
    bool write_shdrs(FILE* f, const std::vector<SecBuf>& extras, const FileLayout& L,
                      const std::unordered_map<size_t, uint64_t>& dyn_vaddr_map,
                      const ShstrtabOut& names) const {
        bool has_plt = (plt_obj_idx_ < objects_.size());
        bool has_gotplt = (got_obj_idx_ < objects_.size());
        bool has_bss = (names.bss_name_off != 0);

        Elf64_Shdr null_sh = {};
        if (fwrite(&null_sh, sizeof(null_sh), 1, f) != 1) return false;

        // 段级 header（.text/.rodata/.data）：extra_size 排除段内合成 section 大小
        auto emit_seg = [&](int c, Elf64_Word nm, Elf64_Xword flg, Elf64_Word tp,
                             uint64_t extra_size) -> bool {
            Elf64_Shdr sh = {};
            sh.sh_name = nm; sh.sh_type = tp; sh.sh_flags = flg;
            sh.sh_addr = segs_[c].vaddr; sh.sh_offset = L.seg_file_off[c];
            sh.sh_size = (segs_[c].filesz > extra_size) ? (segs_[c].filesz - extra_size) : 0;
            sh.sh_addralign = 0x1000;
            return fwrite(&sh, sizeof(sh), 1, f) == 1;
        };
        // 合成段内子区间的 header（.plt 在 text 段，.got.plt 在 data 段）
        auto emit_synthetic = [&](size_t obj_idx, Elf64_Word nm, Elf64_Xword flg,
                                   int seg_c) -> bool {
            if (obj_idx >= objects_.size()) return true;
            const LoadedSection& ls = objects_[obj_idx].sections[1];
            Elf64_Shdr sh = {};
            sh.sh_name = nm; sh.sh_type = SHT_PROGBITS; sh.sh_flags = flg;
            sh.sh_addr = ls.guest_addr;
            sh.sh_offset = L.seg_file_off[seg_c] + (ls.guest_addr - segs_[seg_c].vaddr);
            sh.sh_size = ls.size;
            sh.sh_addralign = 8;
            return fwrite(&sh, sizeof(sh), 1, f) == 1;
        };
        uint64_t plt_size    = has_plt    ? objects_[plt_obj_idx_].sections[1].size    : 0;
        uint64_t gotplt_size = has_gotplt ? objects_[got_obj_idx_].sections[1].size    : 0;
        if (segs_[SEG_TEXT].used   && !emit_seg(SEG_TEXT,   names.text_name_off,   SHF_ALLOC|SHF_EXECINSTR, SHT_PROGBITS, plt_size)) return false;
        if (has_plt               && !emit_synthetic(plt_obj_idx_,  names.plt_name_off,  SHF_ALLOC|SHF_EXECINSTR, SEG_TEXT))  return false;
        if (segs_[SEG_RODATA].used && !emit_seg(SEG_RODATA, names.rodata_name_off, SHF_ALLOC,               SHT_PROGBITS, 0)) return false;
        if (segs_[SEG_DATA].used   && !emit_seg(SEG_DATA,   names.data_name_off,   SHF_ALLOC|SHF_WRITE,    SHT_PROGBITS, gotplt_size)) return false;
        if (has_gotplt            && !emit_synthetic(got_obj_idx_, names.gotplt_name_off, SHF_ALLOC|SHF_WRITE,    SEG_DATA))  return false;
        if (has_bss) {
            Elf64_Shdr sh = {};
            sh.sh_name = names.bss_name_off; sh.sh_type = SHT_NOBITS; sh.sh_flags = SHF_ALLOC|SHF_WRITE;
            sh.sh_addr = segs_[SEG_DATA].vaddr + segs_[SEG_DATA].filesz;
            sh.sh_offset = L.seg_file_off[SEG_DATA] + segs_[SEG_DATA].filesz;  // NOBITS：offset 无意义
            sh.sh_size = segs_[SEG_DATA].memsz - segs_[SEG_DATA].filesz;
            sh.sh_addralign = 0x10;
            if (fwrite(&sh, sizeof(sh), 1, f) != 1) return false;
        }
        for (size_t i = 0; i < extras.size(); i++) {
            Elf64_Shdr sh = {};
            sh.sh_name = names.extra_name_offs[i];
            sh.sh_type = extras[i].type;
            sh.sh_flags = extras[i].flags;
            sh.sh_offset = L.extra_offs[i];
            sh.sh_size = extras[i].data.size();
            sh.sh_link = extras[i].link;
            sh.sh_info = extras[i].info;
            sh.sh_addralign = extras[i].addralign;
            sh.sh_entsize = extras[i].entsize;
            auto vit = dyn_vaddr_map.find(i);
            if (vit != dyn_vaddr_map.end()) sh.sh_addr = vit->second;
            if (fwrite(&sh, sizeof(sh), 1, f) != 1) return false;
        }
        return true;
    }

    // 辅助：取 obj.sections[sec_idx] 的 guest 地址（write_elf 用）
    uint64_t sec_guest_addr_of(const LoadedObject& obj, size_t sec_idx) const {
        if (sec_idx >= obj.sections.size()) return 0;
        return obj.sections[sec_idx].guest_addr;
    }

    // 应用一个 .o 的所有重定位
    bool apply_relocations(size_t obj_idx) {
        auto& obj = objects_[obj_idx];
        // PIC 模式：绝对引用（lddw/数据指针）不构建期 patch，留占位给 VM 运行时填
        const bool pic = (mode_ == Mode::SHARED_LIB || mode_ == Mode::DYNAMIC_EXE);
        for (const auto& r : obj.relocations) {
            if (r.target_sec >= obj.sections.size()) continue;
            const auto& target = obj.sections[r.target_sec];
            if (!target.loadable) continue;

            auto resolved = resolve_symbol(obj_idx, r.sym_idx);
            const auto& sym = obj.symbols[r.sym_idx];
            const bool fp_ksym = is_fp_ksym(sym.name);   // FP 虚拟指令符号（VM 运行时解释）
            if (!resolved && !fp_ksym) {
                // check_undefined_symbols（static+dynamic 都已跑）已保证无真正未定义符号；
                // 走到这里 = .so 提供的符号（运行时解析，仅 PIC 会出现）。R_BPF_64_32 (call)
                // 经 PLT 桩（plt_addr_ 构建期已知，走下面 case 10）；其余留 .rela.dyn 给 VM 运行时填。
                if (!(r.type == 10 && got_enabled_ && plt_addr_.count(sym.name))) {
                    continue;
                }
            }
            uint64_t S = resolved.value_or(0);

            uint8_t* patch = obj.host_mem + target.offset + r.offset;
            // 写入越界校验（按 reloc 类型确定写入宽度）
            if (r.offset + reloc_write_len(r.type) > target.size) {
                std::cerr << "[elf_linker] relocation out of bounds in " << obj.source
                          << ": offset=" << r.offset << " type=" << r.type
                          << " sec_size=" << target.size << "\n";
                return false;
            }
            // r.addend 已在加载时统一填好（SHT_RELA: r_addend；SHT_REL: patch 点 embedded）
            switch (r.type) {
            case 1: {  // R_BPF_64_64 — lddw 64-bit absolute address
                // lddw 占两个 8 字节指令槽；64 位值拆成两个 32 位写到各自的 imm 字段
                // imm 字段分别在 byte 4-7 和 byte 12-15
                if (pic) break;  // PIC：不 patch，r.addend 供 .rela.dyn 生成用
                uint64_t V = S + (uint64_t)r.addend;
                uint32_t lo = (uint32_t)V;
                uint32_t hi = (uint32_t)(V >> 32);
                if (g_debug) {
                    const auto& sym = obj.symbols[r.sym_idx];
                    std::cerr << "[reloc] R_BPF_64_64 @ " << obj.source << " off=0x" << std::hex
                                << r.offset << " sym=" << sym.name << " S=0x" << S
                                << " V=0x" << V << std::dec << "\n";
                }
                memcpy(patch + 4, &lo, 4);
                memcpy(patch + 12, &hi, 4);
                break;
            }
            case 2: {  // R_BPF_64_ABS64 — 64-bit absolute, used for .data pointers
                if (pic) break;  // PIC：不 patch
                uint64_t V = S + (uint64_t)r.addend;
                if (g_debug) {
                    const auto& sym = obj.symbols[r.sym_idx];
                    std::cerr << "[reloc] R_BPF_64_ABS64 @ " << obj.source << " off=0x" << std::hex
                                << r.offset << " sym=" << sym.name << " S=0x" << S
                                << " A=0x" << r.addend << " V=0x" << V << std::dec << "\n";
                }
                memcpy(patch, &V, 8);
                break;
            }
            case 10: {  // R_BPF_64_32 — 32-bit relative for BPF_CALL
                // FP 虚拟指令符号：pass 用 extern __ksym __bpf_fp_<ID> 生成，clang emit
                // src_reg=1 + 本重定位。linker 改写为 src_reg=2 + imm=<ID>（FP 专用通道，
                // VM 按 src_reg=2 走 do_softfp）。byte[1] 高 4 位是 src_reg：0x10→0x20。
                if (fp_ksym) {
                    uint32_t fp_id = 0;
                    if (!parse_fp_ksym_id(sym.name, fp_id)) {
                        std::cerr << "[elf_linker] malformed FP ksym name: " << sym.name << "\n";
                        return false;
                    }
                    patch[1] = (patch[1] & 0x0f) | 0x20;   // src_reg: 1 -> 2
                    int32_t imm = (int32_t)fp_id;
                    memcpy(patch + 4, &imm, 4);
                    if (g_debug) {
                        std::cerr << "[reloc] R_BPF_64_32 FP @ " << obj.source << " off=0x"
                                  << std::hex << r.offset << " sym=" << sym.name
                                  << " -> src_reg=2 imm=0x" << fp_id << std::dec << "\n";
                    }
                    break;
                }
                // 普通 call：imm = (target - call_site) / 8 - 1
                // clang 对未解析 call 写 imm=-1（占位符），不是有效 addend，必须忽略。
                //（BPF call 的 imm 单位是 bpf_insn；VM 执行 pc+=imm 后 pc++ 到下一条，
                // 所以 target = call_site + (imm+1)*8 → imm = (target-call_site)/8 - 1）
                uint64_t call_site = target.guest_addr + r.offset;
                uint64_t tgt = S;
                // PIC + UND 符号：跨模块函数调用走 PLT 桩（运行期 GOT 间接）。
                // 内部定义符号（resolved 成功）直接相对 call，不走 PLT（对齐标准 ld 默认行为）。
                if (!resolved && got_enabled_ && r.sym_idx < obj.symbols.size()) {
                    auto pit = plt_addr_.find(obj.symbols[r.sym_idx].name);
                    if (pit != plt_addr_.end()) tgt = pit->second;
                }
                int64_t byte_off = (int64_t)tgt - (int64_t)call_site;
                int32_t imm = (int32_t)(byte_off / 8 - 1);
                if (g_debug) {
                    std::cerr << "[reloc] R_BPF_64_32 @ " << obj.source << " off=0x" << std::hex
                                << r.offset << " sym=" << sym.name << " tgt=0x" << tgt
                                << " call_site=0x" << call_site << std::dec << " imm=" << imm << "\n";
                }
                memcpy(patch + 4, &imm, 4);
                break;
            }
            case 4: {  // R_BPF_64_NODYLD32 — 32-bit absolute
                uint32_t V = (uint32_t)(S + r.addend);
                memcpy(patch, &V, 4);
                break;
            }
            default:
                break;
            }
        }
        return true;
    }

    // 合成 GOT(.got, SEG_DATA)与 PLT(.plt, SEG_TEXT)，追加到 pool 末尾。
    // 默认对所有被 R_BPF_64_32 引用的 UND 函数分配 8 字节 GOT 槽 + 40 字节 PLT 桩
    // （标准 ld 默认行为：跨模块函数调用走 PLT/GOT）。
    // guest_addr 由 layout_segments 分配；PLT 桩字节码由 finalize_plt_stubs 回填。
    bool synthesize_got_plt() {
        // 收集实际被引用的 UND 函数符号（去重，保持顺序）
        std::vector<std::string> got_syms;
        std::set<std::string> seen;
        for (const auto& obj : objects_) {
            for (const auto& r : obj.relocations) {
                if (r.type != 10) continue;  // R_BPF_64_32 (call)
                if (r.sym_idx >= obj.symbols.size()) continue;
                const auto& sym = obj.symbols[r.sym_idx];
                if (sym.defined) continue;  // 内部函数：相对 call，不需要 PLT
                // UND 但定义在其它已加载成员（.a/.o）里：仍是内部 call，不走 PLT/GOT。
                //（resolve_symbol 会经 globals_ 把它解析成直接相对 call。）
                if (globals_.count(sym.name)) continue;
                // FP 虚拟指令符号：apply_relocations 已把 call 改写成 src_reg=2 + imm，
                // 不再是跨模块函数调用，不走 PLT/GOT（否则 runtime loader 会因找不到
                // 这些虚拟符号而报警）。
                if (is_fp_ksym(sym.name)) continue;
                if (seen.insert(sym.name).second) got_syms.push_back(sym.name);
            }
        }
        // DYNAMIC_EXE：入口符号（_start）通常在 .so，主程序不引用也得有 PLT 桩作 e_entry
        if (mode_ == Mode::DYNAMIC_EXE && !entry_name_.empty()) {
            // 确认入口符号是 UND（在 .so 里）且主程序未定义
            bool main_defined = (globals_.find(entry_name_) != globals_.end());
            if (!main_defined && seen.insert(entry_name_).second) {
                got_syms.push_back(entry_name_);
            }
        }
        if (got_syms.empty()) return true;  // 无跨模块函数调用

        // GOT 段：N*8 字节，初值 0（运行期由加载器填函数地址）
        pool_used_ = (pool_used_ + 7) & ~size_t(7);
        size_t got_off = pool_used_;
        size_t got_bytes = got_syms.size() * 8;
        if (got_off + got_bytes > pool_size_) {
            std::cerr << "[elf_linker] pool exhausted for GOT\n";
            return false;
        }
        memset(pool_ + got_off, 0, got_bytes);
        pool_used_ += got_bytes;
        size_t got_obj_idx = objects_.size();
        {
            LoadedObject go;
            go.source = ".got (synthetic)";
            go.base = guest_base_ + got_off;
            go.pool_offset = got_off;
            go.total_size = got_bytes;
            go.host_mem = pool_ + got_off;
            go.host_mem_size = got_bytes;
            LoadedSection n; n.type = SHT_NULL; go.sections.push_back(n);
            LoadedSection gs;
            gs.name = ".got.plt"; gs.type = SHT_PROGBITS; gs.loadable = true;
            gs.writable = true; gs.executable = false; gs.seg = SEG_DATA;
            gs.offset = 0; gs.size = got_bytes;  // guest_addr 由 layout 填
            go.sections.push_back(gs);
            objects_.push_back(std::move(go));
        }
        // PLT 段：N*kPltStubSize 字节，初值 0（字节码待回填）
        pool_used_ = (pool_used_ + 7) & ~size_t(7);
        size_t plt_off = pool_used_;
        size_t plt_bytes = got_syms.size() * kPltStubSize;
        if (plt_off + plt_bytes > pool_size_) {
            std::cerr << "[elf_linker] pool exhausted for PLT\n";
            return false;
        }
        memset(pool_ + plt_off, 0, plt_bytes);
        pool_used_ += plt_bytes;
        size_t plt_obj_idx = objects_.size();
        {
            LoadedObject po;
            po.source = ".plt (synthetic)";
            po.base = guest_base_ + plt_off;
            po.pool_offset = plt_off;
            po.total_size = plt_bytes;
            po.host_mem = pool_ + plt_off;
            po.host_mem_size = plt_bytes;
            LoadedSection n; n.type = SHT_NULL; po.sections.push_back(n);
            LoadedSection ts;
            ts.name = ".plt"; ts.type = SHT_PROGBITS; ts.loadable = true;
            ts.executable = true; ts.writable = false; ts.seg = SEG_TEXT;
            ts.offset = 0; ts.size = plt_bytes;
            po.sections.push_back(ts);
            objects_.push_back(std::move(po));
        }
        for (size_t i = 0; i < got_syms.size(); i++) {
            got_slots_[got_syms[i]] = {got_obj_idx, i * 8};
            plt_entries_[got_syms[i]] = {plt_obj_idx, i * kPltStubSize};
        }
        // 记录 GOT 段的 obj_idx，供 .rela.dyn 生成 PLT 桩 lddw 重定位用
        got_obj_idx_ = got_obj_idx;
        plt_obj_idx_ = plt_obj_idx;
        got_syms_ = got_syms;
        got_enabled_ = true;
        if (g_debug) std::cerr << "[elf_linker] GOT/PLT synthesized: " << got_syms.size()
                  << " sym(s), " << plt_bytes << "B .plt, " << got_bytes << "B .got\n";
        return true;
    }

    // layout_segments 后回填 PLT 桩字节码并记录桩 guest_addr（供 apply_relocations 用）。
    bool finalize_plt_stubs() {
        for (const auto& [sym, pe] : plt_entries_) {
            auto git = got_slots_.find(sym);
            if (git == got_slots_.end()) continue;
            const LoadedSection& got_sec = objects_[git->second.obj_idx].sections[1];
            const LoadedSection& plt_sec = objects_[pe.obj_idx].sections[1];
            uint64_t slot_addr = got_sec.guest_addr + git->second.offset;
            emit_plt_stub(objects_[pe.obj_idx].host_mem + pe.offset, slot_addr);
            plt_addr_[sym] = plt_sec.guest_addr + pe.offset;
        }
        return true;
    }

    // 写一个 kPltStubSize 字节 PLT 桩到 p（p 已 memset 0）：
    //   lddw r6, <slot>   ; GOT 槽地址（构建期已知）
    //   ldx  r6, [r6]     ; 读槽内容（函数运行期地址）
    //   call *r6          ; 0x8D 间接调用
    //   exit              ; 返回调用者（对应 call <plt> 的 push_frame）
    static void emit_plt_stub(uint8_t* p, uint64_t slot_addr) {
        p[0] = 0x18; p[1] = 0x06;                          // lddw r6 (BPF_LD|BPF_DW|BPF_IMM, dst=6 src=0)
        uint32_t lo = (uint32_t)slot_addr;       memcpy(p + 4,  &lo, 4);
        uint32_t hi = (uint32_t)(slot_addr >> 32); memcpy(p + 12, &hi, 4);
        p[16] = 0x79; p[17] = 0x66;                        // ldx r6,[r6] (BPF_LDX|BPF_DW|BPF_MEM, dst=6 src=6)
        p[24] = 0x8d; p[25] = 0x06;                        // call *r6 (BPF_JMP|BPF_CALL|BPF_X, dst_reg=6)
        p[32] = 0x95;                                      // exit (BPF_JMP|BPF_EXIT)
    }
};

}  // namespace

bool link_bpf_object(const std::vector<std::string>& inputs, const std::string& out_path,
                     const std::vector<std::string>& archives) {
    Linker linker;
    linker.set_archives(archives);
    if (!linker.run(inputs)) return false;
    return linker.write_elf(out_path);
}

bool link_bpf_shared(const std::vector<std::string>& inputs, const std::string& out_path,
                     const std::string& soname,
                     const std::vector<std::string>& deps) {
    Linker linker(Linker::Mode::SHARED_LIB);
    linker.set_soname(soname);
    linker.set_deps(deps);
    if (!linker.run(inputs)) return false;
    return linker.write_elf(out_path);
}

bool link_bpf_exe(const std::vector<std::string>& inputs, const std::string& out_path,
                  const std::vector<std::string>& deps,
                  const std::string& entry_name) {
    Linker linker(Linker::Mode::DYNAMIC_EXE);
    linker.set_deps(deps);
    linker.set_entry_name(entry_name);
    if (!linker.run(inputs)) return false;
    return linker.write_elf(out_path);
}

