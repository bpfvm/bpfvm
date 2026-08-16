//
// elf_linker.cpp — BPF 离线链接器核心（bpfvm-ld 专用）
//
// Linker 类把多个 .o/archive 合并到一个
// 连续 host pool，应用重定位，导出 ET_EXEC ELF（静态）或带 DT_NEEDED 的动态产物。
// VM 端的加载（含 DT_NEEDED 动态加载）统一在 elf_loader.cpp 的 load_elf 处理。
//
// 流程：
//   -  加载主 .o：解析所有 section、符号、重定位。
//   -  依赖来自命令行 -l archive（由 ld_main 解析为完整路径），全展开。
//   -  聚合所有 GLOBAL 符号到全局符号表。
//   -  应用所有重定位（R_BPF_64_64 / R_BPF_64_ABS64 / R_BPF_64_32 / R_BPF_64_NODYLD32）。
//   -  找入口（_start / main），写出 ET_EXEC。
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
#include <unordered_set>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <optional>
#include <cstring>
#include <cctype>
#include <functional>
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
    // 原始 ELF 元数据，-r (partial link) 合并段/重写 shdr 时需忠实保留。
    // final-link 路径不读这些字段，默认值不影响其行为。
    Elf64_Xword sh_flags = 0;    // 原 sh_flags（SHF_ALLOC|SHF_EXECINSTR|SHF_WRITE 等）
    Elf64_Xword addralign = 1;   // 原 sh_addralign
    Elf64_Xword entsize = 0;     // 原 sh_entsize
};

// 符号
struct LoadedSym {
    std::string name;
    size_t sec_idx = SIZE_MAX;  // 所属 section 在 LoadedObject::sections 的下标；UND -> SIZE_MAX
    uint64_t value = 0;         // section 内偏移
    uint64_t size = 0;
    int binding = 0;
    int type = 0;
    int visibility = STV_DEFAULT;  // 符号可见性（st_other 低 2 位）。hidden 不导出到 .dynsym
    bool defined = false;       // sec_idx != SIZE_MAX
};

// 重定位
struct LoadedReloc {
    size_t target_sec;          // 要 patch 的 section 下标
    uint64_t offset;            // 在该 section 内的偏移
    int type;
    size_t sym_idx;             // LoadedObject::symbols 下标
    int64_t addend = 0;         // SHT_RELA: 来自 r_addend；SHT_REL: 加载时从 patch 点读取
    bool is_rela = true;        // 来源段 SHT_RELA(true)/SHT_REL(false)；-r 统一输出为 RELA
};

// 调试 section（.debug_*）的搬运记录。debug 段非 VM-loadable，不进 host pool、不占 guest
// 地址，独立按段落到输出的 extras 区（non-ALLOC SHT_PROGBITS），供 readelf/objdump 等离线
// 工具消费。extra_idx 由 write_elf_impl 在 push 进 extras 后回填。
struct DebugSec {
    std::string name;            // ".debug_info" 等
    size_t sec_idx;              // obj.sections 下标（对齐 ELF shndx，reloc.target_sec 用）
    Elf64_Xword addralign = 1;   // sh_addralign（输出时保留对齐）
    std::vector<uint8_t> data;   // 原始字节（写出时复制进 SecBuf 并按需 patch 重定位）
    size_t extra_idx = SIZE_MAX; // 写出时在 extras[] 里的位置
    // 本 obj 的该段在合并后的同名输出段中的字节起始偏移（collect_debug_sections 填）。
    // 多 .o 链接时同名 .debug_* 段按输入顺序拼接成一个输出段；contrib_off 标出本 .o
    // 贡献区的起点。debug->debug 重定位（debug_abbrev_offset / DW_AT_str_offsets_base /
    // DW_AT_addr_base / DW_AT_stmt_list 等）必须用 contrib_off + sym.value 定位本 .o 的
    // contribution，否则跨 .o 的 CU 全部错位（gdb 报 "Could not find abbrev" /
    // "DW_FORM_addrx outside .debug_addr"）。
    size_t contrib_off = 0;
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
    std::vector<DebugSec> debug_secs;  // 本 obj 拥有的 .debug_* 段（按出现顺序）
    // obj.sections[idx] -> debug_secs 下标；只对属于 debug 的 section 有效
    std::unordered_map<size_t, size_t> dbg_sec_local_idx;
    // clang -fstack-size-section 产出的 .stack_sizes 段原始字节（keep_debug 时搬运）。
    // 用于链接期修复 DW_OP_fbreg 偏移（见 fix_fbreg_offsets）。每条记录 =
    // [8字节 ABS64 重定位 -> 函数 .text 地址][ULEB128 stacksize]，重定位在 obj.relocations 里。
    std::vector<uint8_t> stack_sizes_data;
    size_t stack_sizes_sec_idx = SIZE_MAX;  // .stack_sizes 在 obj.sections 的下标（reloc 查找用）
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
    // 逻辑大小。-r (partial link) 的 NOBITS 段（.bss）无数据但需非零 size；
    // PROGBITS 段与 data.size() 等价。final-link 路径不读此字段。
    Elf64_Xword size = 0;
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

// ELF section type -> 是否需要加载到 VM
// SHT_INIT_ARRAY/SHT_FINI_ARRAY 是全局构造/析构函数指针表，必须加载（进 SEG_DATA），
// 否则 musl 的 __libc_start_init 循环（[__init_array_start, __init_array_end)）拿不到
// ctor 列表，全局 C++ 对象不会构造。
bool is_loadable_section(Elf64_Word type) {
    return type == SHT_PROGBITS || type == SHT_NOBITS ||
           type == SHT_INIT_ARRAY || type == SHT_FINI_ARRAY;
}

// 标准 ld 的 orphan section 边界符号前缀
// __start_<name>（首，8 字符）/ __stop_<name>（尾，7 字符）。如 section "__lcxx_override"
// -> __start___lcxx_override（三 _: 前缀尾 1 + section 头 2）。
constexpr const char* kSectionStartPrefix = "__start_";  // 8 字符
constexpr const char* kSectionStopPrefix  = "__stop_";   // 7 字符

// 正向：符号名 -> {is_start, section_name}；未命中返回 nullopt。
std::optional<std::pair<bool, std::string>> parse_section_boundary_sym(const std::string& sym) {
    std::string_view sv(sym);
    std::string_view sp(kSectionStartPrefix);
    std::string_view tp(kSectionStopPrefix);
    if (sv.size() > sp.size() && sv.substr(0, sp.size()) == sp)
        return std::make_pair(true, std::string(sv.substr(sp.size())));
    if (sv.size() > tp.size() && sv.substr(0, tp.size()) == tp)
        return std::make_pair(false, std::string(sv.substr(tp.size())));
    return std::nullopt;
}

// 反向：section 名 + is_start -> 符号名。
std::string make_section_boundary_sym(const std::string& sec, bool is_start) {
    return std::string(is_start ? kSectionStartPrefix : kSectionStopPrefix) + sec;
}

// 按 section 属性分流到输出段：可写（含 .bss）-> data；可执行 -> text；只读 -> rodata。
// 可写优先于可执行：W^X 要求代码不可写，即便异常地同时带 EXECINSTR|WRITE 也归 data。
SegClass classify_section(bool executable, bool writable) {
    if (writable) return SEG_DATA;
    if (executable) return SEG_TEXT;
    return SEG_RODATA;
}

// DWARF 调试段（.debug* 及其 .rel.debug*）：可保留到输出（keep_debug 时）。
// 与 .BTF 等分离——BTF 是 BPF 内核用、VM 无需，仍无条件跳过。
bool is_dwarf_section(const std::string& name) {
    if (name.empty()) return false;
    if (name.rfind(".debug", 0) == 0) return true;
    if (name.rfind(".rel.debug", 0) == 0) return true;
    return false;
}

// 判断 section 是否需要跳过（BTF/llvm_addrsig 等；DWARF 由 is_dwarf_section 单独判）
bool is_debug_section(const std::string& name) {
    if (name.empty()) return false;
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
    case 3:  return 4;   // R_BPF_64_ABS32 (DWARF 段偏移引用)
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
    case 3: {  // R_BPF_64_ABS32: 4 字节（DWARF 段偏移引用）
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
        RELOCATABLE,  // -r：输入 .o/.a，合并为单个 ET_REL（保留重定位、不解析符号，无 segment/入口）
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
    std::unordered_map<std::string, GotPltLoc> got_slots_;   // sym -> GOT 槽（合成 .got 内偏移）
    std::unordered_map<std::string, GotPltLoc> plt_entries_; // sym -> PLT 桩（合成 .plt 内偏移）
    std::unordered_map<std::string, uint64_t> plt_addr_;     // sym -> 桩 guest_addr（layout 后回填）
    bool got_enabled_ = false;
    size_t got_obj_idx_ = SIZE_MAX;  // 合成 .got.plt 的 obj idx（DT_PLTGOT 指向它）
    size_t plt_obj_idx_ = SIZE_MAX;  // 合成 .plt 的 obj idx（运行时按 section 名定位）
    std::vector<std::string> got_syms_;  // PLT/GOT 符号顺序（.rela.plt 按此顺序生成）
    std::vector<std::string> explicit_archives_;  // STATIC_EXE: 命令行 -l archive（完整路径）
    std::vector<LoadedObject> objects_;
    std::unordered_map<std::string, GlobalSymbol> globals_;
    bool keep_debug_ = true;  // 默认保留 DWARF 调试段（对齐标准 ld）
    bool keep_symtab_ = true; // 默认输出静态 .symtab/.strtab（-s/--strip-all 关闭，对齐 ld）

    // === -r (RELOCATABLE) 专用状态 ===
    // (obj_idx, sec_idx) -> 该输入段在合并输出段中的字节贡献起点
    std::map<std::pair<size_t,size_t>, size_t> rel_contrib_off_;
    // (obj_idx, sec_idx) -> 该输入段对应的输出 section 在 extras_ 里的下标
    std::map<std::pair<size_t,size_t>, size_t> rel_sec_out_index_;
    // (obj_idx, sym_idx) -> 该输入符号在输出 .symtab 中的索引（供重定位 r_info 重索引）
    std::map<std::pair<size_t,size_t>, size_t> rel_sym_out_index_;
    // 仍 UND 的符号名 -> 输出 symtab 索引（UND 条目无 obj/si，按名查）
    std::unordered_map<std::string, size_t> rel_und_name_index_;

    // 函数 guest 地址 -> 栈大小（来自 .stack_sizes，build_stack_size_map 填充）。
    // 供 fix_fbreg_offsets 修正 DW_OP_fbreg 偏移（clang BPF 后端把栈变量偏移算错为
    // +(stacksize-N)，正确应为 -N；linker 用此表把 +N 改成 +N-stacksize）。
    std::unordered_map<uint64_t, uint64_t> stack_sizes_;

    // loclistx 索引 -> 所属函数栈大小（fix_fbreg_offsets 扫 .debug_info 时填）。
    // .debug_loclists 里的 DW_OP_breg10 偏移有同 fbreg 一样的 bug（应为 -N 算成 +N），
    // fix_loclists_breg10 用此表按 loclist 所属函数修正。
    // 键 = loclists_base(合并段内绝对偏移) + loclistx 索引；与 fix_loclists_breg10 里
    // 的 loclists_base + i 一致（注意：用【旧】base，即重建前的贡献区起点 +12）。
    std::unordered_map<uint64_t, uint64_t> loclist_ss_;

    // loclists_base 旧值 -> 新值（fix_loclists_breg10 重建 .debug_loclists 后填）。
    // 贡献区按真实长度重建（不再 padding），后续贡献区起点会位移 -> 其 loclists_base 改变，
    // remap_loclists_base 据此定长改写 .debug_info 里的 DW_AT_loclists_base(sec_offset)。
    std::unordered_map<uint64_t, uint64_t> loclists_base_remap_;

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

    // .init_array/.fini_array 拼接区间的边界（layout_segments 填充）。
    // present 表示对应 section 存在；空时 define_init_fini_symbols 不合成边界符号——
    // 留给 musl 的 weak UND 引用走标准 ld 语义（解析到 libc.so 的真实定义，或静态/动态
    // 链接器把 weak UND 解析为 0）。否则合成为 GLOBAL ABS、值为 0 的符号会被 musl ldso
    // 的 find_sym2 当「st_value==0 跳过」而报 symbol not found（见 dynlink.c 的
    // `if (!sym->st_value) continue`），且与 libc.so 自身的 musl 定义重复污染符号表。
    struct InitFiniArray {
        uint64_t start = 0;   // 首 section 的 guest_addr
        uint64_t end = 0;      // 末 section 的 guest_addr + size
        bool present = false;  // 是否存在对应 section（即使 size==0 也为 true）
        uint64_t size() const { return end - start; }
        bool empty() const { return end <= start; }  // size==0（含无 section）
    };
    InitFiniArray init_array_;
    InitFiniArray fini_array_;

    // 合成全局符号（name -> guest vaddr）：__init_array_start/end、__fini_array_*、
    // __dso_handle 等。resolve_symbol 先查这里；build_static/dynamic_symtab 会遍历
    // 它们 emit 到符号表。与 globals_（必须指向真实 obj symbol）不同，这里存的是
    // linker 凭空合成的定义。
    std::unordered_map<std::string, uint64_t> synthetic_globals_;

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
    // 是否需要 ELF header + phdr 表被映射进 guest（生成 PT_PHDR + 首段覆盖文件头）。
    // 可执行文件（STATIC_EXE/DYNAMIC_EXE）总是需要（loader/crt 读 auxv AT_PHDR + __ehdr_start）。
    // 普通 .so 不需要（VM loader 用 libelf 读文件，不读内存）。但 ldso 是"可执行的 .so"——
    // 它的 guest 代码（__dls2 等）要读 __ehdr_start 定位自身 phdr/dynv，故也需映射 ELF header。
    // 判据：SHARED_LIB 且显式指定了入口符号（-e _dlstart）即为 ldso。
    bool need_ehdr() const {
        return mode_ != Mode::SHARED_LIB || entry_name_ != "_start";
    }
    void set_needed(std::vector<std::string> n) { needed_ = std::move(n); }
    void set_deps(std::vector<std::string> d) { dep_paths_ = std::move(d); }
    void set_archives(std::vector<std::string> a) { explicit_archives_ = std::move(a); }
    void set_keep_debug(bool b) { keep_debug_ = b; }
    void set_keep_symtab(bool b) { keep_symtab_ = b; }

    // 输入文件按内容（而非扩展名）判定的类型。kbuild 产出的 built-in.o 名字固定，
    // 内容却可能是空 ar 归档（lib-y 目录占位）或 ET_DYN（obj-y 目录 clang -r 产物），
    // 按扩展名分发会误判，故统一嗅探 magic + ELF e_type。
    enum class InputKind { ARCHIVE, REL, DYN, NOT_FOUND };
    InputKind classify_input(const std::string& path) {
        std::vector<uint8_t> data;
        if (!read_file(path, data)) return InputKind::NOT_FOUND;
        // ar 归档 magic "!<arch>\n"（含 8 字节空归档）
        static const char ar_magic[8] = {'!', '<', 'a', 'r', 'c', 'h', '>', '\n'};
        if (data.size() >= 8 && memcmp(data.data(), ar_magic, 8) == 0)
            return InputKind::ARCHIVE;
        // ELF：嗅探 e_type 区分 ET_REL 与 ET_DYN/ET_EXEC
        Elf* elf = elf_memory((char*)data.data(), data.size());
        if (elf && elf_kind(elf) == ELF_K_ELF) {
            GElf_Ehdr ehdr;
            if (gelf_getehdr(elf, &ehdr) == &ehdr) {
                elf_end(elf);
                return (ehdr.e_type == ET_REL) ? InputKind::REL : InputKind::DYN;
            }
        }
        if (elf) elf_end(elf);
        // 既非 ar 也非 ELF：交给 load_rel_file 走原有报错路径（保持兼容）
        return InputKind::REL;
    }

    // 按文件实际内容加载：ar 归档->全展开、ET_REL->目标、ET_DYN->动态符号+DT_NEEDED。
    bool load_input(const std::string& in) {
        switch (classify_input(in)) {
            case InputKind::NOT_FOUND:
                std::cerr << "[elf_linker] cannot find input: " << in << "\n";
                return false;
            case InputKind::ARCHIVE:
                load_archive_file(in);   // 空/有成员归档都正确处理（空归档天然无害）
                return true;
            case InputKind::DYN:
                return load_bpfso_symbols(in);   // 只读 .dynsym + DT_NEEDED，不并入段
            case InputKind::REL:
                return load_rel_file(in) != SIZE_MAX;
        }
        return false;
    }

    // 执行链接
    bool run(const std::vector<std::string>& inputs) {
        if (!pool_) return false;

        if (elf_version(EV_CURRENT) == EV_NONE) {
            std::cerr << "[elf_linker] libelf init failed\n";
            return false;
        }

        // -r (partial link) 走独立路径，不复用 final-link 的 layout/reloc/入口机器
        if (mode_ == Mode::RELOCATABLE) {
            return run_relocatable(inputs);
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
            // 这里加载只为读 DT_SONAME -> needed_，从而输出 DT_NEEDED）。
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
            // 动态主程序：依赖按文件实际内容分流——
            //   ar 归档 -> 静态拉入成员（符号进 globals_，内部相对 call 解析）；
            //   ET_REL -> 当作附加对象静态链入；
            //   ET_DYN/ET_EXEC -> 动态依赖（只读 dynsym + DT_NEEDED，跨模块调用走 PLT/GOT）。
            for (const auto& dep : dep_paths_) {
                switch (classify_input(dep)) {
                    case InputKind::NOT_FOUND:
                        std::cerr << "[elf_linker] failed to load dep: " << dep << "\n";
                        return false;
                    case InputKind::ARCHIVE:
                        load_archive_file(dep);
                        break;
                    case InputKind::REL:
                        if (load_rel_file(dep) == SIZE_MAX) {
                            std::cerr << "[elf_linker] failed to load dep: " << dep << "\n";
                            return false;
                        }
                        break;
                    case InputKind::DYN:
                        if (!load_bpfso_symbols(dep)) {
                            std::cerr << "[elf_linker] failed to load dep: " << dep << "\n";
                            return false;
                        }
                        break;
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
        // 先合成不依赖 layout 的符号（__dso_handle + __start___/___stop section 边界），
        // 让 check 把它们当已定义。
        // __dso_handle 用占位值 1（非 0——避免被误当 UND/weak 未定义）。musl 静态链接下
        // __cxa_atexit 的 dtor 链表对 dso_handle 值不敏感（靠链表管理），故 1 能让
        // test_cpp_ctor 通过；标准 ld 让 __dso_handle 指向自身对象地址，这里用固定占位是折衷。
        synthetic_globals_["__dso_handle"] = 1;
        collect_section_boundary_refs();   // 预登记 __start___<sec>/__stop___<sec>（占位）
        if (mode_ != Mode::SHARED_LIB && !check_undefined_symbols()) return false;

        // 运行时 GOT/PLT 合成（DYNAMIC_EXE + SHARED_LIB 默认对所有 UND 函数）：
        // BPF call 是相对偏移，跨模块调用必须经 PLT/GOT 间接（callx）。
        // 主程序和 .so 各有自己的 PLT/GOT，供内部对 UND 函数的调用用。
        if ((mode_ == Mode::DYNAMIC_EXE || mode_ == Mode::SHARED_LIB) && !synthesize_got_plt()) return false;

        // 全局 3 段布局：分配 guest vaddr（必须在 apply_relocations 前，重定位读 guest_addr）
        layout_segments();

        // layout 后 .init_array/.fini_array 边界 vaddr 已定：合成 __init_array_start/end
        // 等符号（apply_relocations 会 resolve 这些符号，必须先定义）。
        define_init_fini_symbols();
        // layout 后各自定义 section（如 __lcxx_override）边界 vaddr 已定：合成
        // __start___<sec>/__stop___<sec>（标准 ld 对 orphan section 的 __start_/__stop_ 合成）。
        define_section_boundary_symbols();

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
            // -  主程序内的全局符号（STATIC_EXE 的 _start，或 DYNAMIC_EXE 主程序自带入口）
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
                // -  DYNAMIC_EXE：_start 在 .so，走 PLT/GOT，entry 指向 PLT 桩
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
        } else {
            // SHARED_LIB：普通 .so 无入口（entry_ 保持 0）。但 ldso 是特殊的 .so——它需要
            // e_entry 指向自身入口（_dlstart），供 VM 加载后从那里开始执行动态链接流程。
            // 仅当显式指定 -e 且符号存在时设置，普通 .so（默认 _start 通常不在 .so 内）不受影响。
            auto it = globals_.find(entry_name_);
            if (it != globals_.end()) {
                const auto& obj = objects_[it->second.obj_idx];
                const auto& sym = obj.symbols[it->second.sym_idx];
                const auto& sec = obj.sections[sym.sec_idx];
                entry_ = sec.guest_addr + sym.value;
                if (g_debug) std::cerr << "[elf_linker] entry: " << entry_name_
                          << " @ 0x" << std::hex << entry_ << std::dec
                          << " from " << obj.source << " (SHARED_LIB)\n";
            }
        }
        return true;
    }

    // 全局 3 段布局：把所有 object 的 loadable section 按 SEG_TEXT/RODATA/DATA 分流到
    // 三个 PT_LOAD，分配 guest vaddr（每段页对齐、互不重叠），更新 ls.guest_addr。
    // host pool 布局保持不变（section 数据仍在 load 时的位置）；输出时按段拼接。
    // .bss(NOBITS) 排在 data 段 PROGBITS 之后，不占 filesz，只计入 memsz。
    // 注意：输出 ELF 的 section header 表只给每段一个 SHT_PROGBITS（.text/.rodata/.data），
    // .init_array/.fini_array 的内容被折叠进 .data section header（VM 只看 PT_LOAD 段 +
    // 合成的 __init_array_start/end 符号，不依赖独立 section header；但 readelf -S 看不到
    // 独立 .init_array，与标准 ld 不同——是有意简化）。
    void layout_segments() {
        for (int c = 0; c < 3; c++) segs_[c] = SegInfo{};
        // 分桶（保持 object/section 出现顺序 -> 段内顺序稳定）。
        // SEG_DATA 特殊处理：把所有 .init_array/.fini_array section 挑出来排在段尾，
        // 保证它们各自连续（musl 的 [__init_array_start, __init_array_end) 循环假设
        // 是连续的函数指针数组，被 .data 穿插会读到非函数指针 -> crash）。
        std::vector<std::pair<size_t,size_t>> data_init, data_fini;
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            for (size_t si = 1; si < objects_[oi].sections.size(); si++) {
                LoadedSection& ls = objects_[oi].sections[si];
                if (!ls.loadable) continue;
                if (ls.seg == SEG_DATA) {
                    if (ls.type == SHT_INIT_ARRAY) { data_init.push_back({oi, si}); continue; }
                    if (ls.type == SHT_FINI_ARRAY) { data_fini.push_back({oi, si}); continue; }
                }
                segs_[ls.seg].secs.push_back({oi, si});
            }
        }
        // init_array 在前、fini_array 在后，统一追加到 SEG_DATA 末尾。
        for (auto& pr : data_init) segs_[SEG_DATA].secs.push_back(pr);
        for (auto& pr : data_fini) segs_[SEG_DATA].secs.push_back(pr);
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
        // 所有模式首段都从 guest_base_+0x1000 起：给文件 offset [0, 0x1000)（ELF header +
        // phdr table）让出 vaddr 空间。这保证任何 section 的 vaddr > 0。
        uint64_t cur = guest_base_;
        cur += 0x1000;
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
        // 记录 .init_array/.fini_array 拼接区间的边界 vaddr（已保证连续）。
        // init_array 在 SEG_DATA 段内连续排列（layout_segments 分桶时挑出），
        // 边界 = 第一个 section 的 guest_addr .. 最后一个的 guest_addr + size。
        // 空区间显式判 .empty()（不依赖「首地址非 0」哨兵——PIE 或 fixed_base=0 下
        // 首地址可能合法地为 0，用哨兵会静默把真区间当空区间）。
        init_array_ = compute_array_boundary(data_init);
        fini_array_ = compute_array_boundary(data_fini);
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

    // 按 (obj_idx, sec_idx) 列表计算拼接区间的边界 [首 guest_addr, 末 guest_addr+size]。
    // 列表空时返回 present=false（start/end 保持 0）。
    InitFiniArray compute_array_boundary(const std::vector<std::pair<size_t,size_t>>& secs) const {
        InitFiniArray b;
        if (secs.empty()) return b;
        const LoadedSection& first = objects_[secs.front().first].sections[secs.front().second];
        const LoadedSection& last  = objects_[secs.back().first].sections[secs.back().second];
        b.start = first.guest_addr;
        b.end = last.guest_addr + last.size;
        b.present = true;
        return b;
    }

    // 合成 .init_array/.fini_array 边界符号 + __dso_handle。
    // 仅当对应 section 存在时合成——空时保留 musl 的 weak UND 引用，交由链接器/ldso
    // 走标准语义解析（合成为值为 0 的 ABS 符号会被 musl ldso 当 st_value==0 跳过而报
    // symbol not found，dynamic busybox 即此回归）。
    void define_init_fini_symbols() {
        if (init_array_.present) {
            synthetic_globals_["__init_array_start"] = init_array_.start;
            synthetic_globals_["__init_array_end"]   = init_array_.end;
        }
        if (fini_array_.present) {
            synthetic_globals_["__fini_array_start"] = fini_array_.start;
            synthetic_globals_["__fini_array_end"]   = fini_array_.end;
        }
        // __dso_handle 已在 check_undefined_symbols 之前合成（不依赖 layout）。
    }

    // 收集所有 UND 符号里形如 __start___<name> / __stop___<name> 的引用，若存在名为
    // <name> 的 section，则登记到 synthetic_globals_（占位值 1，让 check_undefined_symbols
    // 把它当已定义）。真实边界地址在 layout 后由 define_section_boundary_symbols 填入。
    // 对齐标准 ld：对任意 orphan section <name>，若有对 __start___<name>/__stop___<name>
    // 的引用，且该 section 存在，则自动合成边界符号。libc++ 的 operator new/delete 弱符号
    // 放进 __lcxx_override section，其可覆盖检测宏 __is_function_overridden 引用
    // __start___lcxx_override/__stop___lcxx_override 即走此机制。
    void collect_section_boundary_refs() {
        // 先建 name->存在 的 section 名集合（loadable section）。
        std::set<std::string> sec_names;
        for (const auto& obj : objects_) {
            for (const auto& ls : obj.sections) {
                if (ls.loadable && !ls.name.empty()) sec_names.insert(ls.name);
            }
        }
        for (const auto& obj : objects_) {
            for (const auto& sym : obj.symbols) {
                if (sym.defined || sym.name.empty()) continue;
                auto parsed = parse_section_boundary_sym(sym.name);
                if (!parsed) continue;
                const std::string& sec = parsed->second;
                // section 存在才合成（对齐 ld：无对应 section 时 __start_/__stop_ 不合成，
                // 留作 weak UND->0 或报 undefined）。
                if (sec_names.count(sec)) synthetic_globals_[sym.name] = 1;
            }
        }
    }

    // layout 后各自定义 section（如 __lcxx_override）按 section 名合并，取最小 guest_addr
    // 为 __start___<name>、最大 guest_addr+size 为 __stop___<name>。同名 section 可能跨多
    // 个 object（如多个 .o 都有 __lcxx_override），合并后边界即标准 ld 的 section 合并结果。
    // 仅对 collect_section_boundary_refs 已登记（即被引用且 section 存在）的符号更新地址。
    void define_section_boundary_symbols() {
        if (synthetic_globals_.empty()) return;
        // 筛出需要合成的 section 名（复用 parse_section_boundary_sym，单一前缀解析点）。
        std::set<std::string> wanted;
        for (const auto& [sym, _] : synthetic_globals_) {
            auto parsed = parse_section_boundary_sym(sym);
            if (parsed) wanted.insert(parsed->second);
        }
        if (wanted.empty()) return;
        // 按 section 名算合并后的边界。
        std::unordered_map<std::string, std::pair<uint64_t,uint64_t>> bounds; // name -> {min_addr, max_end}
        for (const auto& obj : objects_) {
            for (const auto& ls : obj.sections) {
                if (!ls.loadable || ls.name.empty()) continue;
                if (!wanted.count(ls.name)) continue;
                auto it = bounds.find(ls.name);
                uint64_t start = ls.guest_addr;
                uint64_t end = ls.guest_addr + ls.size;
                if (it == bounds.end()) bounds[ls.name] = {start, end};
                else { it->second.first  = std::min(it->second.first, start);
                       it->second.second = std::max(it->second.second, end); }
            }
        }
        for (const auto& [sec, pr] : bounds) {
            synthetic_globals_[make_section_boundary_sym(sec, true)]  = pr.first;
            synthetic_globals_[make_section_boundary_sym(sec, false)] = pr.second;
        }
    }

    // ======================================================================
    // === -r (RELOCATABLE / partial link) 独立路径 =========================
    // 与 final-link 完全分离：不调 layout_segments/apply_relocations/GOT-PLT/
    // 入口解析；自己合并段、重建 symtab、重写重定位、写 ET_REL。
    // 标准语义：合并同名段、保留未解析符号、保留重定位（不应用）、无 segment/入口。
    // ======================================================================

    bool run_relocatable(const std::vector<std::string>& inputs) {
        // -  加载输入（仅 ET_REL + ar 归档；classify_input 会把 .so/ET_DYN 也分流，
        //    但 partial link 不接受共享库——遇到 ET_DYN 输入直接报错）
        for (const auto& in : inputs) {
            auto kind = classify_input(in);
            if (kind == InputKind::DYN) {
                std::cerr << "[elf_linker] -r (partial link) does not accept shared object input: "
                          << in << " (only .o/.a)\n";
                return false;
            }
            if (!load_input(in)) {
                std::cerr << "[elf_linker] failed to load: " << in << "\n";
                return false;
            }
        }
        for (const auto& a : explicit_archives_) {
            load_archive_file(a);
        }
        // -  register_globals：建立 globals_（强覆盖弱），供 symtab 去重 + UND 判定
        for (size_t i = 0; i < objects_.size(); i++) {
            register_globals(i);
        }
        // -  partial link 允许未解析符号——不调 check_undefined_symbols
        return true;
    }

    // 合并所有输入对象的 loadable 段（按完整段名）到 extras，并填 rel_contrib_off_/
    // rel_sec_out_index_。同名段顺序拼接，.bss(NOBITS) 只累加 size 不写数据。
    void merge_rel_sections(std::vector<SecBuf>& extras) {
        // name -> (extras 下标, 当前累计字节)
        std::unordered_map<std::string, std::pair<size_t, size_t>> merged;
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            for (size_t si = 1; si < objects_[oi].sections.size(); si++) {
                const auto& ls = objects_[oi].sections[si];
                if (!ls.loadable) continue;
                auto align = ls.addralign ? ls.addralign : 1;
                auto it = merged.find(ls.name);
                if (it == merged.end()) {
                    SecBuf sb;
                    sb.name = ls.name;
                    sb.type = (ls.type == SHT_NOBITS) ? SHT_NOBITS : SHT_PROGBITS;
                    sb.flags = ls.sh_flags;
                    sb.addralign = align;
                    sb.entsize = ls.entsize;
                    sb.size = ls.size;  // 逻辑大小（NOBITS 无 data，靠此字段承载）
                    // 首份贡献区数据
                    if (ls.type != SHT_NOBITS && ls.size > 0) {
                        sb.data.assign(objects_[oi].host_mem + ls.offset,
                                       objects_[oi].host_mem + ls.offset + ls.size);
                    }
                    rel_contrib_off_[{oi, si}] = 0;
                    rel_sec_out_index_[{oi, si}] = extras.size();
                    merged[ls.name] = {extras.size(), ls.size};
                    extras.push_back(std::move(sb));
                } else {
                    auto& [idx, acc] = it->second;
                    auto& out = extras[idx];
                    // 对齐填充到 align 倍数
                    if (align > 1 && (acc % align) != 0) {
                        size_t pad = align - (acc % align);
                        if (out.type != SHT_NOBITS) {
                            out.data.insert(out.data.end(), pad, 0);
                        }
                        acc += pad;
                    }
                    // 取最大对齐
                    if (align > out.addralign) out.addralign = align;
                    rel_contrib_off_[{oi, si}] = acc;
                    rel_sec_out_index_[{oi, si}] = idx;
                    if (ls.type != SHT_NOBITS && ls.size > 0) {
                        out.data.insert(out.data.end(),
                                        objects_[oi].host_mem + ls.offset,
                                        objects_[oi].host_mem + ls.offset + ls.size);
                    }
                    acc += ls.size;
                    out.size = acc;  // PROGBITS: == data.size()；NOBITS: 逻辑大小
                }
            }
        }
    }

    // -r 专用：合并 DWARF 调试段（.debug_*）与 .stack_sizes 到 extras（非 ALLOC
    // SHT_PROGBITS），按名拼接保留原始字节，供后续 final-link 消费。keep_debug_ 关闭时跳过。
    void merge_rel_debug_sections(std::vector<SecBuf>& extras) {
        if (!keep_debug_) return;
        // name -> (extras 下标, 累计字节)
        std::unordered_map<std::string, std::pair<size_t, size_t>> merged;
        auto append = [&](size_t oi, size_t sec_idx, const std::string& name,
                          Elf64_Xword align, const std::vector<uint8_t>& data) {
            if (align == 0) align = 1;
            auto it = merged.find(name);
            if (it == merged.end()) {
                SecBuf sb;
                sb.name = name;
                sb.type = SHT_PROGBITS;
                sb.flags = 0;       // 非 ALLOC
                sb.addralign = align;
                sb.data = data;
                sb.size = data.size();
                rel_contrib_off_[{oi, sec_idx}] = 0;
                rel_sec_out_index_[{oi, sec_idx}] = extras.size();
                merged[name] = {extras.size(), data.size()};
                extras.push_back(std::move(sb));
            } else {
                auto& [idx, acc] = it->second;
                auto& out = extras[idx];
                if (align > 1 && (acc % align) != 0) {
                    size_t pad = align - (acc % align);
                    out.data.insert(out.data.end(), pad, 0);
                    acc += pad;
                }
                if (align > out.addralign) out.addralign = align;
                rel_contrib_off_[{oi, sec_idx}] = acc;
                rel_sec_out_index_[{oi, sec_idx}] = idx;
                out.data.insert(out.data.end(), data.begin(), data.end());
                acc += data.size();
                out.size = acc;
            }
        };
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            for (const auto& ds : objects_[oi].debug_secs) {
                // -r 不合成 .debug_frame：保留输入原样（final-link 才合成 CFI）
                append(oi, ds.sec_idx, ds.name, ds.addralign, ds.data);
            }
            // .stack_sizes（clang -fstack-size-section）：元数据段，供后续 final-link 的
            // fix_fbreg_offsets 解出栈大小。按名合并，重定位随通用路径重写。
            if (objects_[oi].stack_sizes_sec_idx != SIZE_MAX &&
                !objects_[oi].stack_sizes_data.empty()) {
                append(oi, objects_[oi].stack_sizes_sec_idx, ".stack_sizes", 1,
                       objects_[oi].stack_sizes_data);
            }
        }
    }

    // 构建 -r 的 .symtab/.strtab：输出所有 local（含 STT_SECTION）、保留原 binding、
    // 未解析符号作 SHN_UNDEF、st_value 用合并段内偏移。填 rel_sym_out_index_。
    // 返回 (symtab 在 extras 的下标, strtab 在 extras 的下标)。
    std::pair<size_t, size_t> build_rel_symtab(std::vector<SecBuf>& extras) {
        SecBuf strtab;
        strtab.name = ".strtab";
        strtab.type = SHT_STRTAB;
        strtab.data.push_back(0);
        strtab.addralign = 1;
        auto add_name = [&](const std::string& n) -> Elf64_Word {
            if (n.empty()) return 0;
            Elf64_Word off = (Elf64_Word)strtab.data.size();
            strtab.data.insert(strtab.data.end(), n.begin(), n.end());
            strtab.data.push_back(0);
            return off;
        };

        SecBuf symtab;
        symtab.name = ".symtab";
        symtab.type = SHT_SYMTAB;
        symtab.addralign = 8;
        symtab.entsize = sizeof(Elf64_Sym);

        size_t sym_count = 0;
        // NULL 符号（index 0）
        Elf64_Sym zsym = {};
        symtab.data.insert(symtab.data.end(), (uint8_t*)&zsym, (uint8_t*)&zsym + sizeof(zsym));
        sym_count++;

        // 计算某输入符号在合并段的值：contrib_off + sym.value
        auto sym_value = [&](size_t oi, const LoadedSym& s) -> uint64_t {
            if (s.sec_idx == SIZE_MAX) return s.value;  // UND/ABS：原值
            auto cit = rel_contrib_off_.find({oi, s.sec_idx});
            if (cit == rel_contrib_off_.end()) return s.value;
            return cit->second + s.value;
        };
        // 计算某输入符号的输出 shndx
        auto sym_shndx = [&](size_t oi, const LoadedSym& s) -> Elf64_Half {
            if (s.sec_idx == SIZE_MAX) {
                return (s.type == STT_FILE) ? SHN_ABS : SHN_UNDEF;
            }
            auto sit = rel_sec_out_index_.find({oi, s.sec_idx});
            // +1: NULL shdr 占 index 0，合并段从 index 1 开始
            return sit != rel_sec_out_index_.end() ? (Elf64_Half)(sit->second + 1) : SHN_UNDEF;
        };

        auto emit = [&](size_t oi, size_t si, const LoadedSym& s) {
            Elf64_Sym es = {};
            es.st_name = add_name(s.name);
            es.st_info = GELF_ST_INFO(s.binding, s.type);
            es.st_other = GELF_ST_VISIBILITY(s.visibility);  // 保留原可见性
            es.st_shndx = sym_shndx(oi, s);
            es.st_value = sym_value(oi, s);
            es.st_size = s.size;
            symtab.data.insert(symtab.data.end(), (uint8_t*)&es, (uint8_t*)&es + sizeof(es));
            rel_sym_out_index_[{oi, si}] = sym_count;
            sym_count++;
        };

        // -  本地符号（STB_LOCAL）：所有类型，含 STT_SECTION/STT_FILE。
        //    同名段合并后，每个输入对象的 STT_SECTION 符号须各自保留——它们被本对象的
        //    重定位引用（r_info 指向本 obj 的 section 符号），合并段后 shndx 改指合并段，
        //    value 改指贡献区起点。
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            for (size_t si = 1; si < objects_[oi].symbols.size(); si++) {  // 跳过 index 0 (NULL 符号)
                const auto& s = objects_[oi].symbols[si];
                if (s.binding != STB_LOCAL) continue;
                emit(oi, si, s);
            }
        }
        symtab.info = (Elf64_Word)sym_count;  // sh_info = 第一个 non-local 的索引

        // -  global/weak 符号：每个名字输出一条（取 globals_ 的胜出定义，保留其 binding）；
        //    同时为所有引用过但无定义的 UND 名字输出 SHN_UNDEF 条目。
        // 先输出有定义的 global/weak
        for (const auto& kv : globals_) {
            size_t oi = kv.second.obj_idx;
            size_t si = kv.second.sym_idx;
            const auto& s = objects_[oi].symbols[si];
            emit(oi, si, s);
        }
        // 再输出仍 UND 的（被重定位引用但无 globals_ 定义）：每个唯一名字一条
        std::unordered_set<std::string> seen_und;
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            for (size_t si = 1; si < objects_[oi].symbols.size(); si++) {  // 跳过 NULL 符号
                const auto& s = objects_[oi].symbols[si];
                if (s.defined) continue;              // 已处理
                if (s.binding == STB_LOCAL) continue; // local UND 不输出
                // 已有定义的符号名不输出 UND 条目（定义在 globals_ 里，已输出）
                if (globals_.count(s.name)) continue;
                if (!seen_und.insert(s.name).second) continue;  // 去重
                Elf64_Sym es = {};
                es.st_name = add_name(s.name);
                es.st_info = GELF_ST_INFO(s.binding, s.type);
                es.st_other = GELF_ST_VISIBILITY(s.visibility);  // 保留原可见性
                es.st_shndx = SHN_UNDEF;
                es.st_value = 0;
                es.st_size = 0;
                symtab.data.insert(symtab.data.end(), (uint8_t*)&es, (uint8_t*)&es + sizeof(es));
                rel_und_name_index_[s.name] = sym_count;
                sym_count++;
            }
        }

        size_t strtab_idx = extras.size();
        extras.push_back(std::move(strtab));
        size_t symtab_idx = extras.size();
        extras.push_back(std::move(symtab));
        extras[symtab_idx].link = (Elf64_Word)strtab_idx + 1;  // +1: NULL shdr 占 index 0
        return {symtab_idx, strtab_idx};
    }

    // 重写重定位：按【输出目标段】(rel_sec_out_index_ 的值，即合并后的段) 重组为 SHT_RELA。
    // 多个输入对象的 .text 合并成一个输出 .text 后，它们各自的 .rela.text 须合并成一个
    // .rela.text（目标段 index 相同）。r_offset 重定位到合并段内（contrib_off + r.offset），
    // r_info 重索引到输出 symtab，addend 原样保留。不跳过任何重定位类型（含 call type 10）。
    void build_rel_relocations(std::vector<SecBuf>& extras, size_t symtab_idx) {
        // 输出目标段 index -> (extras 下标, 段名)
        std::map<size_t, size_t> outsec_to_rela;
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            for (const auto& r : objects_[oi].relocations) {
                if (r.target_sec >= objects_[oi].sections.size()) continue;
                auto sit = rel_sec_out_index_.find({oi, r.target_sec});
                if (sit == rel_sec_out_index_.end()) continue;
                size_t out_sec_idx = sit->second;  // 合并后的输出段在 extras 的下标
                const auto& target = objects_[oi].sections[r.target_sec];
                auto it = outsec_to_rela.find(out_sec_idx);
                size_t idx;
                if (it == outsec_to_rela.end()) {
                    SecBuf sb;
                    sb.name = std::string(".rela") + target.name;  // .rela.text 等
                    sb.type = SHT_RELA;
                    sb.addralign = 8;
                    sb.entsize = sizeof(Elf64_Rela);
                    sb.link = (Elf64_Word)symtab_idx + 1;  // +1: NULL shdr 占 index 0
                    sb.info = (Elf64_Word)out_sec_idx + 1; // 目标合并段 shdr index
                    idx = extras.size();
                    extras.push_back(std::move(sb));
                    outsec_to_rela[out_sec_idx] = idx;
                } else {
                    idx = it->second;
                }
                Elf64_Rela rela = {};
                // r_offset 重定位到合并段内
                auto cit = rel_contrib_off_.find({oi, r.target_sec});
                uint64_t contrib = (cit != rel_contrib_off_.end()) ? cit->second : 0;
                rela.r_offset = contrib + r.offset;
                // r_info 重索引：优先按 (obj, sym_idx) 查已映射的输出索引；
                // 若查不到（UND 符号引用，本 obj 内未定义），按符号名查 globals_ 定义者；
                // 再不行查 rel_und_name_index_（仍 UND 的符号）。
                size_t out_sym = 0;
                auto symit = rel_sym_out_index_.find({oi, r.sym_idx});
                if (symit != rel_sym_out_index_.end()) {
                    out_sym = symit->second;
                } else if (r.sym_idx < objects_[oi].symbols.size()) {
                    const auto& rsym = objects_[oi].symbols[r.sym_idx];
                    auto git = globals_.find(rsym.name);
                    if (git != globals_.end()) {
                        auto g2 = rel_sym_out_index_.find({git->second.obj_idx, git->second.sym_idx});
                        if (g2 != rel_sym_out_index_.end()) out_sym = g2->second;
                    }
                    if (out_sym == 0) {
                        auto uit = rel_und_name_index_.find(rsym.name);
                        if (uit != rel_und_name_index_.end()) out_sym = uit->second;
                    }
                }
                rela.r_info = ELF64_R_INFO(out_sym, (uint64_t)r.type);
                rela.r_addend = r.addend;  // 原样保留
                extras[idx].data.insert(extras[idx].data.end(),
                                        (uint8_t*)&rela, (uint8_t*)&rela + sizeof(rela));
            }
        }
    }

    // -r 文件布局：ehdr -> extras 数据(顺序，按 addralign 对齐) -> shdr 表
    struct RelLayout {
        std::vector<uint64_t> extra_offs;  // 每个 extra 的文件 offset
        uint64_t sh_off = 0;               // shdr 表 offset
        Elf64_Half shnum = 0;
        Elf64_Half shstrndx = 0;
    };

    bool write_rel_impl(FILE* f) {
        // -  合并 loadable 段 + （keep_debug 时）DWARF/.stack_sizes 段
        std::vector<SecBuf> extras;
        merge_rel_sections(extras);
        merge_rel_debug_sections(extras);

        // -  symtab + strtab
        auto [symtab_idx, strtab_idx] = build_rel_symtab(extras);

        // -  重定位段
        build_rel_relocations(extras, symtab_idx);

        // -  .shstrtab（收集所有 extra 名字）
        SecBuf shstrtab;
        shstrtab.name = ".shstrtab";
        shstrtab.type = SHT_STRTAB;
        shstrtab.data.push_back(0);  // index 0 = 空名
        shstrtab.addralign = 1;
        std::vector<Elf64_Word> name_offs;
        auto add_shstr = [&](const std::string& n) -> Elf64_Word {
            Elf64_Word off = (Elf64_Word)shstrtab.data.size();
            shstrtab.data.insert(shstrtab.data.end(), n.begin(), n.end());
            shstrtab.data.push_back(0);
            return off;
        };
        for (auto& e : extras) name_offs.push_back(add_shstr(e.name));
        Elf64_Word shstrtab_name_off = add_shstr(".shstrtab");
        size_t shstrtab_idx = extras.size();
        extras.push_back(std::move(shstrtab));
        name_offs.push_back(shstrtab_name_off);  // 与 extras 对齐，shstrtab 自身名字占一位

        // -  计算文件布局
        RelLayout L;
        uint64_t off = sizeof(Elf64_Ehdr);  // 无 phdr
        L.extra_offs.resize(extras.size());
        for (size_t i = 0; i < extras.size(); i++) {
            uint64_t align = extras[i].addralign ? extras[i].addralign : 1;
            if (align > 1) off = (off + align - 1) & ~(align - 1);
            L.extra_offs[i] = off;
            if (extras[i].type != SHT_NOBITS) {
                off += extras[i].data.size();
            }
            // NOBITS 不占文件空间
        }
        // shdr 表 8 字节对齐
        off = (off + 7) & ~uint64_t(7);
        L.sh_off = off;
        L.shnum = (Elf64_Half)(extras.size() + 1);  // +1: NULL shdr
        L.shstrndx = (Elf64_Half)shstrtab_idx + 1;  // +1: NULL shdr 占 index 0

        // -  写 Ehdr
        Elf64_Ehdr eh = {};
        eh.e_ident[0] = 0x7f; eh.e_ident[1] = 'E'; eh.e_ident[2] = 'L'; eh.e_ident[3] = 'F';
        eh.e_ident[4] = ELFCLASS64; eh.e_ident[5] = ELFDATA2LSB; eh.e_ident[6] = EV_CURRENT;
        eh.e_ident[7] = ELFOSABI_NONE;
        eh.e_type = ET_REL;
        eh.e_machine = EM_BPF;
        eh.e_version = EV_CURRENT;
        eh.e_entry = 0;
        eh.e_phoff = 0;   // REL 无 program header
        eh.e_shoff = L.sh_off;
        eh.e_flags = 0;
        eh.e_ehsize = sizeof(Elf64_Ehdr);
        eh.e_phentsize = 0;
        eh.e_phnum = 0;
        eh.e_shentsize = sizeof(Elf64_Shdr);
        eh.e_shnum = L.shnum;
        eh.e_shstrndx = L.shstrndx;
        if (fwrite(&eh, sizeof(eh), 1, f) != 1) return false;

        // -  写 extras 数据（NOBITS 跳过）
        for (size_t i = 0; i < extras.size(); i++) {
            if (extras[i].type == SHT_NOBITS) continue;
            if (fseek(f, (long)L.extra_offs[i], SEEK_SET) != 0) return false;
            if (!extras[i].data.empty()) {
                if (fwrite(extras[i].data.data(), extras[i].data.size(), 1, f) != 1) return false;
            }
        }

        // -  写 shdr 表：NULL + 每个 extra 一条
        if (fseek(f, (long)L.sh_off, SEEK_SET) != 0) return false;
        Elf64_Shdr null_sh = {};
        if (fwrite(&null_sh, sizeof(null_sh), 1, f) != 1) return false;
        for (size_t i = 0; i < extras.size(); i++) {
            Elf64_Shdr sh = {};
            sh.sh_name = name_offs[i];
            sh.sh_type = extras[i].type;
            sh.sh_flags = extras[i].flags;
            sh.sh_addr = 0;  // REL 无虚拟地址
            sh.sh_offset = (extras[i].type == SHT_NOBITS) ? 0 : L.extra_offs[i];
            // NOBITS（.bss）无 data，逻辑大小记在 size 字段；其余用 data 实际字节数
            sh.sh_size = (extras[i].type == SHT_NOBITS) ? extras[i].size : extras[i].data.size();
            sh.sh_link = extras[i].link;
            sh.sh_info = extras[i].info;
            sh.sh_addralign = extras[i].addralign;
            sh.sh_entsize = extras[i].entsize;
            if (fwrite(&sh, sizeof(sh), 1, f) != 1) return false;
        }
        return true;
    }

    uint64_t entry() const { return entry_; }

    bool write_elf(const std::string& path) {
        if (!pool_ || pool_used_ == 0) return false;

        // -r 走独立 writer（ET_REL，无 segment/phdr）
        if (mode_ == Mode::RELOCATABLE) {
            FILE* f = fopen(path.c_str(), "wb");
            if (!f) {
                std::cerr << "[elf_linker] cannot write " << path << ": " << strerror(errno) << "\n";
                return false;
            }
            bool ok = write_rel_impl(f);
            fclose(f);
            if (ok) chmod(path.c_str(), 0644);  // 中间 .o，无可执行位
            return ok;
        }

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
    // .so 提供的符号表（DYNAMIC_EXE 模式用）：symbol name -> 已固定地址
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
            ls.loadable = is_loadable_section(shdr.sh_type) &&
                          !is_debug_section(ls.name) && !is_dwarf_section(ls.name) &&
                          ls.name != ".stack_sizes";  // -fstack-size-section 的元数据段：不进 VM
            ls.writable = (shdr.sh_flags & SHF_WRITE) != 0;
            ls.executable = (shdr.sh_flags & SHF_EXECINSTR) != 0;
            ls.seg = classify_section(ls.executable, ls.writable);
            ls.sh_flags = shdr.sh_flags;
            ls.addralign = shdr.sh_addralign ? shdr.sh_addralign : 1;
            ls.entsize = shdr.sh_entsize;
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

        // 第二遍：拷贝 PROGBITS 数据（VM-loadable 进 host pool；DWARF 段进独立 debug_secs）
        scn = nullptr;
        size_t sec_idx = 1;  // 从 1 开始，跳过 NULL 占位
        while ((scn = elf_nextscn(elf, scn)) != nullptr) {
            GElf_Shdr shdr;
            gelf_getshdr(scn, &shdr);
            LoadedSection& ls = obj.sections[sec_idx++];
            if (!ls.loadable) {
                // DWARF 调试段：keep_debug 时搬运原始字节到 debug_secs（独立缓冲，不进 host pool）。
                // is_dwarf_section 只匹配 .debug*/.rel.debug*；后者是 SHT_REL，被 SHT_PROGBITS
                // 条件排除，故这里仅捕获真正的 .debug_* 数据段。
                if (keep_debug_ && shdr.sh_type == SHT_PROGBITS && is_dwarf_section(ls.name)) {
                    Elf_Data* d = elf_getdata(scn, nullptr);
                    if (d && d->d_size > 0) {
                        DebugSec ds;
                        ds.name = ls.name;
                        ds.sec_idx = sec_idx - 1;       // 与 obj.sections 下标对齐
                        ds.addralign = shdr.sh_addralign ? shdr.sh_addralign : 1;
                        ds.data.assign((uint8_t*)d->d_buf, (uint8_t*)d->d_buf + d->d_size);
                        obj.dbg_sec_local_idx[sec_idx - 1] = obj.debug_secs.size();
                        obj.debug_secs.push_back(std::move(ds));
                    }
                }
                // .stack_sizes（clang -fstack-size-section）：keep_debug 时搬运原始字节，
                // 供 fix_fbreg_offsets 解出每个函数的栈大小。其重定位随 .rel.stack_sizes 进
                // obj.relocations（target_sec = 本段下标）。
                if (keep_debug_ && shdr.sh_type == SHT_PROGBITS && ls.name == ".stack_sizes") {
                    Elf_Data* d = elf_getdata(scn, nullptr);
                    if (d && d->d_size > 0) {
                        obj.stack_sizes_data.assign((uint8_t*)d->d_buf, (uint8_t*)d->d_buf + d->d_size);
                        obj.stack_sizes_sec_idx = sec_idx - 1;
                    }
                }
                continue;
            }
            ls.guest_addr = obj.base + ls.offset;
            if (shdr.sh_type != SHT_PROGBITS &&
                shdr.sh_type != SHT_INIT_ARRAY &&
                shdr.sh_type != SHT_FINI_ARRAY) {
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
                    ls.visibility = GELF_ST_VISIBILITY(sym.st_other);
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
                    r.is_rela = true;
                    GElf_Rela rela;
                    gelf_getrela(d, i, &rela);
                    r.offset = rela.r_offset;
                    r.type = GELF_R_TYPE(rela.r_info);
                    r.sym_idx = GELF_R_SYM(rela.r_info);
                    r.addend = rela.r_addend;
                } else {
                    r.is_rela = false;
                    GElf_Rel rel;
                    gelf_getrel(d, i, &rel);
                    r.offset = rel.r_offset;
                    r.type = GELF_R_TYPE(rel.r_info);
                    r.sym_idx = GELF_R_SYM(rel.r_info);
                    // SHT_REL：addend 嵌入在 patch 点原值里，按类型读取。
                    // 数据重定位（type 1/2/3/4：lddw / 绝对指针 / DWARF 段内偏移）：patch 点是
                    // 真实的 embedded addend，对 UND 符号也一样（clang 在这里写的是真偏移，非占位）。
                    // 典型：C++ RTTI 的 typeinfo 第一槽是「vtable+16 指针」，引用 UND 符号
                    // _ZTVN10__cxxabiv1*（定义在 libc++abi），embedded addend = +16 必须读出，
                    // 否则 typeinfo 的 vtable 指针少 16 -> 落到 offset-to-top/typeinfo 槽 ->
                    // dynamic_cast/typeid 崩。
                    // call 重定位（type 10）：clang 对未解析调用写 imm=-1 占位符（非真实 addend），
                    // 故 UND 符号时 addend 保持 0；已定义符号的 call 也走相对偏移（addend 用不上）。
                    bool sym_defined = (r.sym_idx < obj.symbols.size() && obj.symbols[r.sym_idx].defined);
                    // 仅 type 10 (R_BPF_64_32 / call) 对 UND 跳过读 embedded addend
                    //（clang 写 imm=-1 占位符）。其余数据重定位即使 UND 也读真 addend。
                    bool read_embedded = (sym_defined || r.type != 10);
                    if (read_embedded && target_sec < obj.sections.size()) {
                        const auto& tgt = obj.sections[target_sec];
                        if (tgt.loadable) {
                            const unsigned char* patch = obj.host_mem + tgt.offset + r.offset;
                            r.addend = read_embedded_addend(patch, r.type);
                        } else {
                            // SHT_REL 的 DWARF 重定位（.rel.debug_*）：patch 点在 debug 段原始字节里。
                            // 从已搬运的 debug_secs 缓冲读 embedded addend。
                            auto it = obj.dbg_sec_local_idx.find(target_sec);
                            if (it != obj.dbg_sec_local_idx.end() &&
                                r.offset + reloc_write_len(r.type) <= tgt.size) {
                                const auto& dbuf = obj.debug_secs[it->second].data;
                                r.addend = read_embedded_addend(dbuf.data() + r.offset, r.type);
                            }
                        }
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
                if (sym.binding == STB_WEAK) continue;           // weak 未定义 -> 解析为 0
                if (globals_.count(sym.name)) continue;          // .o/.a 提供（resolve_symbol 可解析）
                if (synthetic_globals_.count(sym.name)) continue;// 合成符号（__init_array_start 等）
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

        // 合成符号（__init_array_start/end、__fini_array_*、__dso_handle 等）：
        // linker 凭空定义、不指向真实 obj symbol，直接返回合成的 vaddr。
        auto sit = synthetic_globals_.find(sym.name);
        if (sit != synthetic_globals_.end()) {
            return sit->second;
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

    // 解析符号对 debug 重定位的「值」：DWARF consumer 需要的是 section 内偏移或运行时
    // 地址，取决于目标所在 section 性质：
    //   - 符号指向 debug 段（.debug_*）：值 = 符号在该 debug 段内的偏移（sym.value）。
    //     DWARF 的 section 间引用是「目标段内偏移」语义（如 .debug_info 的 DW_AT_abbrev
    //     指向 .debug_abbrev 段内偏移），不是文件内偏移。addend 已编码段内目标位置。
    //   - 符号指向 VM-loadable 段（.text/.rodata/.data）：值 = 运行时 guest 地址（STATIC
    //     下即最终地址；debug->loadable 引用，如 .debug_addr/.debug_ranges 指向代码/数据）。
    // 返回 nullopt 表示无法解析。
    std::optional<uint64_t> resolve_debug_value(size_t obj_idx, size_t sym_idx) const {
        const auto& sym = objects_[obj_idx].symbols[sym_idx];
        // 非 STB_LOCAL：按 globals_ 解析为最终定义处的 guest 地址或 debug 段内偏移
        size_t def_obj_idx = obj_idx;
        size_t def_sym_idx = sym_idx;
        if (sym.binding != STB_LOCAL) {
            auto it = globals_.find(sym.name);
            if (it != globals_.end()) {
                def_obj_idx = it->second.obj_idx;
                def_sym_idx = it->second.sym_idx;
            } else {
                if (sym.binding == STB_WEAK && mode_ != Mode::SHARED_LIB) return 0;
                return std::nullopt;
            }
        }
        const auto& def_sym = objects_[def_obj_idx].symbols[def_sym_idx];
        if (def_sym.sec_idx == SIZE_MAX || def_sym.sec_idx >= objects_[def_obj_idx].sections.size())
            return 0;
        // 符号指向 debug 段：值 = 本 .o 贡献区起点（contrib_off）+ 段内偏移（sym.value）。
        // 同名 debug 段已合并成单个输出段，每 .o 占一个贡献区；不加 contrib_off 会让所有
        // .o 的 base 属性都指向段头（CU header 的 debug_abbrev_offset、DW_AT_addr_base 等），
        // 导致 gdb 报 "Could not find abbrev" / "DW_FORM_addrx outside .debug_addr"。
        auto lit = objects_[def_obj_idx].dbg_sec_local_idx.find(def_sym.sec_idx);
        if (lit != objects_[def_obj_idx].dbg_sec_local_idx.end()) {
            const auto& dsec = objects_[def_obj_idx].debug_secs[lit->second];
            return dsec.contrib_off + def_sym.value;
        }
        // 否则指向 loadable 段：用 guest 地址（STATIC_EXE 下即最终地址）
        const auto& sec = objects_[def_obj_idx].sections[def_sym.sec_idx];
        return sec.guest_addr + def_sym.value;
    }

    // 加载 .so 文件，提取其 symtab 中所有 GLOBAL 符号 -> 地址映射
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
            // hidden 符号不跨模块可见，跳过（防御性：正确生成的 .so 不该在 .dynsym 含 hidden
            // 符号，但保护下游不被错误产物污染）。
            if (GELF_ST_VISIBILITY(sym.st_other) == STV_HIDDEN) continue;
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
    // 流程：构建 extras -> 计算布局 -> 回填动态段 vaddr -> 写 header/phdr/payload/shdr。
    // 各阶段拆到 build_*/compute_*/backfill_*/write_* helper，本函数仅编排。
    bool write_elf_impl(FILE* f) {
        // -  section index 布局：NULL(0) -> .text -> .plt? -> .rodata -> .data -> .got.plt? -> .bss? -> extras
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

        // -  构建 extras（按 mode_ 条件追加）
        std::vector<SecBuf> extras;
        // 2a. DWARF 调试段（最先 push：在 extras 区前部，便于 shstrtab 自动注册名字）。
        //     .debug_addr/.debug_ranges 等含运行时地址的重定位走 debug->loadable 分支，
        //     返回 guest_addr。STATIC_EXE 下 guest_addr 即最终地址；PIE 模式下 guest_addr
        //     是文件内偏移（基址 0），运行时由 VM 加载基址后，GDB 经 qOffsets/RSP 获得真实
        //     地址——但 GDB 对 PIE remote target 默认按文件内偏移匹配，二者需一致，故 PIE
        //     下 .debug_addr 填文件内偏移可用（VM 加载基址与 GDB 推断一致即可）。
        const bool emit_debug = (keep_debug_ && mode_ != Mode::SHARED_LIB);
        if (emit_debug) {
            collect_debug_sections(extras);
            // 合成 .debug_frame（clang BPF 不生成 CFI；GDB bt 靠它回溯栈）。
            // 在 collect_debug_sections 之后：它已跳过输入的空 .debug_frame，这里补合成版。
            synthesize_debug_frame(extras);
            // 建 函数地址->栈大小 表（来自 -fstack-size-section 的 .stack_sizes），供
            // fix_fbreg_offsets 修正 DW_OP_fbreg。不依赖 extras，只读 obj.stack_sizes_data。
            build_stack_size_map();
        }
        // 2b. 静态符号表（三种模式都输出，含本地 FUNC/OBJECT，供反汇编/调试）。
        //     -s/--strip-all 时跳过（对齐标准 ld；运行时符号解析仍走 .dynsym）。
        if (keep_symtab_) {
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

        // 2c. DWARF 重定位 patch + 偏移修正：必须在 compute_file_layout 之前完成，
        //     因为 fix_fbreg_offsets / fix_loclists_breg10 可能改变 .debug_info /
        //     .debug_loclists 长度（SLEB128 变长重写），若在布局后才改，后续段的文件偏移
        //     会与变化后的尺寸不一致 -> 段重叠/破坏。resolve_debug_value 用的是 guest 地址
        //     （layout_segments 已设），不依赖文件布局，故提前到此处安全。
        if (emit_debug) {
            apply_debug_relocations(extras);
            // 修正 .debug_info 里 DW_OP_fbreg 的错误偏移（clang BPF 后端 bug）。
            // 必须在 apply_debug_relocations 之后：那时 .debug_addr 已 patch 为函数 guest
            // 地址，fix_fbreg_offsets 据此把每条 fbreg 关联到所在函数的 stacksize 并改写。
            // （同时填 loclist_ss_：loclistx 索引 -> 所属函数 stacksize，供下一步用。）
            fix_fbreg_offsets(extras);
            // 修正 .debug_loclists 里 DW_OP_breg10 的错误偏移（同源 bug，参数/变量 spill 的位置）。
            // 必须在 fix_fbreg_offsets 之后（用其填的 loclist_ss_）。三阶段重写：loclist 按真实
            // 长度重建 -> offset_table 重算 -> 贡献区位移，产出 old_base->new_base 表。
            fix_loclists_breg10(extras);
            // 用 old_base->new_base 定长改写 .debug_info 里 DW_AT_loclists_base 的 sec_offset。
            // 必须在 fix_loclists_breg10 之后（用其填的 loclists_base_remap_），且在最终 .debug_info
            // （fix_fbreg_offsets 重建后）上扫描；定长改写不改长度，故不影响布局。
            remap_loclists_base(extras);
        }

        // -  计算文件布局（此时各 extras[].data 已是最终内容/尺寸）
        FileLayout layout = compute_file_layout(extras, extras_base, next_sh,
                                                 names.shstrtab_idx, interp_idx, need_dynamic);

        // -  回填动态 section 的 vaddr 并 patch DT_*
        std::unordered_map<size_t, uint64_t> dyn_vaddr_map;
        if (need_dynamic) {
            dyn_vaddr_map = backfill_dynamic_vaddrs(extras, layout.extra_offs, dyn_idx, interp_idx);
        }

        // -  写出
        if (!write_ehdr(f, layout)) return false;
        if (!write_phdrs(f, extras, layout, dyn_vaddr_map, dyn_idx, interp_idx, need_dynamic)) return false;
        if (!write_payload(f, extras, layout)) return false;
        if (!write_shdrs(f, extras, layout, dyn_vaddr_map, names)) return false;
        return true;
    }

    // 收集所有 obj 的 DWARF 调试段为 non-ALLOC SecBuf，推入 extras；同时回填各
    // DebugSec::extra_idx 以便后续 patch 按索引找到对应缓冲。
    // 收集 debug 段到 extras：同名段按 objects_ 输入顺序拼接成单个输出段（对齐标准
    // 链接器做法——DWARF v5 设计假设）。每个 .o 的同名段在合并段里占一个"贡献区"
    // （contribution），起点记到 ds.contrib_off；DWARF 重定位用它定位本 .o 的 contribution。
    // 对齐：每个贡献区按该段的 sh_addralign 填充，保证 contribution header 不错位。
    void collect_debug_sections(std::vector<SecBuf>& extras) {
        // name -> (extras 里的 SecBuf 下标, 合并段当前累计字节)
        std::unordered_map<std::string, std::pair<size_t, size_t>> merged;
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            for (size_t di = 0; di < objects_[oi].debug_secs.size(); di++) {
                auto& ds = objects_[oi].debug_secs[di];
                // 跳过 clang 输出的空 .debug_frame（CIE 只有 DW_CFA_nop、FDE 无 CFI 指令），
                // 改由 synthesize_debug_frame 按本 VM 的帧布局合成正确的 CFI。
                if(ds.name == ".debug_frame") continue;
                auto align = ds.addralign ? ds.addralign : 1;
                auto it = merged.find(ds.name);
                if (it == merged.end()) {
                    // 首次出现该段名：新建一个 SecBuf，contrib_off = 0
                    SecBuf sb;
                    sb.name = ds.name;
                    sb.type = SHT_PROGBITS;
                    sb.flags = 0;       // 非 ALLOC：write_shdrs 留 sh_addr=0
                    sb.addralign = align;
                    sb.data = ds.data;  // 首份贡献区，从 0 开始
                    ds.extra_idx = extras.size();
                    ds.contrib_off = 0;
                    merged[ds.name] = {extras.size(), sb.data.size()};
                    extras.push_back(std::move(sb));
                } else {
                    auto& [idx, acc] = it->second;
                    auto& out = extras[idx];
                    // 对齐填充到 align 的倍数
                    if (align > 1 && (acc % align) != 0) {
                        size_t pad = align - (acc % align);
                        out.data.insert(out.data.end(), pad, 0);
                        acc += pad;
                    }
                    ds.extra_idx = idx;
                    ds.contrib_off = acc;          // 本 .o 贡献区起点
                    out.data.insert(out.data.end(), ds.data.begin(), ds.data.end());
                    acc += ds.data.size();
                }
            }
        }
    }

    // 合成 .debug_frame：clang 的 BPF backend 不输出 CFI（CIE 仅 DW_CFA_nop，FDE 空），
    // GDB 的 bt 无法回溯。这里按本 VM 的帧布局（见 insn.cpp Stack Frame Layout）合成 CFI。
    // r10 全程指向帧头且不变（BPF ABI，frame pointer 只读），old_r10/RA 固定在 r10+8/+16，
    // 故 CIE 用 DWARF expression 对所有 PC 给出统一规则，一套即通吃普通/信号帧：
    //   CFA = *(r10 + 8)   caller 的 r10，GDB 把它当上一帧 frame base 继续回溯。
    //   RA  = *(r10 + 16)  帧头返回地址槽。
    //
    // RA 列号 11 是 DWARF 逻辑列（r0..r10 对应列 0..10，列 11 专属 RA），GDB 的
    // dwarf2_frame_cache 会特殊处理该列。
    //
    // _start 的帧 RA 槽=0（push_frame(0)）。其 FDE 用 DW_CFA_undefined 覆盖 RA 规则，
    // 使 GDB 在此停止回溯。
    void synthesize_debug_frame(std::vector<SecBuf>& extras) {
        std::vector<uint8_t> d;  // .debug_frame 数据
        auto push_u8  = [&](uint8_t v){ d.push_back(v); };
        auto push_u32 = [&](uint32_t v){ for(int i=0;i<4;i++) d.push_back(v >> (i*8)); };  // 小端
        auto push_u64 = [&](uint64_t v){ for(int i=0;i<8;i++) d.push_back(v >> (i*8)); };
        auto push_uleb = [&](uint64_t v){
            do { uint8_t b = v & 0x7F; v >>= 7; if(v) b |= 0x80; d.push_back(b); } while(v);
        };
        auto push_sleb = [&](int64_t v){
            bool more = true;
            while(more) {
                uint8_t b = v & 0x7F; v >>= 7;
                if((v == 0 && !(b & 0x40)) || (v == -1 && (b & 0x40))) more = false;
                else b |= 0x80;
                d.push_back(b);
            }
        };
        // 在当前 d 末尾预留 4 字节 length 占位，返回其偏移；record 结束后回填 length。
        auto reserve_length = [&]() -> size_t {
            size_t off = d.size();
            d.insert(d.end(), 4, 0);
            return off;
        };
        auto patch_length = [&](size_t off){
            uint32_t len = (uint32_t)(d.size() - off - 4);
            for(int i = 0; i < 4; i++) d[off + i] = (len >> (i*8)) & 0xFF;
        };
        // 写一条带 ULEB128 长度前缀的 DWARF location expression。
        // expression 字节由 lambda 直接 push 到 d；本辅助负责在表达式内容前回填长度。
        auto push_expr = [&](const std::function<void()>& emit_body) {
            size_t start = d.size();
            emit_body();  // 写 expression 内容（不含长度前缀）
            size_t len = d.size() - start;
            std::vector<uint8_t> uleb;
            do { uint8_t b = len & 0x7F; len >>= 7; if(len) b |= 0x80; uleb.push_back(b); } while(len);
            d.insert(d.begin() + start, uleb.begin(), uleb.end());
        };

        // ── CIE（第一条记录，FDE 的 CIE_pointer = 0）──
        size_t cie_len_off = reserve_length();
        push_u32(0xFFFFFFFF);   // CIE_id（.debug_frame 用 0xFFFFFFFF 标识 CIE）
        push_u8(4);             // version（DWARF 4：address_size/segment_size 字段、return_address_reg ULEB）
        push_u8(0);             // augmentation（空）
        push_u8(8);             // address_size
        push_u8(0);             // segment_size
        push_uleb(1);           // code_alignment_factor（PC 偏移按字节；expression 不用它）
        push_sleb(8);           // data_alignment_factor（保持 8；expression 不用它）
        push_uleb(11);          // return_address_register（r0..r10=列0..10，RA=列11；见函数头注释）

        // initial_instructions：用 expression 定义默认展开规则，对所有 PC 生效。
        // CFA = *(r10 + 8)：DW_OP_breg10(8), DW_OP_deref。
        push_u8(0x0f);          // DW_CFA_def_cfa_expression
        push_expr([&]{
            push_u8(0x7a);      // DW_OP_breg10
            push_sleb(8);       // +8
            push_u8(0x06);      // DW_OP_deref
        });
        // RA 存于帧头 [+16] 槽。两种 CFA 指令的 expression 语义不同：
        //   DW_CFA_def_cfa_expression（上面）：expression 结果 = CFA 值，故需 deref。
        //   DW_CFA_expression（这里）：expression 结果 = RA 的存放地址，GDB 据此再读值，
        //   故只算出 r10+16，不带 deref。
        push_u8(0x10);          // DW_CFA_expression
        push_uleb(11);          // RA 列
        push_expr([&]{
            push_u8(0x7a);      // DW_OP_breg10
            push_sleb(16);      // +16（返回地址存放的地址；GDB 自动从此处读值）
        });
        patch_length(cie_len_off);

        // ── 枚举所有函数 [addr,size)，按地址去重，每个写一个 FDE ──
        std::set<std::pair<uint64_t,uint64_t>> seen;  // (addr, size)
        auto emit_fde = [&](uint64_t addr, uint64_t size, bool is_entry) {
            if(size == 0) return;
            if(!seen.insert({addr, size}).second) return;  // 去重（同名 local + global）
            size_t len_off = reserve_length();
            push_u32(0);           // CIE_pointer = 0（CIE 在 .debug_frame 起始）
            // 注：FDE 没有 address_size/segment_size 字段（那是 CIE v4 才有的）；
            // initial_location/address_range 的大小由 CIE 的 addr_size 决定（这里 8 字节）。
            push_u64(addr);        // initial_location
            push_u64(size);        // address_range
            if(is_entry) {
                // _start：RA 不可恢复，GDB 在此干净停止回溯。
                push_u8(0x07);     // DW_CFA_undefined
                push_uleb(11);     // RA 列
            }
            // 否则 FDE 指令序列为空——CIE 的 initial_instructions 已覆盖所有 PC。
            patch_length(len_off);
        };

        // 本地 STT_FUNC（仿 build_static_symtab 的枚举）
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            const auto& obj = objects_[oi];
            for (size_t si = 1; si < obj.symbols.size(); si++) {
                const auto& sym = obj.symbols[si];
                if (sym.binding != STB_LOCAL) continue;
                if (!sym.defined) continue;
                if (sym.type != STT_FUNC) continue;
                emit_fde(sec_guest_addr_of(obj, sym.sec_idx) + sym.value, sym.size, false);
            }
        }
        // 全局 STT_FUNC
        for (const auto& kv : globals_) {
            const auto& obj = objects_[kv.second.obj_idx];
            const auto& sym = obj.symbols[kv.second.sym_idx];
            if (!sym.defined || sym.type != STT_FUNC) continue;
            uint64_t addr = sec_guest_addr_of(obj, sym.sec_idx) + sym.value;
            emit_fde(addr, sym.size, addr == entry_);
        }

        // _start 可能未在符号表里（如来自 .so 的 PLT stub 入口）——若上面没覆盖到，
        // 单独补一个终止 FDE（用 entry_ 起始、保守小范围，确保 GDB 在入口处能停）。
        if (entry_ != 0) {
            bool covered = false;
            for (const auto& r : seen) {
                if (entry_ >= r.first && entry_ < r.first + r.second) { covered = true; break; }
            }
            if (!covered) emit_fde(entry_, 8, true);  // 8 字节 = 一条 BPF 指令，足以让 RA=undefined 生效
        }

        SecBuf sb;
        sb.name = ".debug_frame";
        sb.type = SHT_PROGBITS;
        sb.flags = 0;
        sb.addralign = 8;
        sb.data = std::move(d);
        extras.push_back(std::move(sb));
    }

    // 解码 .stack_sizes：每个 obj 的 .stack_sizes + 其 .rel.stack_sizes，建立
    // 函数 guest 地址 -> 栈大小 的全局表 stack_sizes_。供 fix_fbreg_offsets 查询。
    //
    // .stack_sizes 记录格式（clang -fstack-size-section）：
    //   每条 = [8 字节 ABS64 重定位 -> 指向函数 .text 内地址][ULEB128 stacksize]
    // 重定位是 SHT_REL（addend 嵌入在 .stack_sizes 字节里），符号是 STT_SECTION（.text），
    // 故函数地址 = section.guest_addr + sym.value(0) + embedded addend。
    // 注意：.stack_sizes 既非 loadable 也非 debug 段，loader 不会为它读 embedded addend
    //（r.addend 保持 0），必须直接从 stack_sizes_data 读。
    void build_stack_size_map() {
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            LoadedObject& obj = objects_[oi];
            if (obj.stack_sizes_data.empty() || obj.stack_sizes_sec_idx == SIZE_MAX) continue;
            const auto& data = obj.stack_sizes_data;
            // 收集本 obj 所有 target 为 .stack_sizes 的重定位，按 offset 排序。
            std::vector<const LoadedReloc*> rels;
            for (const auto& r : obj.relocations) {
                if (r.target_sec == obj.stack_sizes_sec_idx) rels.push_back(&r);
            }
            std::sort(rels.begin(), rels.end(),
                      [](const LoadedReloc* a, const LoadedReloc* b){ return a->offset < b->offset; });
            for (const LoadedReloc* rp : rels) {
                const LoadedReloc& r = *rp;
                if (r.sym_idx >= obj.symbols.size()) continue;
                // section 符号(.text)的 guest 地址；STB_LOCAL 走 resolve_symbol 的 local 分支。
                auto symval = resolve_symbol(oi, r.sym_idx);
                if (!symval) continue;
                // embedded addend：直接从 .stack_sizes 字节读 8 字节小端（type ABS64）。
                if (r.offset + 8 > data.size()) continue;
                uint64_t addend = 0;
                memcpy(&addend, data.data() + r.offset, 8);
                uint64_t func_addr = *symval + addend;
                // stacksize：紧跟在 8 字节槽后的 ULEB128。
                size_t p = r.offset + 8;
                if (p >= data.size()) continue;
                uint64_t stacksize = 0;
                int shift = 0;
                while (p < data.size()) {
                    uint8_t b = data[p++];
                    stacksize |= (uint64_t)(b & 0x7F) << shift;
                    shift += 7;
                    if (!(b & 0x80)) break;
                }
                stack_sizes_[func_addr] = stacksize;
                if (g_debug)
                    std::cerr << "[elf_linker] stacksize: 0x" << std::hex << func_addr << " = "
                              << std::dec << stacksize << "\n";
            }
        }
    }

    // 修复 .debug_info 里 DW_OP_fbreg 的错误偏移（clang BPF 后端 bug）。
    //
    // 背景：clang BPF 把栈变量偏移算成 +(stacksize-N)（BPF frame base 是帧顶 R10，
    // 通用实现按帧底算），正确应为 -N。本函数按所在函数的 stacksize 把 +N 改成 +N-stacksize。
    //
    // 难点：SLEB128 改写常变长(+4->-120 是 1->2 字节)，变长会移动后续 DIE 偏移，而
    // .debug_info 里遍布 DW_FORM_ref1/2/4/8（CU 内 DIE 偏移引用，如 DW_AT_type）。
    // in-place 改写若不同步 remap 这些 ref 就悬空 -> "invalid abbreviation"。
    //
    // 解法（两遍 buffer 重建，避免 in-place 多级偏移级联）：
    //   Pass A：逐 DIE 扫描，把每个 DIE 序列化成「重建字节块」。fbreg 改写直接产生新字节；
    //           ref1/2/4/8 字段记位置+旧 CU 偏移值，待 Pass B remap。
    //   Pass B：按 DIE 顺序算 old_off->new_off 映射，回填 ref 值；拼成新 CU，回填 unit_length。
    //   长度变化的 CU 收集起来，最后一次性重建整段 .debug_info 贡献区。
    //
    // 只处理 .debug_info 内联的 DW_FORM_exprloc（实测 100% fbreg 在此形态）。
    void fix_fbreg_offsets(std::vector<SecBuf>& extras) {
        if (stack_sizes_.empty()) return;

        // form 字节数（DWARF5 BPF 实际集）。定长返回字节数；变长返回 -1。
        // form 编号见 DWARF5 7.5.5 节（data1=0x0b；strx1/addrx1=0x25/0x29）。
        auto form_fixed_size = [](uint64_t form) -> int {
            switch (form) {
            case 0x01: return 8;   // addr (BPF 8 字节)
            case 0x0b: return 1;   // data1
            case 0x05: return 2;   // data2
            case 0x06: return 4;   // data4
            case 0x07: return 8;   // data8
            case 0x1e: return 16;  // data16
            case 0x0c: return 1;   // flag (data1)
            case 0x11: return 1;   // ref1
            case 0x12: return 2;   // ref2
            case 0x13: return 4;   // ref4
            case 0x14: return 8;   // ref8
            case 0x0e: return 4;   // strp (DWARF32)
            case 0x17: return 4;   // sec_offset (DWARF32)
            case 0x1f: return 4;   // line_strp (DWARF32)
            case 0x25: return 1;   // strx1
            case 0x26: return 2;   // strx2
            case 0x27: return 3;   // strx3
            case 0x28: return 4;   // strx4
            case 0x29: return 1;   // addrx1
            case 0x2a: return 2;   // addrx2
            case 0x2b: return 3;   // addrx3
            case 0x2c: return 4;   // addrx4
            case 0x1c: return 4;   // ref_sup4
            case 0x24: return 8;   // ref_sup8
            default:   return -1;  // 变长/特殊
            }
        };
        // CU 内 DIE 偏移引用的 form -> 字节数（变长 ref_udata 返回 -1）。非 ref 返回 0。
        auto ref_form_size = [](uint64_t form) -> int {
            switch (form) {
            case 0x11: return 1;  // ref1
            case 0x12: return 2;  // ref2
            case 0x13: return 4;  // ref4
            case 0x14: return 8;  // ref8
            default:   return 0;  // ref_udata(0x10,ULEB) 罕见，按非 ref 处理；ref_addr/ref_sup 是跨段绝对偏移不 remap
            }
        };
        auto enc_uleb = [](std::vector<uint8_t>& o, uint64_t v){
            do { uint8_t b = v & 0x7F; v >>= 7; if(v) b |= 0x80; o.push_back(b); } while(v);
        };
        auto enc_sleb = [](std::vector<uint8_t>& o, int64_t v){
            while (true) {
                uint8_t b = v & 0x7F; v >>= 7;
                bool last = ((v == 0 && !(b & 0x40)) || (v == -1 && (b & 0x40)));
                o.push_back(last ? b : (uint8_t)(b | 0x80));
                if (last) break;
            }
        };

        // 收集所有 obj 所有 CU 的重写（绝对段偏移），最后一次性应用到合并 .debug_info。
        struct CURewrite { size_t start; size_t old_len; std::vector<uint8_t> new_bytes; };
        std::vector<CURewrite> cu_rewrites;

        for (size_t oi = 0; oi < objects_.size(); oi++) {
            LoadedObject& obj = objects_[oi];
            DebugSec* info_ds = nullptr;
            SecBuf* info_sec = nullptr;
            for (auto& ds : obj.debug_secs) {
                if (ds.name == ".debug_info" && ds.extra_idx < extras.size()) {
                    info_ds = &ds; info_sec = &extras[ds.extra_idx]; break;
                }
            }
            if (!info_sec) continue;
            const SecBuf* abbr_sec = nullptr;
            size_t abbr_contrib = 0;
            for (const auto& ds : obj.debug_secs) {
                if (ds.name == ".debug_abbrev" && ds.extra_idx < extras.size()) {
                    abbr_sec = &extras[ds.extra_idx]; abbr_contrib = ds.contrib_off; break;
                }
            }
            if (!abbr_sec) continue;
            const SecBuf* addr_sec = nullptr;
            for (const auto& ds : obj.debug_secs) {
                if (ds.name == ".debug_addr" && ds.extra_idx < extras.size()) { addr_sec = &extras[ds.extra_idx]; break; }
            }

            // 解析 abbrev 表：table_key(段内起始偏移) -> {code -> {tag, has_children, [(attr,form,ic)]}}。
            const auto& ad = abbr_sec->data;
            struct AbbrevEntry {
                uint64_t tag; bool has_children;
                std::vector<std::array<uint64_t,3>> attrs;
            };
            std::unordered_map<size_t, std::unordered_map<uint64_t, AbbrevEntry>> abbr_tables;
            {
                size_t q = abbr_contrib;
                while (q < ad.size()) {
                    size_t table_start = q;
                    std::unordered_map<uint64_t, AbbrevEntry> tab;
                    bool any = false;
                    while (q < ad.size()) {
                        uint64_t code = 0; int sh = 0;
                        while (q < ad.size()) { uint8_t b = ad[q++]; code |= (uint64_t)(b&0x7F)<<sh; sh+=7; if(!(b&0x80)) break; }
                        if (code == 0) break;
                        any = true;
                        uint64_t tag = 0; sh = 0;
                        while (q < ad.size()) { uint8_t b = ad[q++]; tag |= (uint64_t)(b&0x7F)<<sh; sh+=7; if(!(b&0x80)) break; }
                        bool has_children = (q < ad.size()) && (ad[q++] != 0);
                        AbbrevEntry e; e.tag = tag; e.has_children = has_children;
                        while (q < ad.size()) {
                            uint64_t attr = 0; sh = 0;
                            while (q < ad.size()) { uint8_t b = ad[q++]; attr |= (uint64_t)(b&0x7F)<<sh; sh+=7; if(!(b&0x80)) break; }
                            uint64_t form = 0; sh = 0;
                            while (q < ad.size()) { uint8_t b = ad[q++]; form |= (uint64_t)(b&0x7F)<<sh; sh+=7; if(!(b&0x80)) break; }
                            if (attr == 0 && form == 0) break;
                            uint64_t ic = 0;
                            if (form == 0x21) { sh = 0; while (q < ad.size()) { uint8_t b = ad[q++]; ic |= (uint64_t)(b&0x7F)<<sh; sh+=7; if(!(b&0x80)) break; } }
                            e.attrs.push_back({attr, form, ic});
                        }
                        tab[code] = std::move(e);
                    }
                    abbr_tables[table_start] = std::move(tab);
                    if (!any) break;
                }
            }

            // 基于合并段（已 patch）分析：必须用 info_sec->data（apply_debug_relocations 已
            // patch 了 DW_AT_addr_base/sec_offset 等），否则 addr_base/str_offsets_base 读到
            // 未 patch 值。但要限制循环在本 obj 贡献区 [contrib_off, contrib_off+orig_size) 内，
            // 不能越界读到别的 obj 的 CU（用错 abbrev 表 -> 级联错位）。
            const auto& d = info_sec->data;
            const size_t contrib_start = info_ds->contrib_off;
            const size_t contrib_end = info_ds->contrib_off + info_ds->data.size();
            auto read_uleb = [&](size_t& pos) -> uint64_t {
                uint64_t v = 0; int sh = 0;
                while (pos < d.size()) { uint8_t b = d[pos++]; v |= (uint64_t)(b&0x7F)<<sh; sh+=7; if(!(b&0x80)) break; }
                return v;
            };

            // ── 逐 CU 重建（ref 是 CU 内偏移，跨 CU 无依赖）。重写收集到全局 cu_rewrites。
            // CU 遍历限制在本 obj 贡献区 [contrib_start, contrib_end)。
            size_t p = contrib_start;
            while (p + 12 <= contrib_end && p + 12 <= d.size()) {
                uint32_t unit_length = 0; memcpy(&unit_length, d.data() + p, 4);
                if (unit_length == 0xffffffff) break;  // DWARF64
                if (unit_length < 8) break;
                size_t cu_end = p + 4 + unit_length;
                if (cu_end > contrib_end || cu_end > d.size()) break;  // 越出本 obj 贡献区
                uint16_t version = 0; memcpy(&version, d.data() + p + 4, 2);
                if (version < 4 || version > 5) { p = cu_end; continue; }
                size_t hdr = p + 4;
                size_t cu_die_start; uint32_t abbr_offset;
                if (version >= 5) {
                    abbr_offset = 0; memcpy(&abbr_offset, d.data() + hdr + 4, 4);
                    cu_die_start = hdr + 8;
                } else {
                    abbr_offset = 0; memcpy(&abbr_offset, d.data() + hdr + 2, 4);
                    cu_die_start = hdr + 7;
                }
                // abbr_offset 是 .debug_abbrev 段内绝对偏移（sec_offset，相对合并段头）。
                // abbr_tables 的键是表在段内的绝对起始偏移（从 abbr_contrib 起扫描得到），
                // 故直接用 abbr_offset 查（不要再加 abbr_contrib）。
                size_t table_key = abbr_offset;
                auto tit = abbr_tables.find(table_key);
                if (tit == abbr_tables.end()) { p = cu_end; continue; }
                const auto& tab = tit->second;
                size_t cu_header_len = cu_die_start - p;
                const size_t CU_BASE = p;  // ref 值是相对 CU 起点的偏移

                // Pass A：每个 DIE = {old_off(相对CU), bytes(重建后), ref_edits[], has_fbreg}。
                struct RefEdit { size_t byte_pos; uint64_t old_cu_off; size_t nbytes; };
                struct DIE {
                    uint64_t old_off;
                    std::vector<uint8_t> bytes;
                    std::vector<RefEdit> ref_edits;
                    bool has_fbreg = false;
                };
                std::vector<DIE> dies;
                std::vector<std::optional<uint64_t>> stk;  // 函数帧栈
                uint64_t cur_addr_base = 8;
                uint64_t cur_loclists_base = 0;  // 本 CU 的 .debug_loclists 偏移表起点(段内绝对)
                bool cu_ok = true;
                size_t q = cu_die_start;
                while (q < cu_end) {
                    size_t die_start = q;
                    uint64_t code = read_uleb(q);
                    DIE de;
                    de.old_off = die_start - CU_BASE;
                    if (code == 0) {
                        de.bytes.push_back(0);
                        if (!stk.empty()) stk.pop_back();
                        dies.push_back(std::move(de));
                        continue;
                    }
                    auto cit = tab.find(code);
                    if (cit == tab.end()) { cu_ok = false; break; }
                    const AbbrevEntry& e = cit->second;
                    enc_uleb(de.bytes, code);

                    std::optional<uint64_t> low_pc_addrx, low_pc_literal;
                    bool found_low_pc = false;
                    bool die_fbreg = false;

                    for (const auto& a : e.attrs) {
                        uint64_t attr = a[0], form = a[1];
                        if (form == 0x21) continue;  // implicit_const
                        if (form == 0x19) continue;  // flag_present

                        if (form == 0x18) {  // DW_FORM_exprloc
                            size_t len_prefix_start = q;
                            uint64_t len = read_uleb(q);
                            size_t expr_end = q + len;
                            if (expr_end > cu_end) { cu_ok = false; break; }
                            bool is_location = (attr == 0x02);
                            std::optional<uint64_t> cur_ss =
                                (is_location && !stk.empty()) ? stk.back() : std::nullopt;
                            if (is_location && cur_ss) {
                                std::vector<uint8_t> new_expr;
                                size_t ep = q;
                                while (ep < expr_end) {
                                    if (d[ep] == 0x91 && ep + 1 < expr_end) {  // DW_OP_fbreg
                                        new_expr.push_back(0x91); ep++;
                                        int64_t stored = 0; int sh2 = 0;
                                        while (ep < expr_end) {
                                            uint8_t b = d[ep++]; stored |= (int64_t)(b & 0x7F) << sh2; sh2 += 7;
                                            if (!(b & 0x80)) { if (b & 0x40) stored |= -((int64_t)1 << sh2); break; }
                                        }
                                        int64_t correct = stored - (int64_t)*cur_ss;
                                        enc_sleb(new_expr, correct);
                                        if (correct != stored) {
                                            die_fbreg = true;
                                            if (g_debug)
                                                std::cerr << "[elf_linker] fbreg: stored=" << stored
                                                          << " ss=" << *cur_ss << " -> " << correct << "\n";
                                        }
                                    } else {
                                        new_expr.push_back(d[ep++]);
                                    }
                                }
                                enc_uleb(de.bytes, (uint64_t)new_expr.size());
                                de.bytes.insert(de.bytes.end(), new_expr.begin(), new_expr.end());
                            } else {
                                // 非 location / 无 stacksize：原样拷贝 len 前缀 + 表达式。
                                de.bytes.insert(de.bytes.end(), d.begin() + len_prefix_start, d.begin() + expr_end);
                            }
                            q = expr_end;
                            continue;
                        }

                        if (form == 0x1b || form == 0x1a || form == 0x0f || form == 0x10 ||
                            form == 0x22 || form == 0x23) {  // ULEB 变长
                            size_t s = q; uint64_t v = read_uleb(q);
                            de.bytes.insert(de.bytes.end(), d.begin() + s, d.begin() + q);
                            if (attr == 0x11) { found_low_pc = true; low_pc_addrx = v; }
                            // DW_AT_location(loclistx) -> 记录该 loclist 所属函数的 stacksize，
                            // 供 fix_loclists_breg10 修 .debug_loclists 里的 DW_OP_breg10 偏移。
                            // 键用 loclists_base + 索引（loclists_base 是偏移表段内绝对偏移，
                            // 索引 *4 后定位偏移表项；loclists_base + 索引 唯一标识该 CU 的该 loclist）。
                            if (attr == 0x02 && form == 0x22 && !stk.empty() && stk.back()) {
                                loclist_ss_[cur_loclists_base + v] = *stk.back();
                            }
                            continue;
                        }
                        if (form == 0x0d) {  // SLEB 变长
                            size_t s = q;
                            while (q < cu_end) { uint8_t b = d[q++]; if (!(b & 0x80)) break; }
                            de.bytes.insert(de.bytes.end(), d.begin() + s, d.begin() + q);
                            continue;
                        }
                        int fsz = form_fixed_size(form);
                        if (fsz > 0) {
                            if (attr == 0x11) {
                                found_low_pc = true;
                                if (form == 0x01) { uint64_t v; memcpy(&v, d.data()+q, 8); low_pc_literal = v; }
                                else if (form == 0x29) low_pc_addrx = d[q];
                                else if (form == 0x2a) { uint16_t v; memcpy(&v, d.data()+q, 2); low_pc_addrx = v; }
                                else if (form == 0x2b) { uint32_t v=0; memcpy(&v, d.data()+q, 3); low_pc_addrx = v; }
                                else if (form == 0x2c) { uint32_t v; memcpy(&v, d.data()+q, 4); low_pc_addrx = v; }
                            } else if (attr == 0x73 && form == 0x17) {  // DW_AT_addr_base
                                uint32_t v; memcpy(&v, d.data()+q, 4); cur_addr_base = v;
                            } else if (attr == 0x8c && form == 0x17) {  // DW_AT_loclists_base
                                uint32_t v; memcpy(&v, d.data()+q, 4); cur_loclists_base = v;
                            }
                            int refsz = ref_form_size(form);
                            if (refsz > 0) {
                                uint64_t oldref = 0; memcpy(&oldref, d.data()+q, refsz);
                                de.ref_edits.push_back({de.bytes.size(), oldref, (size_t)refsz});
                                de.bytes.insert(de.bytes.end(), d.begin() + q, d.begin() + q + refsz);
                            } else {
                                de.bytes.insert(de.bytes.end(), d.begin() + q, d.begin() + q + fsz);
                            }
                            q += fsz;
                        } else {
                            cu_ok = false; break;
                        }
                    }
                    if (!cu_ok) break;
                    de.has_fbreg = die_fbreg;

                    // 压/弹函数帧。
                    if (e.tag == 0x2e && found_low_pc) {
                        std::optional<uint64_t> func_addr;
                        if (low_pc_literal) func_addr = *low_pc_literal;
                        else if (low_pc_addrx && addr_sec) {
                            size_t bo = (size_t)cur_addr_base + (size_t)(*low_pc_addrx) * 8;
                            if (bo + 8 <= addr_sec->data.size()) {
                                uint64_t fa = 0; memcpy(&fa, addr_sec->data.data() + bo, 8); func_addr = fa;
                            }
                        }
                        if (func_addr) {
                            auto sit = stack_sizes_.find(*func_addr);
                            if (sit != stack_sizes_.end() && e.has_children) stk.push_back(sit->second);
                            else if (e.has_children) stk.push_back(std::nullopt);
                        } else if (e.has_children) stk.push_back(std::nullopt);
                    } else if (e.has_children) {
                        stk.push_back(stk.empty() ? std::nullopt : stk.back());
                    }
                    dies.push_back(std::move(de));
                }
                if (!cu_ok) { p = cu_end; continue; }

                // 只有本 CU 有 fbreg 改写时才重建。
                bool need = false;
                for (auto& de : dies) if (de.has_fbreg) { need = true; break; }
                if (!need) { p = cu_end; continue; }

                // Pass B：算 old_off->new_off，回填 ref。
                std::unordered_map<uint64_t, uint64_t> new_off;
                uint64_t acc = cu_header_len;
                for (auto& de : dies) { new_off[de.old_off] = acc; acc += de.bytes.size(); }
                for (auto& de : dies) {
                    for (auto& re : de.ref_edits) {
                        auto it = new_off.find(re.old_cu_off);
                        uint64_t nv = (it != new_off.end()) ? it->second : re.old_cu_off;
                        memcpy(de.bytes.data() + re.byte_pos, &nv, re.nbytes);
                    }
                }
                std::vector<uint8_t> new_cu;
                new_cu.assign(d.begin() + p, d.begin() + p + cu_header_len);  // header 原样
                for (auto& de : dies) new_cu.insert(new_cu.end(), de.bytes.begin(), de.bytes.end());
                uint32_t newlen = (uint32_t)(new_cu.size() - 4);
                memcpy(new_cu.data(), &newlen, 4);

                cu_rewrites.push_back({p, cu_end - p, std::move(new_cu)});
                p = cu_end;
            }
            // CU 重写已收集到全局 cu_rewrites（绝对段偏移），最后统一应用。
        }

        // 所有 obj 处理完：把收集的 CU 重写一次性应用到合并 .debug_info 段。
        // cu_rewrites 按 start 排序后逐段替换；一次重建避免逐 obj 改写的偏移错乱。
        if (!cu_rewrites.empty()) {
            std::sort(cu_rewrites.begin(), cu_rewrites.end(),
                      [](const CURewrite& a, const CURewrite& b){ return a.start < b.start; });
            SecBuf* info_out = nullptr;
            for (auto& obj : objects_)
                for (auto& ds : obj.debug_secs)
                    if (ds.name == ".debug_info" && ds.extra_idx < extras.size()) { info_out = &extras[ds.extra_idx]; break; }
            if (info_out) {
                const auto& src = info_out->data;
                std::vector<uint8_t> out;
                out.reserve(src.size());
                size_t pos = 0;
                for (auto& cr : cu_rewrites) {
                    if (cr.start < pos) continue;  // 防御：重叠跳过
                    out.insert(out.end(), src.begin() + pos, src.begin() + cr.start);
                    out.insert(out.end(), cr.new_bytes.begin(), cr.new_bytes.end());
                    pos = cr.start + cr.old_len;
                }
                out.insert(out.end(), src.begin() + pos, src.end());
                info_out->data = std::move(out);
            }
        }
    }

    // 修正 .debug_loclists 里 DW_OP_breg10(0x7a) 的错误偏移（与 fbreg 同源 bug）。
    // clang BPF 把栈变量偏移算成 +(stacksize-N)，正确应为 -N；breg10 直接相对 R10，
    // 故同样用 stored - stacksize 修正。参数/变量 location 多走 loclist（被 spill），
    // 不修则 GDB 读到帧头保存寄存器槽的垃圾。
    //
    // .debug_loclists（DWARF5）：每贡献区 = header[12B] + offset_table[N*4] + loclist 数据。
    //   每条 loclist = 若干 entry + DW_LLE_end_of_list(0)。
    //   DW_LLE_offset_pair(4)：[start:uleb][end:uleb][expr_len:uleb][expr]。
    //   offset_table[i] = 第 i 条 loclist 起点相对 loclists_base 的偏移（loclistx 索引经此定位）；
    //   loclists_base = 贡献区起点 + 12（offset_table 起点）。
    //
    // 三阶段完整重写（不再 padding 到原长，故 stacksize>64 的 SLEB128 变长 loclist 也能修）：
    //   A. 每条 loclist 按修正后 SLEB128 的【真实长度】重建。
    //   B. offset_table[i] 用新 loclist 起点相对新 loclists_base 的偏移重算（条数/定长 4B 不变，只值变）。
    //   C. 贡献区按真实新长度拼接 -> 后续贡献区起点位移 -> 其 loclists_base 改变；
    //      记录 old_base->new_base 到 loclists_base_remap_，由 remap_loclists_base 定长改写 .debug_info。
    //
    // 之所以可行：所有 loclist 引用都用 DW_FORM_loclistx（索引形式），consumer 只经 offset_table
    // 定位每条 loclist 起点、读到自己的 end_of_list 即止，loclist 之间无需物理连续/定长。
    void fix_loclists_breg10(std::vector<SecBuf>& extras) {
        if (loclist_ss_.empty()) return;
        auto enc_sleb = [](std::vector<uint8_t>& o, int64_t v){
            while (true) {
                uint8_t b = v & 0x7F; v >>= 7;
                bool last = ((v == 0 && !(b & 0x40)) || (v == -1 && (b & 0x40)));
                o.push_back(last ? b : (uint8_t)(b | 0x80));
                if (last) break;
            }
        };
        auto enc_uleb = [](std::vector<uint8_t>& o, uint64_t v){
            do { uint8_t b = v & 0x7F; v >>= 7; if (v) b |= 0x80; o.push_back(b); } while (v);
        };

        // 先按贡献区在段内的出现顺序收集每个贡献区的重建结果，再统一拼到输出段，
        // 这样跨贡献区的位移（阶段 C）可一次算清。
        struct Contrib { size_t old_start; size_t old_len; std::vector<uint8_t> new_bytes; uint64_t old_base; };
        std::vector<Contrib> contribs;
        // 收集时记录贡献区在源段里的绝对起止，用于最后重建整段。

        for (size_t oi = 0; oi < objects_.size(); oi++) {
            const auto& obj = objects_[oi];
            const DebugSec* ll_ds = nullptr;
            for (const auto& ds : obj.debug_secs) {
                if (ds.name == ".debug_loclists" && ds.extra_idx < extras.size()) { ll_ds = &ds; break; }
            }
            if (!ll_ds) continue;
            const SecBuf* ll_sec = &extras[ll_ds->extra_idx];
            const auto& d = ll_sec->data;
            const size_t cs = ll_ds->contrib_off;
            const size_t ce = ll_ds->contrib_off + ll_ds->data.size();
            if (cs + 12 > ce || cs + 12 > d.size()) continue;
            uint32_t unit_length = 0; memcpy(&unit_length, d.data() + cs, 4);
            if (unit_length == 0xffffffff || unit_length < 8) continue;
            size_t hdr_end = cs + 4 + unit_length;  // 本贡献区结束（= unit_length 覆盖范围）
            if (hdr_end > ce || hdr_end > d.size()) continue;
            uint32_t off_cnt = 0; memcpy(&off_cnt, d.data() + cs + 8, 4);
            size_t off_tbl = cs + 12;
            size_t data_start = off_tbl + (size_t)off_cnt * 4;
            if (data_start > hdr_end) continue;
            const uint64_t old_base = cs + 12;  // 旧 loclists_base（offset_table 起点）；loclistx 键 = old_base + i

            // 阶段 A：重建每条 loclist（按真实长度）。new_lists[i] = 该 loclist 重建后字节。
            std::vector<std::vector<uint8_t>> new_lists(off_cnt);
            bool any_change = false;
            // parse_ok=false 表示本贡献区解析出错（未知 LLE code 等）-> 放弃，保留原字节。
            bool parse_ok = true;

            for (uint32_t i = 0; i < off_cnt && parse_ok; i++) {
                uint32_t ll_off = 0; memcpy(&ll_off, d.data() + off_tbl + i * 4, 4);
                size_t start = old_base + ll_off;  // loclist 实际段偏移
                if (start < data_start || start >= hdr_end) { parse_ok = false; break; }
                auto sit = loclist_ss_.find(old_base + i);
                std::optional<uint64_t> ss = (sit != loclist_ss_.end())
                    ? std::optional<uint64_t>(sit->second) : std::nullopt;
                std::vector<uint8_t>& nb = new_lists[i];
                bool changed = false;
                size_t q = start;
                // 通用 LLE entry 解析：code + (地址部分) + (表达式部分)。
                //   0 end_of_list：无。1 base_addressx：[addrx:uleb]。6 base_address：[addr:8]。
                //   2 startx_endx：[s:uleb][e:uleb] + expr。3 start_end：[s:8][e:8] + expr。
                //   4 offset_pair：[s:uleb][e:uleb] + expr。5 default：expr。
                //   7 startx_length：[s:uleb][len:uleb] + expr。
                // 表达式部分（2/3/4/5/7）= [elen:uleb][bytes]，其中 breg10 可改写。
                auto copy_uleb = [&]() -> bool {
                    while (q < hdr_end) { uint8_t b = d[q++]; nb.push_back(b); if (!(b & 0x80)) return true; }
                    return false;
                };
                auto copy_fixed = [&](size_t n) -> bool {
                    if (q + n > hdr_end) return false;
                    nb.insert(nb.end(), d.begin() + q, d.begin() + q + n);
                    q += n; return true;
                };
                auto copy_expr_with_breg10 = [&]() -> bool {
                    uint64_t elen = 0; int sh = 0;
                    while (q < hdr_end) { uint8_t b = d[q++]; elen |= (uint64_t)(b & 0x7F) << sh; sh += 7; if (!(b & 0x80)) break; }
                    size_t expr_end = q + elen;
                    if (expr_end > hdr_end) return false;
                    std::vector<uint8_t> new_expr;
                    size_t ep = q;
                    while (ep < expr_end) {
                        if (d[ep] == 0x7a && ep + 1 < expr_end && ss) {
                            new_expr.push_back(0x7a); ep++;
                            int64_t stored = 0; int sh2 = 0;
                            while (ep < expr_end) {
                                uint8_t b = d[ep++]; stored |= (int64_t)(b & 0x7F) << sh2; sh2 += 7;
                                if (!(b & 0x80)) { if (b & 0x40) stored |= -((int64_t)1 << sh2); break; }
                            }
                            int64_t correct = stored - (int64_t)*ss;
                            enc_sleb(new_expr, correct);
                            if (correct != stored) { changed = true;
                                if (g_debug) std::cerr << "[elf_linker] breg10: stored=" << stored
                                                       << " ss=" << *ss << " -> " << correct << "\n"; }
                        } else {
                            new_expr.push_back(d[ep++]);
                        }
                    }
                    enc_uleb(nb, new_expr.size());
                    nb.insert(nb.end(), new_expr.begin(), new_expr.end());
                    q = expr_end;
                    return true;
                };
                bool done = false;
                while (q < hdr_end) {
                    uint8_t code = d[q];
                    if (code == 0) { nb.push_back(0); q++; done = true; break; }  // end_of_list
                    nb.push_back(code); q++;
                    bool ok = true;
                    switch (code) {
                    case 1: ok = copy_uleb(); break;                       // base_addressx
                    case 6: ok = copy_fixed(8); break;                     // base_address
                    case 5: ok = copy_expr_with_breg10(); break;           // default (expr)
                    case 4: case 2:                                        // offset_pair / startx_endx
                        ok = copy_uleb() && copy_uleb() && copy_expr_with_breg10(); break;
                    case 3: ok = copy_fixed(8) && copy_fixed(8) && copy_expr_with_breg10(); break; // start_end
                    case 7: ok = copy_uleb() && copy_uleb() && copy_expr_with_breg10(); break; // startx_length
                    default: ok = false; break;                            // 未知 code：放弃本贡献区
                    }
                    if (!ok) break;
                }
                if (!done) parse_ok = false;  // 未正常遇到 end_of_list
                if (changed) any_change = true;
            }

            if (!parse_ok || !any_change) {
                // 解析失败或无可改写项 -> 保留原贡献区字节，loclists_base 不变（old_base->old_base）。
                contribs.push_back({cs, hdr_end - cs,
                                    std::vector<uint8_t>(d.begin() + cs, d.begin() + hdr_end), old_base});
                continue;
            }

            // 阶段 B：重算 offset_table（值变，条数/定长 4B 不变）。new_off_tbl[i] = 第 i 条
            //   loclist 新起点 相对新 loclists_base(= 贡献区新起点+12) 的偏移。
            //   新 loclist 体从 offset_table 之后开始排列，第 i 条起点 = off_cnt*4 + sum_{j<i} new_lists[j].size()。
            std::vector<uint8_t> new_off_tbl((size_t)off_cnt * 4, 0);
            size_t acc = (size_t)off_cnt * 4;  // 相对 offset_table 起点的偏移
            for (uint32_t i = 0; i < off_cnt; i++) {
                uint32_t v = (uint32_t)acc;
                memcpy(new_off_tbl.data() + (size_t)i * 4, &v, 4);
                acc += new_lists[i].size();
            }

            // 阶段 C：拼新贡献区 = header(12, unit_length 待回填) + 新 offset_table + 新 loclist 体。
            std::vector<uint8_t> nb;
            nb.reserve(12 + new_off_tbl.size() + acc);
            nb.insert(nb.end(), d.begin() + cs, d.begin() + cs + 12);  // 旧 header（unit_length 后回填）
            nb.insert(nb.end(), new_off_tbl.begin(), new_off_tbl.end());
            for (uint32_t i = 0; i < off_cnt; i++)
                nb.insert(nb.end(), new_lists[i].begin(), new_lists[i].end());
            uint32_t new_unit_length = (uint32_t)(nb.size() - 4);
            memcpy(nb.data(), &new_unit_length, 4);

            contribs.push_back({cs, hdr_end - cs, std::move(nb), old_base});
        }

        if (contribs.empty()) return;

        // 阶段 C 续：按贡献区在源段里的顺序（old_start 升序）拼出整段，累计位移算 new_base。
        std::sort(contribs.begin(), contribs.end(),
                  [](const Contrib& a, const Contrib& b){ return a.old_start < b.old_start; });
        // 收集每个贡献区前后两段之间源段里的"间隙"字节（不在任何 .debug_loclists 贡献区里，
        // 例如段头/对齐填充），原样保留；位移也要计入。
        SecBuf* ll_out = nullptr;
        for (auto& obj : objects_)
            for (auto& ds : obj.debug_secs)
                if (ds.name == ".debug_loclists" && ds.extra_idx < extras.size()) { ll_out = &extras[ds.extra_idx]; break; }
        if (!ll_out) return;
        const auto& src = ll_out->data;
        std::vector<uint8_t> out;
        out.reserve(src.size());
        size_t pos = 0;
        for (auto& c : contribs) {
            // 间隙 [pos, c.old_start)：原样拷贝，其内字节位移同 out 当前长度。
            if (c.old_start > pos)
                out.insert(out.end(), src.begin() + pos, src.begin() + c.old_start);
            // 贡献区位移：old_base = old_start + 12 -> new_base = out.size() + 12。
            size_t new_start = out.size();
            uint64_t new_base = new_start + 12;
            loclists_base_remap_[c.old_base] = new_base;
            out.insert(out.end(), c.new_bytes.begin(), c.new_bytes.end());
            pos = c.old_start + c.old_len;
        }
        if (pos < src.size())
            out.insert(out.end(), src.begin() + pos, src.end());
        ll_out->data = std::move(out);
    }

    // 用 fix_loclists_breg10 产出的 old_base->new_base 表，定长改写 .debug_info 里所有
    // DW_AT_loclists_base(0x8c) 的 4 字节 sec_offset 槽（DW_FORM_sec_offset=0x17, DWARF32 定长）。
    // 贡献区按真实长度重建后位移，其 loclists_base（sec_offset，已由 apply_debug_relocations
    // patch 为段内绝对偏移）必须同步更新，否则 loclistx 解引用越界。
    //
    // 这里只做【定长字节级改写】，不改 DIE 边界/长度，故可在 fix_fbreg_offsets（变长重建）
    // 之后再扫一遍最终的 .debug_info。注意：fbreg 重建改变了各 obj 贡献区在合并段里的边界，
    // 故不能按 obj 贡献区逐段扫（contrib_off/旧 data.size() 已失效），改为：
    //   -  把所有 obj 的 .debug_abbrev 合并成一张全局 abbrev 表（键=表段内绝对偏移，即 abbr_offset）；
    //   -  把整个合并 .debug_info 当作一条连续的 CU 流，从头扫到尾。
    void remap_loclists_base(std::vector<SecBuf>& extras) {
        if (loclists_base_remap_.empty()) return;

        // 合并 .debug_info / .debug_abbrev 段（已在 fix_fbreg_offsets/apply_debug_relocations 后）。
        SecBuf* info_out = nullptr;
        const SecBuf* abbr_out = nullptr;
        for (auto& obj : objects_) {
            for (auto& ds : obj.debug_secs) {
                if (ds.extra_idx >= extras.size()) continue;
                if (ds.name == ".debug_info" && !info_out) info_out = &extras[ds.extra_idx];
                if (ds.name == ".debug_abbrev" && !abbr_out) abbr_out = &extras[ds.extra_idx];
            }
        }
        if (!info_out || !abbr_out) return;

        const auto& ad = abbr_out->data;
        // 全局 abbrev 表：表段内绝对偏移 -> {code -> [(attr,form)]}。扫一遍合并 .debug_abbrev。
        std::unordered_map<size_t, std::unordered_map<uint64_t,
            std::vector<std::pair<uint64_t,uint64_t>>>> abbr_tables;
        {
            size_t q = 0;
            while (q < ad.size()) {
                size_t table_start = q;
                std::unordered_map<uint64_t, std::vector<std::pair<uint64_t,uint64_t>>> tab;
                bool any = false;
                while (q < ad.size()) {
                    uint64_t code = 0; int sh = 0;
                    while (q < ad.size()) { uint8_t b = ad[q++]; code |= (uint64_t)(b&0x7F)<<sh; sh+=7; if(!(b&0x80)) break; }
                    if (code == 0) break;
                    any = true;
                    uint64_t tag = 0; sh = 0;
                    while (q < ad.size()) { uint8_t b = ad[q++]; tag |= (uint64_t)(b&0x7F)<<sh; sh+=7; if(!(b&0x80)) break; }
                    (void)tag;
                    bool has_children = (q < ad.size()) && (ad[q++] != 0);
                    std::vector<std::pair<uint64_t,uint64_t>> attrs;
                    while (q < ad.size()) {
                        uint64_t attr = 0; sh = 0;
                        while (q < ad.size()) { uint8_t b = ad[q++]; attr |= (uint64_t)(b&0x7F)<<sh; sh+=7; if(!(b&0x80)) break; }
                        uint64_t form = 0; sh = 0;
                        while (q < ad.size()) { uint8_t b = ad[q++]; form |= (uint64_t)(b&0x7F)<<sh; sh+=7; if(!(b&0x80)) break; }
                        if (attr == 0 && form == 0) break;
                        if (form == 0x21) { sh=0; while(q<ad.size()){uint8_t b=ad[q++]; if(!(b&0x80)) break;} }  // implicit_const ULEB
                        attrs.emplace_back(attr, form);
                    }
                    (void)has_children;
                    tab[code] = std::move(attrs);
                }
                abbr_tables[table_start] = std::move(tab);
                if (!any) break;
            }
        }

        // form 定长字节数（与 fix_fbreg_offsets 一致；变长返回 -1）。
        auto form_fixed_size = [](uint64_t form) -> int {
            switch (form) {
            case 0x01: return 8;   // addr
            case 0x0b: return 1;   // data1
            case 0x05: return 2;   // data2
            case 0x06: return 4;   // data4
            case 0x07: return 8;   // data8
            case 0x1e: return 16;  // data16
            case 0x0c: return 1;   // flag
            case 0x11: return 1;   // ref1
            case 0x12: return 2;   // ref2
            case 0x13: return 4;   // ref4
            case 0x14: return 8;   // ref8
            case 0x0e: return 4;   // strp (DWARF32)
            case 0x17: return 4;   // sec_offset (DWARF32)
            case 0x1f: return 4;   // line_strp (DWARF32)
            case 0x25: return 1; case 0x26: return 2; case 0x27: return 3; case 0x28: return 4;  // strx1..4
            case 0x29: return 1; case 0x2a: return 2; case 0x2b: return 3; case 0x2c: return 4;  // addrx1..4
            case 0x1c: return 4; case 0x24: return 8;  // ref_sup4 / ref_sup8
            default:   return -1;
            }
        };

        auto& out = *info_out;  // 直接在最终 .debug_info 上定长改写
        const auto& d = out.data;
        auto read_uleb = [&](size_t& pos) -> uint64_t {
            uint64_t v = 0; int sh = 0;
            while (pos < d.size()) { uint8_t b = d[pos++]; v |= (uint64_t)(b&0x7F)<<sh; sh+=7; if(!(b&0x80)) break; }
            return v;
        };

        // 整段 .debug_info 当作 CU 流，从头扫到尾（fbreg 重建后贡献区边界已变，不能按 obj 分段）。
        size_t p = 0;
        while (p + 12 <= d.size()) {
            uint32_t unit_length = 0; memcpy(&unit_length, d.data() + p, 4);
            if (unit_length == 0xffffffff) break;  // DWARF64（不支持）
            if (unit_length < 8) break;
            size_t cu_end = p + 4 + unit_length;
            if (cu_end > d.size()) break;
            uint16_t version = 0; memcpy(&version, d.data() + p + 4, 2);
            if (version < 4 || version > 5) { p = cu_end; continue; }
            size_t hdr = p + 4;
            size_t cu_die_start; uint32_t abbr_offset;
            if (version >= 5) {
                abbr_offset = 0; memcpy(&abbr_offset, d.data() + hdr + 4, 4);
                cu_die_start = hdr + 8;
            } else {
                abbr_offset = 0; memcpy(&abbr_offset, d.data() + hdr + 2, 4);
                cu_die_start = hdr + 7;
            }
            auto tit = abbr_tables.find((size_t)abbr_offset);
            if (tit == abbr_tables.end()) { p = cu_end; continue; }
            const auto& tab = tit->second;

            // 遍历本 CU 的 DIE，定位 loclists_base 槽。loclists_base 只出现在
            // compile_unit DIE 上，但完整遍历也无害（null DIE 被当作分隔符跳过）。
            size_t q = cu_die_start;
            bool cu_done = false;
            while (q < cu_end && !cu_done) {
                uint64_t code = read_uleb(q);
                if (code == 0) continue;  // null DIE（兄弟链表分隔符）
                auto cit = tab.find(code);
                if (cit == tab.end()) { cu_done = true; break; }
                bool has_locbase = false; size_t locbase_slot = 0;
                for (const auto& [attr, form] : cit->second) {
                    if (form == 0x21) continue;       // implicit_const（值在 abbrev 里）
                    if (form == 0x19) continue;       // flag_present（无数据）
                    // 记 loclists_base 槽位置（改写前先跳过前面所有属性的长度）。
                    if (attr == 0x8c && form == 0x17) {
                        has_locbase = true; locbase_slot = q;
                    }
                    if (form == 0x18) {              // exprloc：[len:uleb][len bytes]
                        uint64_t elen = read_uleb(q);
                        q += elen;
                        continue;
                    }
                    if (form == 0x1b || form == 0x1a || form == 0x0f || form == 0x10 ||
                        form == 0x22 || form == 0x23) { read_uleb(q); continue; }
                    if (form == 0x0d) { while (q < cu_end) { uint8_t b = d[q++]; if (!(b & 0x80)) break; } continue; }
                    int fsz = form_fixed_size(form);
                    if (fsz > 0) { q += fsz; continue; }
                    // 遇未知 form：放弃本 CU（不改写），保底安全。
                    cu_done = true; break;
                }
                if (cu_done) break;
                // 定长改写 loclists_base（在最终 .debug_info 上）。
                if (has_locbase && locbase_slot + 4 <= d.size()) {
                    uint32_t oldv = 0; memcpy(&oldv, d.data() + locbase_slot, 4);
                    auto rit = loclists_base_remap_.find(oldv);
                    if (rit != loclists_base_remap_.end()) {
                        uint32_t newv = (uint32_t)rit->second;
                        memcpy(out.data.data() + locbase_slot, &newv, 4);
                        if (g_debug)
                            std::cerr << "[elf_linker] loclists_base: " << oldv << " -> " << newv << "\n";
                    }
                }
            }
            p = cu_end;
        }
    }

    // 应用 DWARF 段的重定位（.rel.debug_*）。两类：
    //   - target 是 debug 段：patch 写在 extras[extra_idx].data 里
    //   - 符号值按 resolve_debug_value：debug->debug 取段内偏移，debug->loadable 取 guest 地址
    // 类型仅 R_BPF_64_ABS32(3)/R_BPF_64_ABS64(2)（DWARF 不会出现 lddw/call）。
    void apply_debug_relocations(std::vector<SecBuf>& extras) {
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            const auto& obj = objects_[oi];
            for (const auto& r : obj.relocations) {
                if (r.target_sec >= obj.sections.size()) continue;
                // 只处理 target 是 debug 段的重定位（.rel.debug_*）
                auto lit = obj.dbg_sec_local_idx.find(r.target_sec);
                if (lit == obj.dbg_sec_local_idx.end()) continue;
                const auto& ds = obj.debug_secs[lit->second];
                if (ds.extra_idx >= extras.size()) continue;
                auto& out = extras[ds.extra_idx];
                // 合并段里本 .o 贡献区从 contrib_off 起，patch 点要落在贡献区内。
                size_t patch_off = ds.contrib_off + r.offset;
                // 越界校验（针对实际要 patch 的输出副本）
                if (patch_off + reloc_write_len(r.type) > out.data.size()) {
                    std::cerr << "[elf_linker] debug reloc out of bounds in " << obj.source
                              << ": offset=" << r.offset << " type=" << r.type
                              << " sec=" << ds.name << " size=" << out.data.size() << "\n";
                    continue;
                }
                auto resolved = resolve_debug_value(oi, r.sym_idx);
                if (!resolved) continue;
                uint64_t S = *resolved;
                uint8_t* patch = out.data.data() + patch_off;
                switch (r.type) {
                case 3: {  // R_BPF_64_ABS32
                    uint32_t V = (uint32_t)(S + (uint64_t)r.addend);
                    memcpy(patch, &V, 4);
                    break;
                }
                case 2: {  // R_BPF_64_ABS64
                    uint64_t V = S + (uint64_t)r.addend;
                    memcpy(patch, &V, 8);
                    break;
                }
                default:
                    break;  // DWARF 不应出现其它类型
                }
            }
        }
    }

    // 符号所在 section -> 输出 ELF 的 section index（text/rodata/data/bss/ABS）
    Elf64_Half sym_to_shndx(const LoadedObject& obj, size_t sec_idx,
                             Elf64_Half bss_shndx, const Elf64_Half seg_shndx[3]) const {
        if (sec_idx == SIZE_MAX || sec_idx >= obj.sections.size()) return SHN_ABS;
        const LoadedSection& ls = obj.sections[sec_idx];
        if (ls.type == SHT_NOBITS && ls.seg == SEG_DATA) return bss_shndx ? bss_shndx : SHN_ABS;
        return seg_shndx[ls.seg] ? seg_shndx[ls.seg] : SHN_ABS;
    }

    // 构建 .strtab + .symtab（完整符号表，调试用；运行时符号解析另走 .dynsym）。
    // 三种模式都输出，对齐标准 ld 默认行为：本地符号在前、global 在后，sh_info 指向
    // 第一个 global（SHT_SYMTAB 约定）。本地符号含 STB_LOCAL 的 FUNC/OBJECT，让
    // objdump -d 等工具能在反汇编中标注函数边界。
    void build_static_symtab(std::vector<SecBuf>& extras, Elf64_Half extras_base,
                              Elf64_Half bss_shndx, const Elf64_Half seg_shndx[3]) const {
        SecBuf strtab;
        strtab.name = ".strtab";
        strtab.type = SHT_STRTAB;
        strtab.data.push_back(0);  // strtab[0] = '\0'（空名）
        strtab.addralign = 1;

        SecBuf symtab;
        symtab.name = ".symtab";
        symtab.type = SHT_SYMTAB;
        symtab.addralign = 8;
        symtab.entsize = sizeof(Elf64_Sym);

        // strtab 写入名字，返回偏移
        auto add_name = [&](const std::string& n) -> Elf64_Word {
            if (n.empty()) return 0;
            Elf64_Word off = (Elf64_Word)strtab.data.size();
            strtab.data.insert(strtab.data.end(), n.begin(), n.end());
            strtab.data.push_back(0);
            return off;
        };

        // NULL 符号（index 0）
        Elf64_Sym zsym = {};
        size_t sym_count = 0;
        symtab.data.insert(symtab.data.end(), (uint8_t*)&zsym, (uint8_t*)&zsym + sizeof(zsym));
        sym_count++;

        auto emit = [&](const LoadedObject& obj, const LoadedSym& sym, int bind) {
            Elf64_Sym s = {};
            s.st_name = add_name(sym.name);
            s.st_info = GELF_ST_INFO(bind, sym.type == 0 ? STT_FUNC : sym.type);
            s.st_other = GELF_ST_VISIBILITY(sym.visibility);  // 保留原可见性
            s.st_shndx = sym_to_shndx(obj, sym.sec_idx, bss_shndx, seg_shndx);
            s.st_value = sec_guest_addr_of(obj, sym.sec_idx) + sym.value;
            s.st_size = sym.size;
            symtab.data.insert(symtab.data.end(), (uint8_t*)&s, (uint8_t*)&s + sizeof(s));
            sym_count++;
        };

        // -  本地符号（STB_LOCAL 的 FUNC/OBJECT；section 符号 STT_SECTION 也算 local，
        //    但对反汇编帮助不大且无名字，跳过）
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            const auto& obj = objects_[oi];
            for (size_t si = 1; si < obj.symbols.size(); si++) {
                const auto& sym = obj.symbols[si];
                if (sym.binding != STB_LOCAL) continue;
                if (!sym.defined) continue;
                if (sym.type != STT_FUNC && sym.type != STT_OBJECT) continue;
                emit(obj, sym, STB_LOCAL);
            }
        }
        // sh_info = 第一个 global 的下标（local 区结束位置）
        symtab.info = (Elf64_Word)sym_count;

        // -  全局符号（去重：每个 global 名只输出 globals_ 里的定义）
        for (const auto& kv : globals_) {
            const auto& obj = objects_[kv.second.obj_idx];
            const auto& sym = obj.symbols[kv.second.sym_idx];
            emit(obj, sym, STB_GLOBAL);
        }

        // -  合成全局符号（__init_array_start/end 等，SHN_ABS）
        for (const auto& kv : synthetic_globals_) {
            Elf64_Sym s = {};
            s.st_name = add_name(kv.first);
            s.st_info = GELF_ST_INFO(STB_GLOBAL, STT_OBJECT);
            s.st_other = 0;
            s.st_shndx = SHN_ABS;
            s.st_value = kv.second;
            s.st_size = 0;
            symtab.data.insert(symtab.data.end(), (uint8_t*)&s, (uint8_t*)&s + sizeof(s));
            sym_count++;
        }

        size_t strtab_idx = extras.size();
        extras.push_back(std::move(strtab));
        size_t symtab_idx = extras.size();
        extras.push_back(std::move(symtab));
        extras[symtab_idx].link = extras_base + (Elf64_Word)strtab_idx;
    }

    // 收集所有 UND 符号名（跨模块重定位引用的未定义符号 -> .dynsym 的导入部分）。
    // DYNAMIC_EXE：入口符号若不在 globals_ 也加入，让 .rela.plt 能引用（PLT 桩作 e_entry）。
    // 同时跟踪每个名字是否「纯 weak UND」：某名字的所有 UND 引用都是 STB_WEAK（且无 globals_
    // 定义、不是 _DYNAMIC/入口）时，标记为 weak——输出到 .dynsym 时写 STB_WEAK，loader 对其
    // 解析失败静默处理（weak UND -> 0 是标准 ld 语义，如 musl 的 __init_array_start 等边界符号）。
    struct UndNames {
        std::vector<std::string> names;
        std::unordered_map<std::string, size_t> idx;            // name -> names 下标
        std::unordered_map<std::string, bool> is_weak;          // name -> 是否纯 weak UND
    };
    UndNames collect_und_names() const {
        UndNames out;
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            for (const auto& r : objects_[oi].relocations) {
                if (r.sym_idx >= objects_[oi].symbols.size()) continue;
                const auto& sym = objects_[oi].symbols[r.sym_idx];
                if (sym.defined || sym.name.empty()) continue;
                if (sym.name == "_DYNAMIC") continue;  // 由 build_dynamic_sections 合成为 defined 符号
                if (synthetic_globals_.count(sym.name)) continue;  // 已合成为 defined 符号
                // 内部已定义（globals_ 里有）的符号不发 UND
                if (globals_.find(sym.name) != globals_.end()) continue;
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
            // hidden 符号不导出到 .dynsym（标准 ELF 语义：不可被其它模块引用）。
            // 本链接单元内的引用由 .rela.dyn 的 def_in_unit 分支处理，故不导出无副作用。
            if (sym.visibility == STV_HIDDEN) continue;
            if (export_name_off.find(sym.name) != export_name_off.end()) continue;
            Elf64_Word off = (Elf64_Word)dynstr.data.size();
            dynstr.data.insert(dynstr.data.end(), sym.name.begin(), sym.name.end());
            dynstr.data.push_back(0);
            export_name_off[sym.name] = off;
        }
        // 合成符号（__init_array_start 等）也进 dynstr，供 .dynsym emit。
        for (const auto& kv : synthetic_globals_) {
            Elf64_Word off = (Elf64_Word)dynstr.data.size();
            dynstr.data.insert(dynstr.data.end(), kv.first.begin(), kv.first.end());
            dynstr.data.push_back(0);
            export_name_off[kv.first] = off;
        }
        // _DYNAMIC：标准 ld 在 PIE/.so 上合成的符号，指向 .dynamic section 起始。
        // musl __init_tls/dl_iterate_phdr 用它（weak 引用）反推加载基址。bpfvm-ld
        // 这里合成 defined 符号，避免运行时加载器报 "unresolved symbol '_DYNAMIC'"
        // （虽然 weak UND -> 0 语义上安全，musl 走 PT_PHDR 兜底，但消掉噪音更干净）。
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
        std::unordered_map<std::string, size_t> dynsym_idx;  // name -> .dynsym index (0-based)
        for (size_t i = 0; i < und_names.size(); i++) {
            Elf64_Sym s = {};
            s.st_name = und_name_offs[i];
            const std::string& nm = und_names[i];
            bool weak = und.is_weak.count(nm) && und.is_weak.at(nm);
            // 纯 weak UND（如 __init_array_start/__fini_array_start）：保留 STB_WEAK，loader
            // 对其解析失败静默处理（weak UND -> 0，标准 ld 语义）；其余 UND 保持 STB_GLOBAL。
            s.st_info = GELF_ST_INFO(weak ? STB_WEAK : STB_GLOBAL, STT_NOTYPE);
            s.st_shndx = SHN_UNDEF;
            dynsym.data.insert(dynsym.data.end(), (uint8_t*)&s, (uint8_t*)&s + sizeof(s));
            dynsym_idx[nm] = 1 + i;
        }
        Elf64_Word first_global = 1 + (Elf64_Word)und_names.size();
        for (const auto& kv : globals_) {
            const auto& obj = objects_[kv.second.obj_idx];
            const auto& sym = obj.symbols[kv.second.sym_idx];
            // hidden 符号不导出到 .dynsym（与 dynstr 收集处一致）。
            if (sym.visibility == STV_HIDDEN) continue;
            Elf64_Sym s = {};
            auto it = export_name_off.find(sym.name);
            if (it != export_name_off.end()) s.st_name = it->second;
            s.st_info = GELF_ST_INFO(STB_GLOBAL, sym.type == 0 ? STT_FUNC : sym.type);
            // 保留原符号 visibility（st_other 低 2 位）。非 hidden 符号（DEFAULT/PROTECTED）
            // 也写出真实值，而非一律 0——PROTECTED 符号导出但不可被预empt（本链接器/loader
            // 目前不区分，但写出正确值让 ELF 符合标准语义）。
            s.st_other = GELF_ST_VISIBILITY(sym.visibility);
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
        // 合成符号（__init_array_start/end 等）：SHN_ABS defined，值是 layout 算好的 vaddr。
        // 让 loader 的 collect_exports 收为 defined，.rela.dyn 引用能解析。
        for (const auto& kv : synthetic_globals_) {
            Elf64_Sym s = {};
            auto nit = export_name_off.find(kv.first);
            if (nit != export_name_off.end()) s.st_name = nit->second;
            s.st_info = GELF_ST_INFO(STB_GLOBAL, STT_OBJECT);
            s.st_shndx = SHN_ABS;
            s.st_value = kv.second;
            dynsym.data.insert(dynsym.data.end(), (uint8_t*)&s, (uint8_t*)&s + sizeof(s));
            dynsym_idx[kv.first] = dynsym.data.size() / sizeof(Elf64_Sym) - 1;
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
        //   - 本链接单元内定义的符号（含本 obj 定义 + UND 但由同链接单元的 .o/.a 提供）：
        //     用 NULL 符号(idx 0) + addend = 符号相对地址，VM resolve 返回 load_base。
        //   - 真正的外部 UND 符号（本链接单元不提供，来自 .so）：查 .dynsym 索引，VM 按名解析。
        // call (type 10) 不记：构建期已处理（内部相对 call / UND 走 PLT）
        SecBuf reladyn;
        reladyn.name = ".rela.dyn";
        reladyn.type = SHT_RELA;
        reladyn.addralign = 8;
        reladyn.entsize = sizeof(Elf64_Rela);
        reladyn.link = extras_base + (Elf64_Word)out.dynsym_idx;
        bool has_textrel = false;  // 是否有写到可执行段的重定位（lddw imm patch text）
        for (size_t oi = 0; oi < objects_.size(); oi++) {
            for (const auto& r : objects_[oi].relocations) {
                if (r.sym_idx >= objects_[oi].symbols.size()) continue;
                const auto& sym = objects_[oi].symbols[r.sym_idx];
                if (r.target_sec >= objects_[oi].sections.size()) continue;
                if (r.type == 10) continue;
                const auto& target = objects_[oi].sections[r.target_sec];
                if (!target.loadable) continue;
                if (target.executable) has_textrel = true;
                Elf64_Rela rela = {};
                rela.r_offset = target.guest_addr + r.offset;
                // 判断符号是否在本链接单元内有定义：本 obj 定义，或 UND 但由同链接单元的
                // 其它 .o/.a 提供（globals_/synthetic_globals_ 命中）。两者都走本模块内部
                // 引用（sym_idx=0 + addend=解析地址），不查 .dynsym。
                bool def_in_unit = sym.defined ||
                    globals_.count(sym.name) ||
                    synthetic_globals_.count(sym.name);
                if (def_in_unit) {
                    // 用 globals_ 解析后的地址（resolve_symbol），而非本 obj 内的局部定义地址：
                    // weak 符号被 strong 覆盖时 addend 必须指向胜出定义，否则读到错误地址。
                    auto resolved = resolve_symbol(oi, r.sym_idx);
                    uint64_t sym_addr = resolved.value_or(
                        sym.defined ? (sec_guest_addr_of(objects_[oi], sym.sec_idx) + sym.value) : 0);
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
        // PLT 桩 lddw 重定位：每个桩的 lddw 指令（加载 GOT 槽地址）需运行期 patch 成
        // base+槽vaddr。emit_plt_stub 在构建期把 lddw imm 写成槽的链接期 vaddr（相对基址），
        // 这里为每个桩发射一条 type 1 (R_BPF_64_64)、sym_idx=0 的 .rela.dyn 条目：
        //   r_offset = 桩地址，addend = GOT 槽 vaddr。
        if (got_enabled_) {
            for (const auto& sym : got_syms_) {
                auto pe = plt_entries_.find(sym);
                auto git = got_slots_.find(sym);
                if (pe == plt_entries_.end() || git == got_slots_.end()) continue;
                const LoadedSection& plt_sec = objects_[pe->second.obj_idx].sections[1];
                const LoadedSection& got_sec = objects_[git->second.obj_idx].sections[1];
                Elf64_Rela rela = {};
                rela.r_offset = plt_sec.guest_addr + pe->second.offset;  // 桩 lddw 指令地址
                rela.r_info = ELF64_R_INFO(0, 1);  // type 1, NULL 符号（本模块内部）
                rela.r_addend = got_sec.guest_addr + git->second.offset;  // GOT 槽 vaddr
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
                rela.r_info = ELF64_R_INFO(si, 2);  // R_BPF_64_ABS64：8 字节平坦写（GOT 槽是数据槽，非 lddw 指令）
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
        dynamic.link = extras_base + (Elf64_Word)out.dynstr_idx;  // .dynamic.sh_link -> .dynstr
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
        if (has_textrel) add_dyn(DT_TEXTREL, 0);
        if (got_enabled_ && out.relaplt_idx != SIZE_MAX) {
            add_dyn(DT_JMPREL, 0);
            add_dyn(DT_PLTRELSZ, extras[out.relaplt_idx].data.size());
            add_dyn(DT_PLTREL, DT_RELA);  // PLT 重定位类型 = RELA
            add_dyn(DT_PLTGOT, 0);
        }
        // 全局构造/析构函数指针表。值是段内 guest vaddr（基址=0，layout_segments 后已就绪，
        // 与 DT_PLTGOT 同源——都是 SEG_DATA 段内 section，不进 backfill_dynamic_vaddrs，
        // 也不写占位 0）。loader 用 load_base + d_val 定位。
        // 用 !empty() 判非空（size>0）：PIE/fixed_base=0 下首地址可能合法为 0，不能用 != 0。
        if (!init_array_.empty()) {
            add_dyn(DT_INIT_ARRAY,   init_array_.start);
            add_dyn(DT_INIT_ARRAYSZ, init_array_.size());
        }
        if (!fini_array_.empty()) {
            add_dyn(DT_FINI_ARRAY,   fini_array_.start);
            add_dyn(DT_FINI_ARRAYSZ, fini_array_.size());
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
    // seg_data_off 页对齐：保证 p_offset == p_vaddr (mod 0x1000) 对所有 PT_LOAD 成立
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
        if (need_ehdr()) { L.has_phdr = true; L.phnum += 1; }
        L.shnum = next_sh + (Elf64_Half)extras.size();  // NULL + 段secs + bss + extras
        L.shstrndx = extras_base + (Elf64_Half)shstrtab_idx;

        uint64_t eh_size = sizeof(Elf64_Ehdr);
        uint64_t ph_size = sizeof(Elf64_Phdr) * L.phnum;
        L.seg_data_off = (eh_size + ph_size + 0xFFF) & ~0xFFFULL;
        uint64_t cur = L.seg_data_off;
        for (int c = 0; c < 3; c++) {
            if (!segs_[c].used) continue;
            // 段间文件 offset 按页对齐
            cur = (cur + 0xFFF) & ~0xFFFULL;
            L.seg_file_off[c] = cur;
            cur += segs_[c].filesz;
        }
        for (const auto& e : extras) {
            // addralign==0 或 1 不需要对齐（避免 (cur + SIZE_MAX) & 0 把 cur 清零）
            if (e.addralign > 1) cur = (cur + (e.addralign - 1)) & ~(e.addralign - 1);
            L.extra_offs.push_back(cur);
            cur += e.data.size();
        }
        L.sh_off = cur;
        return L;
    }

    // 回填动态 section 的 vaddr：在所有 PT_LOAD 段的 vaddr 范围之后分配，
    // 且 vaddr == offset (mod 0x1000)（满足 PT_LOAD 的 p_offset == p_vaddr 对齐约束）。
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

    // ELF header。STATIC_EXE -> ET_EXEC（固定地址）；SHARED_LIB/DYNAMIC_EXE -> ET_DYN（PIE）
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
        // 满足 p_offset == p_vaddr (mod 0x1000) 让 readelf 不报 "not located in any PT_LOAD"。
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

    // 文件 payload：padding 到段数据区 -> 段数据（按段顺序拼接各 section）-> extras
    bool write_payload(FILE* f, const std::vector<SecBuf>& extras, const FileLayout& L) const {
        long pos = ftell(f);
        if ((uint64_t)pos < L.seg_data_off) {
            std::vector<uint8_t> pad(L.seg_data_off - pos, 0);
            if (fwrite(pad.data(), 1, pad.size(), f) != pad.size()) return false;
        }
        // 段数据：按段顺序拼接各 section（section 数据仍在 host pool 的 load 位置）
        for (int c = 0; c < 3; c++) {
            if (!segs_[c].used) continue;
            long now = ftell(f);
            if ((uint64_t)now < L.seg_file_off[c]) {
                std::vector<uint8_t> pad(L.seg_file_off[c] - now, 0);
                if (fwrite(pad.data(), 1, pad.size(), f) != pad.size()) return false;
            }
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

    // section headers: NULL -> .text -> .plt? -> .rodata -> .data -> .got.plt? -> .bss? -> extras
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
                // VM 按 src_reg=2 走 do_softfp）。byte[1] 高 4 位是 src_reg：0x10->0x20。
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
                // 所以 target = call_site + (imm+1)*8 -> imm = (target-call_site)/8 - 1）
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
                     const std::vector<std::string>& archives,
                     bool keep_debug, bool keep_symtab) {
    Linker linker;
    linker.set_archives(archives);
    linker.set_keep_debug(keep_debug);
    linker.set_keep_symtab(keep_symtab);
    if (!linker.run(inputs)) return false;
    return linker.write_elf(out_path);
}

bool link_bpf_shared(const std::vector<std::string>& inputs, const std::string& out_path,
                     const std::string& soname,
                     const std::vector<std::string>& deps, bool keep_debug, bool keep_symtab,
                     const std::string& entry_name) {
    Linker linker(Linker::Mode::SHARED_LIB);
    linker.set_soname(soname);
    linker.set_deps(deps);
    linker.set_entry_name(entry_name);
    linker.set_keep_debug(keep_debug);
    linker.set_keep_symtab(keep_symtab);
    if (!linker.run(inputs)) return false;
    return linker.write_elf(out_path);
}

bool link_bpf_exe(const std::vector<std::string>& inputs, const std::string& out_path,
                  const std::vector<std::string>& deps,
                  const std::string& entry_name, bool keep_debug, bool keep_symtab) {
    Linker linker(Linker::Mode::DYNAMIC_EXE);
    linker.set_deps(deps);
    linker.set_entry_name(entry_name);
    linker.set_keep_debug(keep_debug);
    linker.set_keep_symtab(keep_symtab);
    if (!linker.run(inputs)) return false;
    return linker.write_elf(out_path);
}

bool link_bpf_relocatable(const std::vector<std::string>& inputs, const std::string& out_path,
                          const std::vector<std::string>& archives, bool keep_debug) {
    Linker linker(Linker::Mode::RELOCATABLE);
    linker.set_archives(archives);
    linker.set_keep_debug(keep_debug);
    if (!linker.run(inputs)) return false;
    return linker.write_elf(out_path);
}

