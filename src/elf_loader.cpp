//
// elf_loader.cpp — BPF ELF 加载与库搜索公共逻辑（ld_main 和 VM 共用）
//

#include "elf_loader.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <iostream>
#include <optional>
#include <set>
#include <sstream>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>

#include <libelf.h>
#include <gelf.h>

// ===== memmap =====

memmap memmap::static_map(void* addr, size_t size, uint64_t paddr) {
    memmap map;
    map.size = size;
    map.set_data((unsigned char*)addr, size, false);
    map.paddr = paddr;
    map.flags = PF_R;
    return map;
}


// ===== 库搜索 =====
static std::vector<std::string> default_lib_search_dirs() {
    std::vector<std::string> dirs;
    if (const char* env = getenv("BPF_LIB_PATH")) {
        std::stringstream ss(env);
        std::string d;
        while (std::getline(ss, d, ':')) {
            if (!d.empty()) dirs.push_back(d);
        }
    }
    dirs.push_back("libc/lib64");
    dirs.push_back("libc/lib");
    dirs.push_back("lib");
    dirs.push_back(".");
    return dirs;
}

std::string find_library(const std::vector<std::string>& extra_dirs, const std::string& name) {
    for (const auto& d : extra_dirs) {
        std::string p = d + "/" + name;
        if (access(p.c_str(), R_OK) == 0) return p;
    }
    for (const auto& d : default_lib_search_dirs()) {
        std::string p = d + "/" + name;
        if (access(p.c_str(), R_OK) == 0) return p;
    }
    if (access(name.c_str(), R_OK) == 0) return name;
    return "";
}

// ===== ELF 加载 =====

namespace {

// 单个 PLT 桩的字节大小（与 elf_linker.cpp 的 emit_plt_stub 输出一致）
constexpr size_t kPltStubSize = 40;

// 读取 ELF 的 .dynamic section，提取指定 tag 的值（首个匹配）。
uint64_t read_dyn_tag(Elf_Scn* dynamic_scn, int64_t tag) {
    if (!dynamic_scn) return 0;
    Elf_Data* dd = elf_getdata(dynamic_scn, nullptr);
    if (!dd) return 0;
    size_t ndyn = dd->d_size / sizeof(Elf64_Dyn);
    for (size_t i = 0; i < ndyn; i++) {
        Elf64_Dyn dyn;
        memcpy(&dyn, (const uint8_t*)dd->d_buf + i * sizeof(Elf64_Dyn), sizeof(dyn));
        if (dyn.d_tag == tag) return dyn.d_un.d_val;
        if (dyn.d_tag == DT_NULL) break;
    }
    return 0;
}

// 读取 .dynamic 里所有 DT_NEEDED soname（依赖的 .so 列表）。
std::vector<std::string> read_needed(Elf_Scn* dynamic_scn, Elf_Scn* dynstr_scn) {
    std::vector<std::string> needed;
    if (!dynamic_scn || !dynstr_scn) return needed;
    Elf_Data* dd = elf_getdata(dynamic_scn, nullptr);
    Elf_Data* ds = elf_getdata(dynstr_scn, nullptr);
    if (!dd || !ds) return needed;
    size_t ndyn = dd->d_size / sizeof(Elf64_Dyn);
    for (size_t i = 0; i < ndyn; i++) {
        Elf64_Dyn dyn;
        memcpy(&dyn, (const uint8_t*)dd->d_buf + i * sizeof(Elf64_Dyn), sizeof(dyn));
        if (dyn.d_tag == DT_NULL) break;
        if (dyn.d_tag == DT_NEEDED && dyn.d_un.d_val < ds->d_size) {
            needed.emplace_back((const char*)ds->d_buf + dyn.d_un.d_val);
        }
    }
    return needed;
}

// 定位 ELF 的 .dynamic / .dynstr / .dynsym / .plt section。
struct DynSections {
    Elf_Scn* dynamic = nullptr;
    Elf_Scn* dynstr = nullptr;
    Elf_Scn* dynsym = nullptr;
    Elf_Scn* plt = nullptr;        // .plt section（运行时 patch PLT 桩 lddw 用）
    size_t dynsym_link = 0;  // .dynsym 的 sh_link（.dynstr 的 section index）
};

DynSections find_dyn_sections(Elf* elf) {
    DynSections r;
    size_t shstrndx = 0;
    elf_getshdrstrndx(elf, &shstrndx);
    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        gelf_getshdr(scn, &shdr);
        char* nm = elf_strptr(elf, shstrndx, shdr.sh_name);
        std::string name(nm ? nm : "");
        if (shdr.sh_type == SHT_DYNAMIC) r.dynamic = scn;
        else if (shdr.sh_type == SHT_STRTAB && name == ".dynstr") r.dynstr = scn;
        else if (shdr.sh_type == SHT_DYNSYM) { r.dynsym = scn; r.dynsym_link = shdr.sh_link; }
        else if (shdr.sh_type == SHT_PROGBITS && name == ".plt") r.plt = scn;
    }
    return r;
}

class Defer {
public:
    Defer(std::function<void()> f) : func(f) {}
    ~Defer() { func(); }
private:
    std::function<void()> func;
};

// 一个打开的 ELF 模块（主程序或 .so 依赖）
struct ElfFile { std::string path; Elf* elf; int fd; };

// 待加载的 PT_LOAD 段（按文件索引 + 实际 vaddr）
struct Seg {
    size_t file_idx;
    uint64_t vaddr;
    uint64_t memsz;
    uint64_t offset;
    uint64_t filesz;
    uint32_t flags;
};

// 段映射后的 host/guest 信息（供 host_of 查询）
struct MapInfo { unsigned char* host; uint64_t paddr; size_t size; };

bool validate_ehdr(const GElf_Ehdr& eh, const char* path) {
    if (eh.e_type == ET_REL) {
        std::cerr << "bpfvm: ET_REL not supported; link with bpfvm-ld first: " << path << std::endl;
        return false;
    }
    if (eh.e_type != ET_EXEC && eh.e_type != ET_DYN) {
        std::cerr << "Not an executable ELF file: " << path << " type: " << eh.e_type << std::endl;
        return false;
    }
    if (eh.e_machine != EM_BPF) {
        std::cerr << "Not a bpf ELF file: " << path << " machine: " << eh.e_machine << std::endl;
        return false;
    }
    return true;
}

// BFS 递归收集所有 DT_NEEDED 依赖；按 soname 去重避免循环依赖或重复加载
// （重定位会重复 patch 导致符号地址错乱）。
bool collect_dependencies(std::vector<ElfFile>& elves,
                         std::vector<std::pair<Elf*, int>>& opened) {
    std::set<std::string> loaded_sonames;
    for (size_t i = 0; i < elves.size(); i++) {
        DynSections ds = find_dyn_sections(elves[i].elf);
        for (const auto& soname : read_needed(ds.dynamic, ds.dynstr)) {
            if (!loaded_sonames.insert(soname).second) continue;
            std::string found = find_library({}, soname);
            if (found.empty()) {
                std::cerr << "[load_elf] cannot find library: " << soname
                          << " (set BPF_LIB_PATH)" << std::endl;
                return false;
            }
            int efd = open(found.c_str(), O_RDONLY);
            if (efd < 0) {
                std::cerr << "[load_elf] cannot open: " << found << std::endl;
                return false;
            }
            Elf* e = elf_begin(efd, ELF_C_READ, nullptr);
            if (!e) { close(efd); return false; }
            elves.push_back({found, e, efd});
            opened.emplace_back(e, efd);
        }
    }
    return true;
}

// 扫描一个模块的所有 PT_LOAD 段，分配加载基址并填充 segs。
//   ET_DYN（PIE/.so）：先扫所有 PT_LOAD 算模块跨度，从 next_alloc 整块分配，
//                     保持模块内相对布局。
//   ET_EXEC：p_vaddr 是绝对地址，st_value 也是绝对地址，base=0
void layout_module(Elf* elf, size_t fi, bool is_dyn,
                  uint64_t& next_alloc, uint64_t& base_out,
                  std::vector<Seg>& segs) {
    GElf_Ehdr eh;
    if (gelf_getehdr(elf, &eh) != &eh) return;

    if (is_dyn) {
        uint64_t min_v = UINT64_MAX, max_end = 0;
        for (size_t i = 0; i < eh.e_phnum; i++) {
            GElf_Phdr ph;
            if (gelf_getphdr(elf, i, &ph) != &ph) continue;
            if (ph.p_type != PT_LOAD) continue;
            if (ph.p_vaddr < min_v) min_v = ph.p_vaddr;
            if (ph.p_vaddr + ph.p_memsz > max_end) max_end = ph.p_vaddr + ph.p_memsz;
        }
        uint64_t mod_base = next_alloc - min_v;  // 实际地址 = mod_base + p_vaddr
        uint64_t mod_span = max_end - min_v;
        next_alloc = (next_alloc + mod_span + 0xFFF) & ~0xFFFULL;
        base_out = mod_base + min_v;  // 首个段实际 vaddr
        for (size_t i = 0; i < eh.e_phnum; i++) {
            GElf_Phdr ph;
            if (gelf_getphdr(elf, i, &ph) != &ph) continue;
            if (ph.p_type != PT_LOAD) continue;
            segs.push_back({fi, mod_base + ph.p_vaddr, ph.p_memsz, ph.p_offset, ph.p_filesz, ph.p_flags});
        }
    } else {
        // ET_EXEC：段 vaddr 已是绝对地址（bpfvm-ld 写死 guest_base_ 起），直接按 phdr 映射。
        // 首段覆盖 ELF header + phdr table 的扩展由 bpfvm-ld 在产物里完成（PT_PHDR 配套），
        // loader 不再需要特例处理。
        base_out = 0;
        for (size_t i = 0; i < eh.e_phnum; i++) {
            GElf_Phdr ph;
            if (gelf_getphdr(elf, i, &ph) != &ph) continue;
            if (ph.p_type != PT_LOAD) continue;
            segs.push_back({fi, ph.p_vaddr, ph.p_memsz, ph.p_offset, ph.p_filesz, ph.p_flags});
        }
    }
}

bool check_overlaps(const std::vector<Seg>& segs, const std::vector<ElfFile>& elves) {
    for (size_t i = 0; i < segs.size(); i++) {
        for (size_t j = i + 1; j < segs.size(); j++) {
            uint64_t a0 = segs[i].vaddr, a1 = a0 + segs[i].memsz;
            uint64_t b0 = segs[j].vaddr, b1 = b0 + segs[j].memsz;
            if (a0 < b1 && b0 < a1) {
                std::cerr << "[load_elf] overlapping PT_LOAD: "
                          << elves[segs[i].file_idx].path << " @0x" << std::hex << a0 << "-0x" << a1
                          << " vs " << elves[segs[j].file_idx].path << " @0x" << b0 << "-0x" << b1
                          << std::dec << std::endl;
                return false;
            }
        }
    }
    return true;
}

// mmap + pread 单个段；先 RW 映射以便 pread + 后续重定位 patch，
// 重定位完成后再 mprotect 降权（只读/可执行段不可写）。
bool map_segment(const Seg& s, const ElfFile& ef,
                memmap& m_out, MapInfo& mi_out) {
    void* host = mmap(nullptr, s.memsz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (host == MAP_FAILED) {
        std::cerr << "[load_elf] mmap failed for " << ef.path
                  << " @0x" << std::hex << s.vaddr << std::dec
                  << ": " << strerror(errno) << std::endl;
        return false;
    }
    if (s.filesz > 0) {
        ssize_t n = pread(ef.fd, host, s.filesz, s.offset);
        if (n < 0 || (uint64_t)n != s.filesz) {
            std::cerr << "[load_elf] short/failed pread of " << ef.path << ": "
                      << n << "/" << s.filesz << std::endl;
            munmap(host, s.memsz);
            return false;
        }
    }
    m_out.paddr = s.vaddr;
    m_out.size = s.memsz;
    m_out.flags = s.flags;
    m_out.set_data((unsigned char*)host, s.memsz, /*own=*/true);
    mi_out = {(unsigned char*)host, s.vaddr, s.memsz};
    return true;
}

// 收集所有模块的导出符号 → 实际地址。
//   PIE: 实际地址 = 模块加载基址 + st_value；ET_EXEC: st_value 已是绝对地址，base=0
//   首个定义优先（避免被后续弱符号覆盖）
void collect_exports(const std::vector<ElfFile>& elves,
                    const std::vector<uint64_t>& load_base,
                    std::unordered_map<std::string, uint64_t>& exports) {
    for (size_t fi = 0; fi < elves.size(); fi++) {
        DynSections ds = find_dyn_sections(elves[fi].elf);
        if (!ds.dynsym) continue;
        Elf_Data* d = elf_getdata(ds.dynsym, nullptr);
        if (!d) continue;
        size_t n = d->d_size / sizeof(GElf_Sym);
        for (size_t i = 0; i < n; i++) {
            GElf_Sym sym; gelf_getsym(d, i, &sym);
            int binding = GELF_ST_BIND(sym.st_info);
            int type = GELF_ST_TYPE(sym.st_info);
            if (binding != STB_GLOBAL && binding != STB_WEAK) continue;
            if (type != STT_FUNC && type != STT_OBJECT) continue;
            if (sym.st_shndx == SHN_UNDEF) continue;  // 导入符号，不是导出
            char* nm = elf_strptr(elves[fi].elf, ds.dynsym_link, sym.st_name);
            if (!nm || !*nm) continue;
            uint64_t addr = load_base[fi] + sym.st_value;
            if (exports.find(nm) == exports.end()) exports[nm] = addr;
        }
    }
}

// 单个模块的重定位上下文：预读 .dynsym 名字表，封装符号解析。
class RelocState {
public:
    RelocState(const ElfFile& ef, uint64_t base,
              const std::unordered_map<std::string, uint64_t>& exports)
        : ef_(ef), base_(base), exports_(exports) {
        DynSections ds = find_dyn_sections(ef_.elf);
        if (!ds.dynsym) return;
        Elf_Data* d = elf_getdata(ds.dynsym, nullptr);
        if (!d) return;
        size_t n = d->d_size / sizeof(GElf_Sym);
        dynsym_names_.reserve(n);
        for (size_t i = 0; i < n; i++) {
            GElf_Sym sym; gelf_getsym(d, i, &sym);
            char* nm = elf_strptr(ef_.elf, ds.dynsym_link, sym.st_name);
            dynsym_names_.emplace_back(nm ? nm : "");
        }
    }

    // si=0（NULL 符号）→ 本模块加载基址（本模块符号重定位用，addend 已含相对偏移）
    // 其他 → 按名查 exports；未找到返回 nullopt
    std::optional<uint64_t> resolve(size_t si) const {
        if (si == 0) return base_;
        if (si >= dynsym_names_.size()) return std::nullopt;
        const std::string& nm = dynsym_names_[si];
        if (nm.empty()) return std::nullopt;
        auto it = exports_.find(nm);
        return it != exports_.end() ? std::optional<uint64_t>(it->second) : std::nullopt;
    }

    const std::string& sym_name(size_t si) const {
        static const std::string empty;
        return (si > 0 && si < dynsym_names_.size()) ? dynsym_names_[si] : empty;
    }

    const std::string& path() const { return ef_.path; }
    uint64_t base() const { return base_; }

private:
    const ElfFile& ef_;
    uint64_t base_;
    const std::unordered_map<std::string, uint64_t>& exports_;
    std::vector<std::string> dynsym_names_;
};

// 应用 .rela.dyn（DT_RELA/DT_RELASZ）：
//   R_BPF_64_64 (lddw, type 1) / R_BPF_64_ABS64 (数据指针, type 2) / R_BPF_64_NODYLD32 (32 位, type 4)
// PIE 模块：DT_RELA / r_offset 都是相对模块基址的偏移，查 host 前要加 base
void process_rela_dyn(const RelocState& rs, const DynSections& ds,
                     const std::function<unsigned char*(uint64_t)>& host_of, bool debug) {
    uint64_t rela_vaddr = read_dyn_tag(ds.dynamic, DT_RELA);
    uint64_t relasz = read_dyn_tag(ds.dynamic, DT_RELASZ);
    if (!rela_vaddr || !relasz) return;
    unsigned char* rela_host = host_of(rs.base() + rela_vaddr);
    if (!rela_host) return;
    size_t n = relasz / sizeof(Elf64_Rela);
    for (size_t i = 0; i < n; i++) {
        Elf64_Rela rela;
        memcpy(&rela, rela_host + i * sizeof(Elf64_Rela), sizeof(rela));
        unsigned char* patch = host_of(rs.base() + rela.r_offset);
        if (!patch) continue;
        int rtype = GELF_R_TYPE(rela.r_info);
        size_t si = GELF_R_SYM(rela.r_info);
        auto S_opt = rs.resolve(si);
        if (!S_opt) {
            std::cerr << "[load_elf] warning: unresolved symbol '" << rs.sym_name(si)
                      << "' in " << rs.path()
                      << " (.rela.dyn type " << rtype << ")\n";
            continue;  // 留原值（0），不写
        }
        uint64_t V = *S_opt + rela.r_addend;
        if (rtype == 1) {  // R_BPF_64_64 (lddw)：写两个 imm 字段
            uint32_t lo = (uint32_t)V;
            uint32_t hi = (uint32_t)(V >> 32);
            memcpy(patch + 4, &lo, 4);
            memcpy(patch + 12, &hi, 4);
        } else if (rtype == 2) {  // R_BPF_64_ABS64：写 8 字节
            memcpy(patch, &V, 8);
        } else if (rtype == 4) {  // R_BPF_64_NODYLD32：写 4 字节
            uint32_t v = (uint32_t)V;
            memcpy(patch, &v, 4);
        }
        if (debug)
            std::cerr << "[load_elf] .rela.dyn @" << rs.path()
                      << " off=0x" << std::hex << rela.r_offset << " type=" << rtype
                      << " V=0x" << V << std::dec << "\n";
    }
}

// 应用 .rela.plt（DT_JMPREL/DT_PLTRELSZ）：把函数地址写进 .got.plt 槽，
// 并 patch 对应 PLT 桩的 lddw imm = 槽实际地址（PIE 运行期重定位）。
// PLT 桩布局：lddw r6, <slot>（16 字节，imm 在 byte 4-7/12-15）；
// 每桩 kPltStubSize 字节，按 .plt sh_addr 顺序排列。
void process_rela_plt(const RelocState& rs, const DynSections& ds,
                     const std::function<unsigned char*(uint64_t)>& host_of, bool debug) {
    uint64_t jmprel_vaddr = read_dyn_tag(ds.dynamic, DT_JMPREL);
    uint64_t pltrelsz = read_dyn_tag(ds.dynamic, DT_PLTRELSZ);
    if (!jmprel_vaddr || !pltrelsz) return;

    uint64_t plt_shaddr = 0;
    if (ds.plt) {
        GElf_Shdr plt_shdr;
        if (gelf_getshdr(ds.plt, &plt_shdr) == &plt_shdr) plt_shaddr = plt_shdr.sh_addr;
    }

    unsigned char* rela_host = host_of(rs.base() + jmprel_vaddr);
    if (!rela_host) return;
    size_t n = pltrelsz / sizeof(Elf64_Rela);
    for (size_t i = 0; i < n; i++) {
        Elf64_Rela rela;
        memcpy(&rela, rela_host + i * sizeof(Elf64_Rela), sizeof(rela));
        unsigned char* got_host = host_of(rs.base() + rela.r_offset);
        if (!got_host) continue;
        size_t si = GELF_R_SYM(rela.r_info);
        auto S_opt = rs.resolve(si);
        if (!S_opt) {
            std::cerr << "[load_elf] warning: unresolved PLT symbol '"
                      << rs.sym_name(si) << "' in " << rs.path() << "\n";
            continue;  // 不写 GOT 槽，保留 0
        }
        uint64_t S = *S_opt;
        memcpy(got_host, &S, 8);
        if (plt_shaddr) {
            unsigned char* plt_stub = host_of(rs.base() + plt_shaddr + i * kPltStubSize);
            if (plt_stub) {
                uint64_t slot_addr = rs.base() + rela.r_offset;
                uint32_t lo = (uint32_t)slot_addr;
                uint32_t hi = (uint32_t)(slot_addr >> 32);
                memcpy(plt_stub + 4, &lo, 4);
                memcpy(plt_stub + 12, &hi, 4);
            }
        }
        if (debug)
            std::cerr << "[load_elf] GOT slot @0x" << std::hex << rela.r_offset
                      << " <- 0x" << S << std::dec
                      << " (" << rs.sym_name(si) << ")\n";
    }
}

}  // namespace

ElfLoadInfo load_elf(const char* path, std::function<void(memmap&&)> add) {
    // 加载 ET_EXEC（静态，固定地址）或 ET_DYN（PIE 主程序 / .so，运行时分配地址）。
    // 运行时处理 .rela.dyn（数据/lddw 重定位）和 .rela.plt（GOT 槽）。
    if (elf_version(EV_CURRENT) == EV_NONE) {
        std::cerr << "Failed to initialize libelf: " << elf_errmsg(-1) << std::endl;
        return ElfLoadInfo{};
    }

    int main_fd = open(path, O_RDONLY);
    if (main_fd < 0) {
        std::cerr << "Failed to open: " << path << ": " << strerror(errno) << std::endl;
        return ElfLoadInfo{};
    }
    Elf* main_elf = elf_begin(main_fd, ELF_C_READ, nullptr);
    if (!main_elf) {
        std::cerr << "Failed to open ELF file: " << elf_errmsg(-1) << std::endl;
        close(main_fd);
        return ElfLoadInfo{};
    }
    std::vector<std::pair<Elf*, int>> opened = {{main_elf, main_fd}};
    Defer defer_close([&]() {
        for (auto& [e, fd] : opened) { if (e) elf_end(e); if (fd >= 0) close(fd); }
    });

    if (elf_kind(main_elf) != ELF_K_ELF) {
        std::cerr << "Not an ELF file: " << path << std::endl;
        return ElfLoadInfo{};
    }
    GElf_Ehdr ehdr;
    if (gelf_getehdr(main_elf, &ehdr) != &ehdr) {
        std::cerr << "Failed to get ELF header: " << elf_errmsg(-1) << std::endl;
        return ElfLoadInfo{};
    }
    if (!validate_ehdr(ehdr, path)) return ElfLoadInfo{};

    // 收集主程序 + 递归所有 DT_NEEDED 依赖（BFS，按 soname 去重）
    std::vector<ElfFile> elves;
    elves.push_back({path, main_elf, main_fd});
    if (!collect_dependencies(elves, opened)) return ElfLoadInfo{};

    // 地址分配 + 段布局
    uint64_t next_alloc = 0x40000000ULL;
    std::vector<uint64_t> load_base(elves.size(), 0);
    std::vector<Seg> segs;
    for (size_t fi = 0; fi < elves.size(); fi++) {
        GElf_Ehdr eh;
        if (gelf_getehdr(elves[fi].elf, &eh) != &eh) continue;
        layout_module(elves[fi].elf, fi, eh.e_type == ET_DYN, next_alloc, load_base[fi], segs);
    }
    if (segs.empty()) {
        std::cerr << "[load_elf] no PT_LOAD segments in " << path << std::endl;
        return ElfLoadInfo{};
    }
    if (!check_overlaps(segs, elves)) return ElfLoadInfo{};

    // mmap 每段；记录 {host, guest vaddr, size} 供后续重定位 vaddr→host 查询
    std::vector<MapInfo> seg_maps;
    auto host_of = [&](uint64_t vaddr) -> unsigned char* {
        for (const auto& mi : seg_maps)
            if (vaddr >= mi.paddr && vaddr < mi.paddr + mi.size) return mi.host + (vaddr - mi.paddr);
        return nullptr;
    };
    for (const auto& s : segs) {
        memmap m;
        MapInfo mi;
        if (!map_segment(s, elves[s.file_idx], m, mi)) return ElfLoadInfo{};
        seg_maps.push_back(mi);
        add(std::move(m));
    }

    // 运行时重定位：先收集所有模块导出符号，再处理每个模块的 .rela.dyn / .rela.plt
    std::unordered_map<std::string, uint64_t> exports;
    collect_exports(elves, load_base, exports);
    const bool debug = getenv("BPF_DEBUG") != nullptr;
    for (size_t fi = 0; fi < elves.size(); fi++) {
        DynSections ds = find_dyn_sections(elves[fi].elf);
        if (!ds.dynamic) continue;
        RelocState rs(elves[fi], load_base[fi], exports);
        process_rela_dyn(rs, ds, host_of, debug);
        process_rela_plt(rs, ds, host_of, debug);
    }

    // 重定位完成后，对只读/可执行段 mprotect 降权（W^X）
    for (size_t i = 0; i < segs.size(); i++) {
        int prot = 0;
        if (segs[i].flags & PF_R) prot |= PROT_READ;
        if (segs[i].flags & PF_W) prot |= PROT_WRITE;
        if (segs[i].flags & PF_X) prot |= PROT_EXEC;
        if (prot == (PROT_READ | PROT_WRITE)) continue;  // 可写段保持
        if (prot == 0) continue;
        mprotect(seg_maps[i].host, segs[i].memsz, prot);
    }

    // 入口地址：ET_DYN（PIE）→ 主程序加载基址 + e_entry；ET_EXEC → e_entry（绝对）
    const uint64_t entry = (ehdr.e_type == ET_DYN) ? (load_base[0] + ehdr.e_entry) : ehdr.e_entry;

    // program header table 的运行时地址（供 auxv AT_PHDR，musl __init_tls 用）：
    // 直接读 PT_PHDR 段。bpfvm-ld 对所有可执行文件（ET_EXEC + PIE）都生成 PT_PHDR，
    // 其 p_vaddr 是 phdr 表的绝对/相对地址，loader 加上加载基址即得运行时地址。
    // ET_EXEC：p_vaddr 已是绝对地址，load_base[0]=0；PIE：p_vaddr 是模块内偏移，加 load_base[0]。
    uint64_t phdr_addr = 0;
    for (size_t i = 0; i < ehdr.e_phnum && phdr_addr == 0; i++) {
        GElf_Phdr ph;
        if (gelf_getphdr(main_elf, i, &ph) != &ph) break;
        if (ph.p_type == PT_PHDR) {
            phdr_addr = load_base[0] + ph.p_vaddr;
        }
    }

    return ElfLoadInfo{entry, phdr_addr, ehdr.e_phentsize, ehdr.e_phnum};
}
