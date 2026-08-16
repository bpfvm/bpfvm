//
// ld_main.cpp — bpfvm-ld: BPF 链接器
//
// 三种模式（对齐标准 ld 默认行为，共用一套链接逻辑）：
//
//   -  默认（动态可执行，PIE ET_DYN + DT_NEEDED）：
//        bpfvm-ld foo.o -l libc.so -o foo.linked
//      跨模块函数调用默认走 PLT/GOT；跨模块数据引用由 .rela.dyn 记录，
//      VM 运行时按实际加载地址 patch。
//
//   -  -static（静态自包含 ET_EXEC，固定地址）：
//        bpfvm-ld -static foo.o -l:libpdclib.a -o foo.linked
//      只搜 .a，构建期全部 patch。
//
//   -  -shared（动态库 .so，PIE ET_DYN）：
//        bpfvm-ld -shared --soname libc.so libpdclib.a -o libc.so
//      p_vaddr=0，可在任意地址加载；VM 加载时按 .rela.dyn 做运行时重定位。
//
// 替代 binutils bpf-ld（Debian bug #1126689 .rodata.str1.1 合并错误在这里不存在）。
//

#include "elf_linker.h"
#include "elf_loader.h"

#include <iostream>
#include <libgen.h>
#include <unistd.h>
#include <getopt.h>
#include <string>
#include <vector>

enum class Mode { STATIC_EXE, DYNAMIC_EXE, SHARED_LIB, RELOCATABLE };

struct Options {
    Mode mode = Mode::DYNAMIC_EXE;  // 默认动态链接（对齐标准 ld）
    bool static_flag = false;       // -static
    bool strip_debug = false;       // --strip-debug：剥掉 DWARF 调试段（默认保留，对齐 ld）
    bool strip_all = false;         // -s/--strip-all：剥掉 DWARF + .symtab/.strtab（对齐 ld -s）
    std::vector<std::string> inputs;  // 输入 .o（可多个，gcc 经 bpf-gcc 链接时传多个）
    std::string output = "a.out";
    std::string soname;
    std::string entry_name = "_start";  // -e/--entry，对齐标准 ld
    std::vector<std::string> libs;      // -l / -l: 列出的依赖名
    std::vector<std::string> lib_dirs;  // -L 搜索路径
};

static void usage(const char* prog) {
    std::cerr << "Usage:\n";
    std::cerr << "  " << prog << " [options] <input>\n";
    std::cerr << "\nModes:\n";
    std::cerr << "  (default)       Dynamic exe (PIE ET_DYN): .o + .so deps -> DT_NEEDED\n";
    std::cerr << "  -static         Static exe (ET_EXEC): .o + .a -> self-contained\n";
    std::cerr << "  -shared         Shared library (.so): archive -> PIE ET_DYN with exports\n";
    std::cerr << "\nOptions:\n";
    std::cerr << "  -o <file>          Output file (default: a.out)\n";
    std::cerr << "  -e <name>          Entry symbol (default: _start)\n";
    std::cerr << "  --soname <name>    DT_SONAME (with -shared)\n";
    std::cerr << "  -l <name>          Dependency: <name>.so (or lib<name>.a with -static)\n";
    std::cerr << "  -l:<file>          Dependency by explicit filename\n";
    std::cerr << "  -L <dir>           Add to library search path\n";
    std::cerr << "  -g                 Keep DWARF debug sections (default)\n";
    std::cerr << "  -S, --strip-debug  Strip debug sections\n";
    std::cerr << "  -s, --strip-all    Strip debug sections and symbol table\n";
}

int main(int argc, char** argv) {
    Options opt;

    // 预处理 argv：把 -Wl,X,Y,Z 按逗号拆开成独立 token（剥离 -Wl, 前缀），
    // 后续解析逻辑只需处理裸 ld 选项（如 -Map、--sort-common）。-Wl, 单独成 token 忽略。
    std::vector<std::string> args;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a.rfind("-Wl,", 0) == 0) {
            std::string body = a.substr(4);
            std::vector<std::string> parts;
            size_t start = 0;
            while (true) {
                size_t comma = body.find(',', start);
                if (comma == std::string::npos) { parts.push_back(body.substr(start)); break; }
                parts.push_back(body.substr(start, comma - start));
                start = comma + 1;
            }
            // 跳过空子项（如 -Wl, 末尾多余逗号）
            for (auto& p : parts) {
                if (!p.empty()) args.push_back(p);
            }
        } else {
            args.push_back(a);
        }
    }

    // 手动扫描展开后的 args，兼容 clang/gcc 风格命令行（让 autoconf 项目的 $(CCLD) 可以直接调用）
    // 已知 bpfvm-ld flags：-o, -e, -l, -l:, -L, -shared, -static, --soname, --entry
    // 已知 clang/gcc 编译 flags（来自 CFLAGS，链接时传入，需忽略）：
    //   -target, -nostdlib, -isystem, -I, -D, -O, -g, -std=, -m*, -f*, -W,
    //   -bpf-stack-size=, -mllvm, ...
    auto ignore_flag = [&](const std::string& a) {
        std::cerr << "[bpfvm-ld] ignoring flag: " << a << "\n";
    };
    auto next_arg = [&](size_t& i, const char* flag) -> const char* {
        if (i + 1 >= args.size()) {
            std::cerr << basename(argv[0]) << ": " << flag << " requires an argument\n";
            return nullptr;
        }
        return args[++i].c_str();
    };

    for (size_t i = 0; i < args.size(); i++) {
        const std::string& a = args[i];

        // --long options
        if (a == "--shared") { opt.mode = Mode::SHARED_LIB; continue; }
        if (a == "--static") { opt.static_flag = true; opt.mode = Mode::STATIC_EXE; continue; }
        // -r / --relocatable：partial link，合并输入 ET_REL/归档为单个 ET_REL（保留重定位、
        // 不解析符号、无 segment/入口）。须在下方 catch-all 单 token 跳过之前识别。
        if (a == "--relocatable" || a == "-r") { opt.mode = Mode::RELOCATABLE; continue; }
        if (a == "--soname") {
            const char* v = next_arg(i, "--soname");
            if (!v) return 1;
            opt.soname = v; continue;
        }
        if (a == "--entry") {
            const char* v = next_arg(i, "--entry");
            if (!v) return 1;
            opt.entry_name = v; continue;
        }
        // 兼容 binutils ld 的单横线长选项
        if (a == "-shared") { opt.mode = Mode::SHARED_LIB; continue; }
        if (a == "-static") { opt.static_flag = true; opt.mode = Mode::STATIC_EXE; continue; }
        if (a == "-soname") {
            const char* v = next_arg(i, "-soname");
            if (!v) return 1;
            opt.soname = v; continue;
        }

        // -e <name> / --entry <name> / -entry <name>（标准 ld 入口符号）
        if (a == "-e") {
            const char* v = next_arg(i, "-e");
            if (!v) return 1;
            opt.entry_name = v; continue;
        }
        // -entry：--entry 的单横线长形式（须在 -e<name> 紧凑形式之前判断，
        // 否则会被吞成 -e + "ntry"）
        if (a == "-entry") {
            const char* v = next_arg(i, "-entry");
            if (!v) return 1;
            opt.entry_name = v; continue;
        }
        if (a.substr(0, 2) == "-e" && a.size() > 2) { opt.entry_name = a.substr(2); continue; }

        // -o<file> / -o <file>
        if (a == "-o") {
            const char* v = next_arg(i, "-o");
            if (!v) return 1;
            opt.output = v; continue;
        }
        if (a.substr(0, 2) == "-o" && a.size() > 2) { opt.output = a.substr(2); continue; }

        // -L<dir> / -L <dir>
        if (a == "-L") {
            const char* v = next_arg(i, "-L");
            if (!v) return 1;
            opt.lib_dirs.push_back(v); continue;
        }
        if (a.substr(0, 2) == "-L" && a.size() > 2) { opt.lib_dirs.push_back(a.substr(2)); continue; }

        // -l<name> / -l <name> / -l:<file>
        // -static 模式只搜 lib<name>.a；否则搜 <name>.so（搜不到再搜 lib<name>.a，对齐标准 ld）
        if (a == "-l") {
            const char* v = next_arg(i, "-l");
            if (!v) return 1;
            opt.libs.push_back(v); continue;
        }
        if (a.substr(0, 3) == "-l:" && a.size() > 3) { opt.libs.push_back(a.substr(3)); continue; }
        if (a.substr(0, 2) == "-l" && a.size() > 2) { opt.libs.push_back(a.substr(2)); continue; }

        // 调试信息开关（对齐标准 ld 语义）：
        //   -g              保留 DWARF 调试段（已是默认，显式接受为 no-op）
        //   --strip-debug   仅剥 .debug_*（-S 等价）
        //   -s / --strip-all  剥 .debug_* + .symtab/.strtab（标准 ld -s 同时剥符号表）
        //   注：仅 STATIC_EXE 当前支持输出调试段；PIE 模式传这些开关也无副作用。
        if (a == "-g" || a.rfind("-g", 0) == 0) continue;  // -g / -g2 / -gdwarf-4 等：默认就保留
        if (a == "--strip-debug" || a == "-S") {
            opt.strip_debug = true; continue;
        }
        if (a == "-s" || a == "--strip-all") {
            opt.strip_debug = true; opt.strip_all = true; continue;
        }

        // 跳过带参数的 flags：clang/gcc 编译 flags + gcc 当 ld 驱动时传的 ld flags。
        // ld 驱动类都带一个参数：-plugin <so>（LTO）、-rpath/-rpath-link <dir>、-T <script>。
        // 必须连参数一起跳过，否则参数（如 plugin 的 .so 路径）会被当成输入文件。
        if (a == "-target" || a == "-isystem" || a == "-I" || a == "-D" || a == "-include" ||
            a == "-mllvm" || a == "-Xclang" || a == "-add-plugin" || a == "-plugin-arg" ||
            a == "-x" ||
            a == "-plugin" || a == "-rpath" || a == "-rpath-link" || a == "-T" ||
            // 标准 ld 带参数选项（bpfvm-ld 不实现其语义，但须吞掉参数避免被当输入文件）
            a == "-Map" || a == "-Script" || a == "-version-script" ||
            a == "-dynamic-linker" || a == "-default-symver" ||
            a == "-wrap" || a == "-defsym" || a == "-exclude-libs" ||
            a == "-y" || a == "-m" || a == "-z" || a == "-O") {
            if (i + 1 < args.size()) { ignore_flag(a + " " + args[i + 1]); i++; }
            else ignore_flag(a);
            continue;
        }

        // 跳过 clang/gcc 单 token flags
        if (a.substr(0, 1) == "-" && a.size() > 1) {
            ignore_flag(a);
            continue;
        }

        // 剩下的是位置参数：.o/.a/.so 都直接作为链接输入（可多个）；只有 -l/-l: 才走库搜索。
        // （标准 ld 语义：位置参数=直接链接，-l=搜索库。gcc 经 bpf-gcc 链接时传多个 .o/.a。）
        if (a.ends_with(".c") || a.ends_with(".cc") || a.ends_with(".cpp")) {
            std::cerr << basename(argv[0]) << ": source file '" << a
                      << "' - bpfvm-ld only links, use clang to compile first\n";
            return 1;
        }
        opt.inputs.push_back(a);
    }

    if (const char* lp = getenv("LD_LIBRARY_PATH")) {
        auto dirs = lib_search_dirs_from_envp({{"LD_LIBRARY_PATH", lp}});
        opt.lib_dirs.insert(opt.lib_dirs.end(), dirs.begin(), dirs.end());
    }

    if (opt.inputs.empty()) {
        std::cerr << basename(argv[0]) << ": missing input file\n";
        usage(argv[0]);
        return 1;
    }

    // 去重 -l 列表（保留顺序）
    {
        std::vector<std::string> unique;
        for (const auto& l : opt.libs) {
            bool seen = false;
            for (const auto& u : unique) if (u == l) { seen = true; break; }
            if (!seen) unique.push_back(l);
        }
        opt.libs = std::move(unique);
    }

    // 解析 -l：-static 只搜 lib<name>.a；否则 <name>.so 优先，搜不到搜 lib<name>.a
    // -l:<file> 原样作为文件名搜索
    std::vector<std::string> resolved_libs;
    for (const auto& l : opt.libs) {
        std::vector<std::string> candidates;
        auto ends_with = [](const std::string& s, const std::string& suf) {
            return s.size() >= suf.size() && s.substr(s.size() - suf.size()) == suf;
        };
        if (l.size() > 0 && l[0] == ':') {
            // -l:<file>：去掉前导 ':'
            candidates.push_back(l.substr(1));
        } else if (ends_with(l, ".a") || ends_with(l, ".so")) {
            // 命令行直接传文件名（如 testgot_lib.a）：当文件路径搜索，不加 lib 前缀
            candidates.push_back(l);
        } else if (opt.static_flag || opt.mode == Mode::RELOCATABLE) {
            // -static 与 -r 都只搜 lib<name>.a：partial link 不接受共享库输入（标准 ld 同此）
            candidates.push_back("lib" + l + ".a");
        } else {
            // 对齐标准 ld：-l <name> 搜 lib<name>.so，找不到再搜 lib<name>.a。
            candidates.push_back("lib" + l + ".so");
            candidates.push_back("lib" + l + ".a");
        }
        std::string found;
        for (const auto& cand : candidates) {
            found = find_library(opt.lib_dirs, cand);
            if (!found.empty()) break;
        }
        if (found.empty()) {
            std::cerr << basename(argv[0]) << ": cannot find library " << l << "\n";
            return 1;
        }
        resolved_libs.push_back(found);
    }

    bool ok = false;
    const bool keep_debug = !opt.strip_debug;
    const bool keep_symtab = !opt.strip_all;
    if (opt.mode == Mode::STATIC_EXE) {
        ok = link_bpf_object(opt.inputs, opt.output, resolved_libs, keep_debug, keep_symtab);
    } else if (opt.mode == Mode::RELOCATABLE) {
        // partial link：合并输入 .o/.a 为单个 ET_REL（保留重定位，不解析符号）
        ok = link_bpf_relocatable(opt.inputs, opt.output, resolved_libs, keep_debug);
    } else if (opt.mode == Mode::DYNAMIC_EXE) {
        ok = link_bpf_exe(opt.inputs, opt.output, resolved_libs, opt.entry_name, keep_debug, keep_symtab);
    } else if (opt.mode == Mode::SHARED_LIB) {
        std::string soname = opt.soname;
        if (soname.empty()) {
            size_t slash = opt.output.find_last_of('/');
            std::string base = (slash == std::string::npos) ? opt.output : opt.output.substr(slash + 1);
            soname = base;
        }
        ok = link_bpf_shared(opt.inputs, opt.output, soname, resolved_libs, keep_debug, keep_symtab, opt.entry_name);
    }

    if (!ok) {
        std::cerr << basename(argv[0]) << ": link failed\n";
        return 1;
    }
    return 0;
}
