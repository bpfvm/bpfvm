//
// elf_linker.h — BPF 链接器（bpfvm-ld 专用）
//
// 把 .o + 依赖 archive/.so 合并/链接成可被 VM 直接加载的产物。
//
// 提供 3 套对外接口，共用同一套链接逻辑（Linker 类），对齐标准 ld 默认行为：
//
//   1. 静态链接（-static，自包含 ET_EXEC，固定地址）：
//        link_bpf_object("foo.o", "foo.linked", {"libpdclib.a"})
//      产物完全自包含，VM 加载时不需任何额外文件。
//
//   2. 构建动态库（-shared，标准 ELF .so，PIE）：
//        link_bpf_shared("libfoo.a", "libfoo.so", "libfoo.so")
//      产出 ET_DYN + PT_DYNAMIC/.dynsym/.dynstr/.hash/.rela.dyn，DT_SONAME 声明自身名。
//      p_vaddr=0，可在任意地址加载；VM 加载时按 .rela.dyn 做运行时重定位。
//
//   3. 构建动态可执行（默认模式，PIE ET_DYN + DT_NEEDED）：
//        link_bpf_exe("foo.o", "foo.linked", {"libc.so", ...}, "_start")
//      产出 ET_DYN + PT_DYNAMIC + DT_NEEDED（依赖的 soname 列表）。
//      跨模块函数调用默认走 PLT/GOT（标准 ld 行为）；跨模块数据引用由 .rela.dyn 记录，
//      VM 加载时按实际加载地址 patch。p_vaddr=0，可在任意地址加载。
//

#ifndef ELF_LINKER_H
#define ELF_LINKER_H

#include <cstdint>
#include <string>
#include <vector>

// 静态链接（-static）：把 .o + archives 合并成自包含 ET_EXEC（固定地址）。
// inputs 是所有输入 .o；archives 由 ld_main 的 -L/-l 解析为完整路径传入。失败返回 false。
bool link_bpf_object(const std::vector<std::string>& inputs, const std::string& out_path,
                     const std::vector<std::string>& archives);

// 构建动态库（-shared，标准 ELF .so，PIE）：把 archive 内部所有 .o 合并成 .so。
// 产出 ET_DYN + PT_DYNAMIC/.dynsym/.dynstr/.hash/.rela.dyn，DT_SONAME 声明名。
// deps 提供本 .so 依赖的 .so 路径列表，生成 DT_NEEDED；空表示无依赖。
// p_vaddr=0，可在任意地址加载；VM 加载时按 .rela.dyn 做运行时重定位。
// 失败返回 false。
bool link_bpf_shared(const std::vector<std::string>& inputs, const std::string& out_path,
                     const std::string& soname,
                     const std::vector<std::string>& deps = {});

// 构建动态可执行（默认模式，PIE ET_DYN + DT_NEEDED）：
// - 输入主程序 .o（可多个）+ 依赖 .so 列表
// - 跨模块函数调用默认走 PLT/GOT；跨模块数据引用由 .rela.dyn 记录，VM 运行时 patch
// - 输出 ET_DYN + PT_DYNAMIC + DT_NEEDED（依赖 soname 列表）
// - VM 运行时按 DT_NEEDED 找 .so，分配加载地址，按 .rela.dyn/.rela.plt 重定位
// entry_name 默认 "_start"（对齐标准 ld）。失败返回 false。
bool link_bpf_exe(const std::vector<std::string>& inputs, const std::string& out_path,
                  const std::vector<std::string>& deps,
                  const std::string& entry_name = "_start");

#endif // ELF_LINKER_H
