# bpfvm.bpf 子项目（BPF-on-BPF 自举）。
#
# 由顶层 ExternalProject_Add 通过 -DCMAKE_TOOLCHAIN_FILE=cmake/bpfvm-bpf-toolchain.cmake
# 调用。toolchain 负责 BPF 编译/链接配置（compiler/linker/flags/pass plugins 全部在那里）；
# 本文件只定义 target，纯标准 CMake 语法。
#
# BPFVM_ROOT 由顶层注入（= 主项目的 ${CMAKE_SOURCE_DIR}），下文两个根是同一个。
#
# 源列表不由本文件维护 —— 由顶层从 host 项目（src/CMakeLists.txt 各目录 PARENT_SCOPE
# 导出）通过 -D 注入 BPFVM_LIB_SOURCES / BPFVM_MAIN_SOURCE / BPFVM_POSIX_SOURCES。
# 三者都是相对 ${BPFVM_ROOT} 的相对路径，这里转成绝对路径。
# JIT 一起编（-target bpf 下 __x86_64__/__aarch64__ 未定义，insn.cpp 平台守卫落到 #else
# StubJitCompiler，jit/*.cpp 的 #if 守卫把实际代码预处理为空 —— 编过但运行时无效）。

cmake_minimum_required(VERSION 3.25)
project(bpfvm_bpf_proj CXX)

# 把注入的相对路径源列表转成绝对路径（BPFVM_ROOT = 主项目根，由顶层注入）。
foreach(_s IN LISTS BPFVM_LIB_SOURCES BPFVM_MAIN_SOURCE BPFVM_POSIX_SOURCES)
    list(APPEND _abs_sources ${BPFVM_ROOT}/${_s})
endforeach()

# 对象库：VM 核心 + JIT + main + POSIX 全部源（与 host 一致）。
add_library(bpfvm_bpf_obj OBJECT ${_abs_sources})
# 项目头搜索路径（insn.h / posix_syscall.h / bpf_syscall.h 等）。
target_include_directories(bpfvm_bpf_obj PRIVATE
    ${BPFVM_ROOT}
    ${BPFVM_ROOT}/src
    ${BPFVM_ROOT}/src/posix)

# 最终 ELF：链接由 toolchain 的 CMAKE_CXX_LINK_EXECUTABLE 驱动 bpfvm-ld 完成。
# 产物名 bpfvm.bpf；INSTALL_COMMAND 会把它拷到 ${CMAKE_BINARY_DIR}/bpfvm.bpf。
add_executable(bpfvm_bpf $<TARGET_OBJECTS:bpfvm_bpf_obj>)
set_target_properties(bpfvm_bpf PROPERTIES OUTPUT_NAME bpfvm.bpf)
