# POSIX syscall 实现的 OBJECT 库。
#
# 把本目录的源文件聚合成一个对象库，父目录通过
#   add_subdirectory(posix)
#   ... $<TARGET_OBJECTS:posix_obj> ...
# 把对象并入 bpfvm_lib，最终仍链接成单个 libbpfvm_lib.a（与原先内联源列表的产物一致）。
# 后续在本目录增删 syscall 文件，只需改这里的源列表，无需动 src/CMakeLists.txt。
#
# 本目录维护的源文件列表（相对当前 CMakeLists 的相对路径）：add_library 直接用；
# 再用 list(TRANSFORM PREPEND) 加上本目录相对项目根的相对前缀，CACHE INTERNAL 导出到
# 全局作用域，供顶层转发给 nesting 子项目（BPF-on-BPF 自举复用同一份列表）。
#
# 仍需沿用项目根的两组头搜索路径：
#   - ${CMAKE_SOURCE_DIR}/src   → "posix_syscall.h" / "insn.h" 等项目头
#   - ${CMAKE_SOURCE_DIR}       → "include/bpf_call.h" 等 BPF 侧头
set(_posix_sources
    posix_syscall.cpp
    signal_queue.cpp
    memory.cpp
    file_io.cpp
    filesystem.cpp
    fd_ops.cpp
    socket.cpp
    process.cpp
    session.cpp
    signal.cpp
    futex.cpp
    procfs.cpp
    fs.cpp
)

add_library(posix_obj OBJECT ${_posix_sources})
target_include_directories(posix_obj PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)

# 导出给顶层/nesting：路径相对 ${CMAKE_SOURCE_DIR}（CACHE INTERNAL 全局可见，
# 不需要 PARENT_SCOPE 一层层提）。
file(RELATIVE_PATH _dir_prefix "${CMAKE_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}")
list(TRANSFORM _posix_sources PREPEND "${_dir_prefix}/" OUTPUT_VARIABLE _posix_exported)
set(BPFVM_POSIX_SOURCES "${_posix_exported}" CACHE INTERNAL "POSIX sources for nesting")
