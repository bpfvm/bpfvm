# POSIX syscall 实现的 OBJECT 库。
#
# 把本目录的源文件聚合成一个对象库，父目录通过
#   add_subdirectory(posix)
#   ... $<TARGET_OBJECTS:posix_obj> ...
# 把对象并入 bpfvm_lib，最终仍链接成单个 libbpfvm_lib.a（与原先内联源列表的产物一致）。
# 后续在本目录增删 syscall 文件，只需改这里的源列表，无需动 src/CMakeLists.txt。
#
# 仍需沿用项目根的两组头搜索路径：
#   - ${CMAKE_SOURCE_DIR}/src   → "posix_syscall.h" / "insn.h" 等项目头
#   - ${CMAKE_SOURCE_DIR}       → "include/bpf_call.h" 等 BPF 侧头
add_library(posix_obj OBJECT
    mpsc_queue.cpp
    posix_syscall.cpp
    memory.cpp
    file_io.cpp
    filesystem.cpp
    fd_ops.cpp
    socket.cpp
    process.cpp
    session.cpp
    signal.cpp
    futex.cpp
)
target_include_directories(posix_obj PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}
)
