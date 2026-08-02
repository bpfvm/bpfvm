set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# VM 核心 + JIT 源（本目录维护）。add_library 直接用相对路径；
# 再用 list(TRANSFORM PREPEND) 加上本目录相对项目根的相对前缀，CACHE INTERNAL 导出到
# 全局作用域，供顶层转发给 nesting 子项目。
set(_lib_sources
    insn.cpp
    elf_loader.cpp
    pty.cpp
    gdb_server.cpp
    jit/jit_compiler.cpp
    jit/x86_emitter.cpp
    jit/aarch64_emitter.cpp
)

add_subdirectory(posix)

add_library(bpfvm_lib STATIC
    ${_lib_sources}
    $<TARGET_OBJECTS:posix_obj>
)
target_include_directories(bpfvm_lib PUBLIC ${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/src)
find_package(Threads REQUIRED)
target_link_libraries(bpfvm_lib PUBLIC Threads::Threads)

# 导出给顶层/nesting：路径相对 ${CMAKE_SOURCE_DIR}（CACHE INTERNAL 全局可见）。
file(RELATIVE_PATH _dir_prefix "${CMAKE_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}")
list(TRANSFORM _lib_sources PREPEND "${_dir_prefix}/" OUTPUT_VARIABLE _lib_exported)
set(BPFVM_LIB_SOURCES   "${_lib_exported}"          CACHE INTERNAL "VM lib sources for nesting")
set(BPFVM_MAIN_SOURCE   "src/main.cpp"              CACHE INTERNAL "VM main source for nesting")

# ---------------------------------------------------------------------------
# BpfWideArgs：BPF 突破 5 参数限制 + 返回结构体的 LLVM pass 插件
#
# 编译为 libBpfWideArgs.so，由 clang -fpass-plugin= 加载。
# 安装到 ${CMAKE_BINARY_DIR}/libBpfWideArgs.so
find_program(LLVM_CONFIG llvm-config)
if(NOT LLVM_CONFIG)
    message(FATAL_ERROR
        "BpfWideArgs: llvm-config not found. LLVM development environment "
        "(libllvm-dev / llvm-devel) is a hard requirement — the BpfWideArgs "
        "pass plugin cannot be built without it. Please install the LLVM "
        "development package (e.g. 'apt install libllvm-dev llvm-dev' on "
        "Debian/Ubuntu) and retry.")
endif()

execute_process(COMMAND ${LLVM_CONFIG} --version
                OUTPUT_VARIABLE LLVM_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${LLVM_CONFIG} --cxxflags
                OUTPUT_VARIABLE LLVM_CXXFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${LLVM_CONFIG} --ldflags
                OUTPUT_VARIABLE LLVM_LDFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${LLVM_CONFIG} --libs core passes analysis support
                OUTPUT_VARIABLE LLVM_LIBS OUTPUT_STRIP_TRAILING_WHITESPACE)
# 拆成 list（这些变量的值都是空格分隔的 flag 字符串）
separate_arguments(LLVM_CXXFLAGS UNIX_COMMAND "${LLVM_CXXFLAGS}")
separate_arguments(LLVM_LDFLAGS UNIX_COMMAND "${LLVM_LDFLAGS}")
separate_arguments(LLVM_LIBS UNIX_COMMAND "${LLVM_LIBS}")

add_library(BpfWideArgs MODULE passes/BpfWideArgs.cpp)
# 需要 ${CMAKE_SOURCE_DIR} 来解析 #include "include/bpf_syscall.h"（VLA 路径用 BPF_CALL_ALLOCA）。
target_include_directories(BpfWideArgs PRIVATE ${CMAKE_SOURCE_DIR})
# -Wno-unused-parameter：LLVM 系统头（DenseMap/Instructions/...）模板里有大量未用形参，
# 是第三方代码，抑制之；bpfvm 自身源码不受影响。
target_compile_options(BpfWideArgs PRIVATE ${LLVM_CXXFLAGS} -fno-rtti -Wno-unused-parameter)
target_link_libraries(BpfWideArgs PRIVATE ${LLVM_LDFLAGS} ${LLVM_LIBS})
set_target_properties(BpfWideArgs PROPERTIES
    OUTPUT_NAME BpfWideArgs
    PREFIX "lib"
    SUFFIX ".so"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
message(STATUS "BpfWideArgs: enabled (LLVM ${LLVM_VERSION}, plugin -> ${CMAKE_BINARY_DIR}/libBpfWideArgs.so)")

# BpfSoftFp：虚拟浮点指令的编码 pass
# 由 clang -fpass-plugin= 加载。
add_library(BpfSoftFp MODULE passes/BpfSoftFp.cpp)
target_include_directories(BpfSoftFp PRIVATE ${CMAKE_SOURCE_DIR})
# -Wno-unused-parameter：同 BpfWideArgs，抑制 LLVM 系统头的未用形参 warning。
target_compile_options(BpfSoftFp PRIVATE ${LLVM_CXXFLAGS} -fno-rtti -Wno-unused-parameter)
target_link_libraries(BpfSoftFp PRIVATE ${LLVM_LDFLAGS} ${LLVM_LIBS})
set_target_properties(BpfSoftFp PROPERTIES
    OUTPUT_NAME BpfSoftFp
    PREFIX "lib"
    SUFFIX ".so"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
message(STATUS "BpfSoftFp: enabled (plugin -> ${CMAKE_BINARY_DIR}/libBpfSoftFp.so)")

# BpfEmutls：把 annotate("emutls") 全局改写成 __emutls_get_address 调用
# （绕过 BPF 后端对 thread_local 的拒绝）。由 clang -fpass-plugin= 加载。
add_library(BpfEmutls MODULE passes/BpfEmutls.cpp)
target_include_directories(BpfEmutls PRIVATE ${CMAKE_SOURCE_DIR})
target_compile_options(BpfEmutls PRIVATE ${LLVM_CXXFLAGS} -fno-rtti -Wno-unused-parameter)
target_link_libraries(BpfEmutls PRIVATE ${LLVM_LDFLAGS} ${LLVM_LIBS})
set_target_properties(BpfEmutls PROPERTIES
    OUTPUT_NAME BpfEmutls
    PREFIX "lib"
    SUFFIX ".so"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
message(STATUS "BpfEmutls: enabled (plugin -> ${CMAKE_BINARY_DIR}/libBpfEmutls.so)")

# BpfLibcallLower：把 @llvm.memcpy/memmove/memset/trap + floor/ceil/trunc/round
# intrinsic 改写成对 musl 函数的普通 call（绕过 BPF 后端对这批 intrinsic 的拒绝）。
# 由 clang -fpass-plugin= 加载。
add_library(BpfLibcallLower MODULE passes/BpfLibcallLower.cpp)
target_include_directories(BpfLibcallLower PRIVATE ${CMAKE_SOURCE_DIR})
target_compile_options(BpfLibcallLower PRIVATE ${LLVM_CXXFLAGS} -fno-rtti -Wno-unused-parameter)
target_link_libraries(BpfLibcallLower PRIVATE ${LLVM_LDFLAGS} ${LLVM_LIBS})
set_target_properties(BpfLibcallLower PROPERTIES
    OUTPUT_NAME BpfLibcallLower
    PREFIX "lib"
    SUFFIX ".so"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
message(STATUS "BpfLibcallLower: enabled (plugin -> ${CMAKE_BINARY_DIR}/libBpfLibcallLower.so)")


add_executable(bpfvm main.cpp)
target_link_libraries(bpfvm bpfvm_lib)

# bpfvm-ld 只需离线链接逻辑，独立编译，不依赖 VM 运行时（bpfvm_lib）
add_executable(bpfvm-ld ld_main.cpp elf_linker.cpp elf_loader.cpp)
target_include_directories(bpfvm-ld PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(bpfvm-ld ${LIBELF_LIBRARIES})

add_executable(bpfvm_test insn_test.cpp)
target_link_libraries(bpfvm_test bpfvm_lib)
