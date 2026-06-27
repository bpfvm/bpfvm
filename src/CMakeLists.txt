set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_library(bpfvm_lib STATIC
    insn.cpp
    elf_loader.cpp
    posix_syscall.cpp
    jit_compiler.cpp
    x86_emitter.cpp
    aarch64_emitter.cpp
)
target_include_directories(bpfvm_lib PUBLIC ${CMAKE_SOURCE_DIR})

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

add_library(BpfWideArgs MODULE BpfWideArgs.cpp)
target_compile_options(BpfWideArgs PRIVATE ${LLVM_CXXFLAGS} -fno-rtti)
target_link_libraries(BpfWideArgs PRIVATE ${LLVM_LDFLAGS} ${LLVM_LIBS})
set_target_properties(BpfWideArgs PROPERTIES
    OUTPUT_NAME BpfWideArgs
    PREFIX "lib"
    SUFFIX ".so"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
message(STATUS "BpfWideArgs: enabled (LLVM ${LLVM_VERSION}, plugin -> ${CMAKE_BINARY_DIR}/libBpfWideArgs.so)")


add_executable(bpfvm main.cpp)
target_link_libraries(bpfvm bpfvm_lib ${LIBELF_LIBRARIES})

# bpfvm-ld 只需离线链接逻辑，独立编译，不依赖 VM 运行时（bpfvm_lib）
add_executable(bpfvm-ld ld_main.cpp elf_linker.cpp elf_loader.cpp)
target_include_directories(bpfvm-ld PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(bpfvm-ld ${LIBELF_LIBRARIES})

add_executable(bpfvm_test insn_test.cpp)
target_link_libraries(bpfvm_test bpfvm_lib ${LIBELF_LIBRARIES})
