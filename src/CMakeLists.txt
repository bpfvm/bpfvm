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

add_executable(bpfvm main.cpp)
target_link_libraries(bpfvm bpfvm_lib ${LIBELF_LIBRARIES})

# bpfvm-ld 只需离线链接逻辑，独立编译，不依赖 VM 运行时（bpfvm_lib）
add_executable(bpfvm-ld ld_main.cpp elf_linker.cpp elf_loader.cpp)
target_include_directories(bpfvm-ld PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(bpfvm-ld ${LIBELF_LIBRARIES})

add_executable(bpfvm_test insn_test.cpp)
target_link_libraries(bpfvm_test bpfvm_lib ${LIBELF_LIBRARIES})
