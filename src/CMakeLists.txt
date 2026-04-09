add_library(bpfvm_lib STATIC
    insn.cpp
    posix_syscall.cpp
    jit_compiler.cpp
    x86_emitter.cpp
)
target_include_directories(bpfvm_lib PUBLIC ${CMAKE_SOURCE_DIR})

add_executable(bpfvm main.cpp)
target_link_libraries(bpfvm bpfvm_lib ${LIBELF_LIBRARIES})

add_executable(bpfvm_test insn_test.cpp)
target_link_libraries(bpfvm_test bpfvm_lib ${LIBELF_LIBRARIES})
