# bpfvm.bpf 交叉编译 toolchain —— 仅 nesting 子项目使用。
#
# 借鉴 pdclib/bpf-toolchain.cmake：set(CMAKE_SYSTEM_NAME/PROCESSOR) 进入 cross-compile
# 模式，clang/clang++ 当编译器，bpfvm-ld 当链接器，所有 flags 用 CACHE FORCE 锁定。
#
# 由顶层 CMakeLists.txt 通过 ExternalProject_Add 的 -DCMAKE_TOOLCHAIN_FILE= 传给子项目。
# 子项目只需提供 BPFVM_ROOT / BPFVM_CLANG / BPFVM_CLANGXX / BPFVM_LIBCXX_INC /
# BPFVM_CLANG_RES_INC / BPFVM_BPFVM_LD / BPFVM_PASS_* 这几个路径变量（顶层探测后传入）。

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR bpf)
# 不让 try_compile 走链接（bpfvm-ld 不支持 link-only 的 try_compile 流程）。
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_COMPILER   ${BPFVM_CLANG})
set(CMAKE_CXX_COMPILER ${BPFVM_CLANGXX})

# C flags（照搬 test/Makefile 的 C 部分）。
set(CMAKE_C_FLAGS "-target bpf -mcpu=v4 -O1 -mllvm -bpf-stack-size=16384 \
    -nostdinc -fno-builtin -fno-math-errno -D_GNU_SOURCE \
    -fpass-plugin=${BPFVM_PASS_WIDEARGS} -fpass-plugin=${BPFVM_PASS_SOFTFP} \
    -fpass-plugin=${BPFVM_PASS_LIBCALLLOWER} -fpass-plugin=${BPFVM_PASS_EMUTLS} \
    -isystem ${BPFVM_LIBCXX_INC} -isystem ${BPFVM_ROOT}/root/include \
    -isystem ${BPFVM_ROOT}/include -isystem ${BPFVM_CLANG_RES_INC}"
    CACHE STRING "BPF C flags" FORCE)

# 关键：libc++ 头(BPFVM_LIBCXX_INC)必须在 musl(root/include)前——cstddef 的
# #include_next <stddef.h> 要求 libc++ 的 stddef.h 先被找到，再串联到 musl。
# 不加 -g：规避 clang BPF 后端 EmitExternalFunctionDeclaration 崩溃。
set(CMAKE_CXX_FLAGS "-target bpf -mcpu=v4 -O1 -mllvm -bpf-stack-size=16384 \
    -nostdinc -fno-builtin -fno-math-errno -fno-exceptions -frtti -std=c++23 \
    -D_GNU_SOURCE \
    -Dthread_local='__attribute__((annotate("emutls")))' \
    -fpass-plugin=${BPFVM_PASS_WIDEARGS} -fpass-plugin=${BPFVM_PASS_SOFTFP} \
    -fpass-plugin=${BPFVM_PASS_LIBCALLLOWER} -fpass-plugin=${BPFVM_PASS_EMUTLS} \
    -isystem ${BPFVM_LIBCXX_INC} -isystem ${BPFVM_ROOT}/root/include \
    -isystem ${BPFVM_ROOT}/include -isystem ${BPFVM_CLANG_RES_INC}"
    CACHE STRING "BPF C++ flags" FORCE)

# 用 bpfvm-ld 当链接器。它兼容 clang/gcc 风格 argv（见 ld_main.cpp），支持
# "-l <name>" 分离形式（ld_main.cpp:141）和 "-L <dir>"（ld_main.cpp:132）。
# 入口 _start：musl crt1 已合进 ld-bpf.so，由链接器按默认 _start 解析。
set(CMAKE_LINKER ${BPFVM_BPFVM_LD})
set(CMAKE_CXX_LINK_EXECUTABLE
    "<CMAKE_LINKER> <OBJECTS> -o <TARGET> -L${BPFVM_ROOT}/root/lib -l libc.so -l libcxx.so"
    CACHE STRING "BPF C++ link rule" FORCE)
set(CMAKE_C_LINK_EXECUTABLE
    "<CMAKE_LINKER> <OBJECTS> -o <TARGET> -L${BPFVM_ROOT}/root/lib -l libc.so -l libcxx.so"
    CACHE STRING "BPF C link rule" FORCE)
