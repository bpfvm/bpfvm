#!/bin/bash
set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

# 公共 env（ROOT_DIR / COMMON_CFLAGS / pass 探测 / make_ld_wrapper 等）见 scripts/env.sh。
# 本脚本所有产物（musl/libcxx 库 + 头 + dash/sbase/busybox 可执行）统一装到 root/：
#   root/include：musl C 头（bits/、sys/…）。
#   root/lib：libc.a/libm.a/…、dlstart.lo/dynlink.lo、libc.so→ld-bpf.so、libcxx.a/libcxx.so。
#   root/bin：dash/sbase/busybox。
make_ld_wrapper
ROOT_BIN_DIR="${ROOT_DIR}/root/bin"
mkdir -p "${ROOT_BIN_DIR}"

# 构建 musl（BPF 目标的 C 标准库）。musl/build.sh 交叉编译产出 libc.a 和头，
# 直接安装到 root/{include,lib}（PREFIX=$ROOT_DIR/root，显式传入避免依赖默认）。
build_musl() {
    echo "Building musl..."
    cd "${ROOT_DIR}"
    sh musl/build.sh "${ROOT_DIR}/root"
}

# 构建系统库 libc.so + 动态链接器 ld-bpf.so
#
# 背景：musl 的 ldso 代码（dlstart.c/dynlink.c）不在 libc.a 里（标准 musl 把它们放进
# libc.so 而非 libc.a），由 musl/build.sh 单独编译成 dlstart.lo/dynlink.lo 安装到 root/lib/。
#
# 只构建一份二进制——libc.a + ldso objects，SONAME=libc.so，入口 _dlstart。
#   - root/lib/ld-bpf.so：这份二进制本体。链接时（-l:libc.so）读它的 dynsym（libc 符号
#     超集）+ DT_SONAME=libc.so，故链接进主程序/libcxx.so 的 DT_NEEDED 仍记 libc.so。
#     * PT_INTERP=/lib/ld-bpf.so → VM loader find_library("ld-bpf.so") 命中，加载它，
#       入口 = load_base + e_entry（e_entry 指向 _dlstart，由 -e _dlstart 设定）。
#     * DT_NEEDED libc.so → ldso 的 load_library 命中 is_self，直接复用已映射的 ldso。
#   - root/lib/libc.so：相对 symlink 指向 ld-bpf.so（同名二进制，供 -l:libc.so 命名）。
#   - 静态程序把 libc.a 直接链进去，不经过 .so，不受影响。
build_libc_bpfso() {
    echo "Building libc.so ..."
    mkdir -p "${ROOT_DIR}/root/lib"
    # 输出为 root/lib/ld-bpf.so（本体），再建 libc.so 软链；少一次 cp。
    "${BPFVM_LD}" -shared --soname libc.so -e _dlstart \
        "${ROOT_DIR}/root/lib/libc.a" \
        "${ROOT_DIR}/root/lib/dlstart.lo" \
        "${ROOT_DIR}/root/lib/dynlink.lo" \
        -o "${ROOT_DIR}/root/lib/ld-bpf.so"
    ln -sf ld-bpf.so "${ROOT_DIR}/root/lib/libc.so"
    rm "${ROOT_DIR}/root/lib/dlstart.lo" "${ROOT_DIR}/root/lib/dynlink.lo"
}

# 构建 C++ 运行时（libcxx.a + libcxx.so）。
#   libcxx.a：由 scripts/build_libcxx.sh 编译 libc++/libc++abi 源码打成静态库，放到 root/lib/。
#   libcxx.so：用 bpfvm-ld -shared 从 libcxx.a 合成（PIE ET_DYN），依赖 libc.so（DT_NEEDED），
#     仿 build_libc_bpfso，直接产出到 root/lib/（rootfs 与 ctest 运行时共用）。
# 必须在 build_libc_bpfso 之后调用（libcxx.so 依赖 libc.so 存在）。
build_libcxx() {
    echo "Building libcxx.a..."
    cd "${ROOT_DIR}"
    "${ROOT_DIR}/scripts/build_libcxx.sh"

    echo "Building libcxx.so..."
    "${BPFVM_LD}" -shared --soname libcxx.so \
        "${ROOT_DIR}/root/lib/libcxx.a" \
        -L "${ROOT_DIR}/root/lib" -l:libc.so \
        -o "${ROOT_DIR}/root/lib/libcxx.so"
}

build_dash() {
    echo "Running autogen.sh..."
    cd "${ROOT_DIR}/dash"
    ./autogen.sh

    echo "Configuring dash..."
    mkdir -p "${ROOT_DIR}/build/dash"
    cd "${ROOT_DIR}/build/dash"

    rm -f src/builtins.def src/builtins.c src/builtins.h

    "${ROOT_DIR}/dash/configure" \
        --host=bpf-unknown-none \
        CC="${CLANG_WRAPPER}" \
        CC_FOR_BUILD="gcc" \
        CFLAGS="-std=gnu11 ${COMMON_CFLAGS} -DJOBS=1" \
        LDFLAGS="${COMMON_LDFLAGS}" \
        LIBS="${ROOT_DIR}/root/lib/libc.a" \
        --enable-fnmatch

    echo "Building dash..."
    make -j4
    echo "Build complete. Binary is at build/dash/src/dash"
    file src/dash
    cp -f src/dash "${ROOT_BIN_DIR}/dash"
}

build_sbase() {
    echo "Building sbase..."
    cd "${ROOT_DIR}/sbase"

    # sbase 是纯 bpf（无 host cc）：直接给 make 设 COMPILER_PATH，bpf-gcc 就用 bpfvm-ld。
    # .c: 后缀规则一次性编译+链接。
    COMPILER_PATH="${LD_WRAPPER_DIR}" make \
        CC="clang" \
        CFLAGS="${COMMON_CFLAGS}" \
        LIB="libutf.a libutil.a ${ROOT_DIR}/root/lib/libc.a" \
        LDFLAGS="${COMMON_LDFLAGS}"

    echo "Build complete. Binaries are in sbase"
    find . -maxdepth 1 -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
        if file -b "$bin" | grep -q 'eBPF'; then
            cp -f "$bin" "${ROOT_BIN_DIR}/"
        fi
    done
}

# 构建 busybox（可选组件；源码不纳入版本控制，需本地 clone 上游到 busybox/）。
# busybox/ 不存在则跳过；构建失败不中断整体流程。产物装到 root/bin/busybox（动态）。
build_busybox() {
    if [ ! -d "${ROOT_DIR}/busybox" ]; then
        echo "busybox/ 不存在，跳过 busybox（可选组件）"
        return 0
    fi
    echo "Building busybox..."
    "${ROOT_DIR}/scripts/build_busybox.sh" || { echo "busybox 构建失败，跳过"; return 0; }
    cp -f "${ROOT_DIR}/busybox/busybox.linked" "${ROOT_BIN_DIR}/busybox" 2>/dev/null || true
}

build_musl
build_libc_bpfso
build_libcxx
build_dash
#build_sbase
build_busybox
