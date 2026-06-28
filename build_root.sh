#!/bin/bash
set -e

ROOT_DIR=$(pwd)
CLANG_RES=$(clang -print-resource-dir)/include
BPFVM_LD="${ROOT_DIR}/build/bpfvm-ld"

# BPF 交叉编译 flags。
# -nostdinc：不用宿主 glibc 头，只用 PDCLib(libc/include) + BPF guest 头(include)。
# -fno-builtin：必须保留。否则 clang 会把 mempcpy/strchr/stpcpy/... 等 builtin
#   优化成对 memcpy 等的调用，而 BPF 后端在 ISel 拒绝这类 builtin lowering
#   （实测 dash 的 arith_yylex.c:mempcpy 即触发）。强制走 PDCLib 的库实现即可。
# 浮点由 BpfSoftFp pass 在 IR 层处理（见下），不依赖 -fno-builtin。
# 两个 pass plugin：libBpfWideArgs（突破 5 参数限制）、libBpfSoftFp（软件浮点），
#   存在才加载，避免插件没编出来时 clang 报 "cannot find"。
COMMON_CFLAGS="-target bpf -mcpu=v4 -O1 -mllvm -bpf-stack-size=4096 -nostdinc -fno-builtin"
if [ -f "${ROOT_DIR}/build/libBpfWideArgs.so" ]; then
    COMMON_CFLAGS="${COMMON_CFLAGS} -fpass-plugin=${ROOT_DIR}/build/libBpfWideArgs.so"
fi
if [ -f "${ROOT_DIR}/build/libBpfSoftFp.so" ]; then
    COMMON_CFLAGS="${COMMON_CFLAGS} -fpass-plugin=${ROOT_DIR}/build/libBpfSoftFp.so"
fi
COMMON_CFLAGS="${COMMON_CFLAGS} -isystem ${ROOT_DIR}/libc/include -isystem ${ROOT_DIR}/include -isystem ${CLANG_RES} -g"
# clang -target bpf 把链接委托给 /usr/bin/bpf-gcc，bpf-gcc 再用 /usr/lib/gcc/bpf/14/ld
# （binutils bpf-ld）。让它改用 bpfvm-ld 的三个坑：
#   1) clang 不把 -B 转发给 bpf-gcc（实测 -### 里没有 -B；-Wl,-B 传给 ld 也没用）；
#   2) -fuse-ld=bpfvm-ld 被 bpf-gcc 拒绝（只认 bfd/gold/lld）；
#   3) bpf-gcc 认 COMPILER_PATH 环境变量——但它对所有 gcc 生效（含 host gcc）。
# 两类程序区别对待：
#   - sbase：纯 bpf（无 host cc），直接给 make 设 COMPILER_PATH 即可，见 build_sbase。
#   - dash：用 CC_FOR_BUILD=gcc 编 host 代码生成器(mkinit/mksyntax/mknodes/mksignames)，
#     与 bpf shell(clang) 在一次 make 里交织——不能给整条 make 设 COMPILER_PATH（会污染
#     host gcc 的链接）。所以只 wrap clang：wrapper 内部 export COMPILER_PATH，bpf-gcc（clang
#     的子进程）继承得到，host gcc（make 直接调）沾不到。
# 共用一个 ld→bpfvm-ld 目录（COMPILER_PATH 指向它）；失败会直接报错，不再被 bpf-ld 静默替掉。
LD_WRAPPER_DIR=$(mktemp -d -p "${ROOT_DIR}" bpfvm-ldpath.XXXXXX)
ln -sf "${BPFVM_LD}" "${LD_WRAPPER_DIR}/ld"
REAL_CLANG="$(command -v clang)"
cat > "${LD_WRAPPER_DIR}/clang" <<EOF
#!/bin/bash
export COMPILER_PATH="${LD_WRAPPER_DIR}"
exec "${REAL_CLANG}" "\$@"
EOF
chmod +x "${LD_WRAPPER_DIR}/clang"
CLANG_WRAPPER="${LD_WRAPPER_DIR}/clang"
trap "rm -rf '${LD_WRAPPER_DIR}'" EXIT
COMMON_LDFLAGS="-target bpf -nostdlib"
ROOT_BIN_DIR="${ROOT_DIR}/root/bin"

mkdir -p "${ROOT_BIN_DIR}"

# 构建系统库 libc.so（libpdclib 的动态形态）：放到 libc/lib64/，并复制一份到 root/lib/
build_libc_bpfso() {
    echo "Building libc.so..."
    "${BPFVM_LD}" -shared --soname libc.so \
        "${ROOT_DIR}/libc/lib64/libpdclib.a" -o "${ROOT_DIR}/libc/lib64/libc.so"
    mkdir -p "${ROOT_DIR}/root/lib"
    cp -f "${ROOT_DIR}/libc/lib64/libc.so" "${ROOT_DIR}/root/lib/libc.so"
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
        CFLAGS="-std=gnu11 ${COMMON_CFLAGS} -DJOBS=0" \
        LDFLAGS="${COMMON_LDFLAGS}" \
        LIBS="${ROOT_DIR}/libc/lib64/libpdclib.a" \
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
        LIB="libutf.a libutil.a ${ROOT_DIR}/libc/lib64/libpdclib.a" \
        LDFLAGS="${COMMON_LDFLAGS}"

    echo "Build complete. Binaries are in sbase"
    find . -maxdepth 1 -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
        if file -b "$bin" | grep -q 'eBPF'; then
            cp -f "$bin" "${ROOT_BIN_DIR}/"
        fi
    done
}

build_libc_bpfso
build_dash
build_sbase
