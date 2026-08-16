#!/bin/bash
set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

# 公共 env（ROOT_DIR / COMMON_CFLAGS / pass 探测 / make_ld_wrapper 等）见 scripts/env.sh。
# 本脚本所有产物（musl/libcxx 库 + 头 + 各可执行）统一装到 root/：
#   root/include：musl C 头（bits/、sys/...）。
#   root/lib：libc.a/libm.a/...、dlstart.lo/dynlink.lo、libc.so->ld-bpf.so、libcxx.a/libcxx.so、libcrypto/libssl.{a,so}。
#   root/bin：dash/sbase/busybox/openssl。
#
# 用法：
#   ./scripts/build_root.sh                # 默认：musl + libc.so + libcxx + busybox
#   ./scripts/build_root.sh dash sbase ... # 额外构建指定组件（dash / sbase / openssl，可多选）
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
#     * PT_INTERP=/lib/ld-bpf.so -> VM loader find_library("ld-bpf.so") 命中，加载它，
#       入口 = load_base + e_entry（e_entry 指向 _dlstart，由 -e _dlstart 设定）。
#     * DT_NEEDED libc.so -> ldso 的 load_library 命中 is_self，直接复用已映射的 ldso。
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
    # 子库的 .so 软链 -> libc.so：musl 把 m/rt/pthread/dl/... 全合并进 libc，
    # 静态侧已在 musl/build.sh 建 lib<sub>.a->libc.a；动态侧补 lib<sub>.so->libc.so，
    # 否则 -lm/-lrt/-lpthread/-ldl 等在 -L root/lib 找不到 .so 会漏到 host
    # /usr/lib 的同名 linker script（非 ELF）-> bpfvm-ld 加载失败。
    for sub in m rt pthread crypt util xnet resolv dl; do
        ln -sf libc.so "${ROOT_DIR}/root/lib/lib${sub}.so"
    done
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

# 构建 OpenSSL（可选组件；源码不纳入版本控制，浅克隆 openssl-3.0 到 openssl/）。
# 产物：root/lib/{libcrypto,libssl}.{a,so} + root/include/openssl/ + root/bin/openssl。
#   - .a 由 make build_libs 产出；.so 从 .a 用 bpfvm-ld -shared 合成（依赖 libc.so）。
#   - CLI 由 make build_programs 让 OpenSSL 自链为静态自包含 PIE（ssl/crypto/libc 全静态打入）。
# 依赖：build_libc_bpfso 已产出 libc.so（.so 合成与 CLI 链接都用到）。
# Configure 配置见 cmake/openssl-bpf.conf；no-* 裁剪理由见该文件尾部注释。
build_openssl() {
    echo "Building OpenSSL..."
    local OPENSSL_DIR="${ROOT_DIR}/openssl"
    local PREFIX="${ROOT_DIR}/root"
    local BUILD_DIR="${ROOT_DIR}/build/openssl"
    local BPF_CONF="${ROOT_DIR}/cmake/openssl-bpf.conf"

    if [ ! -d "${OPENSSL_DIR}/.git" ]; then
        echo "Cloning openssl-3.0 into ${OPENSSL_DIR} ..."
        git clone --depth 1 -b openssl-3.0 https://github.com/openssl/openssl.git "${OPENSSL_DIR}"
    fi

    rm -rf "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"
    cd "${OPENSSL_DIR}"
    make clean || true

    echo "=== Configuring OpenSSL (bpf-unknown-none) ==="
    # OpenSSL 专属 CFLAGS 调整（在 COMMON_CFLAGS 基础上）：
    #   去 -g / -fstack-size-section：clang BPF + -g 对部分外部函数声明 ICE（详见 AGENTS.md #213714）。
    #   -Wno-error=int-conversion：o_str.c 的 strerror_r(int)->char* 赋值（仅错误路径）。
    #   -bpf-stack-size=131072：apps 大函数（s_client/s_server/s_speed）单帧 >16KB；
    #     curve25519/curve448 域运算也需大栈（SIXTY_FOUR_BIT_LONG 下展开更大）。
    #   -UOPENSSL_NO_ASM：SIXTY_FOUR_BIT_LONG 下 BN_UMULT_HIGH/LOHI 需过 bn_local.h:362 的
    #       !OPENSSL_NO_ASM 守卫（no-asm 只定义 OPENSSL_NO_ASM，不定义 OPENSSL_NO_INLINE_ASM）。
    #       这里 undef 它使 __int128 宏分支激活。仅影响预处理宏——asm 源文件列表由 build.info 的
    #       !$disabled{asm} 控制，与 CFLAGS 无关，故不会拉入 x86 asm。
    # __SIZEOF_INT128__ 全局启用：__int128 的乘/除/模/变量移位由 BpfSoftFp pass 改写
    # 成虚拟指令软化（BPF_FP_MUL128 / BPF_FP_*DIV128/*REM128 / 拆半移位，覆盖 bn 的
    # BN_UMULT_HIGH 与 curve448/curve25519 域运算）；add/sub/phi 等其余 i128 运算由
    # BPF 后端原生拆成 (lo,hi) i64 处理。故不再触发 __multi3/__ashlti3 等。
    local OPENSSL_CFLAGS="${COMMON_CFLAGS//-g/}"
    OPENSSL_CFLAGS="${OPENSSL_CFLAGS//-fstack-size-section/} -Wno-error=int-conversion"
    OPENSSL_CFLAGS="${OPENSSL_CFLAGS//-bpf-stack-size=16384/-bpf-stack-size=131072}"
    OPENSSL_CFLAGS="${OPENSSL_CFLAGS} -UOPENSSL_NO_ASM -D__SIZEOF_INT128__=16"

    # LDLIBS 经 BIN_EX_LIBS 注入 -l:libc.so：补 _start + libc/pthread 符号（bpfvm-ld 是
    # -nostdlib 语义），并让 openssl 作为 DT_NEEDED libc.so 的动态可执行（纯动态，省产物体积）。
    CFLAGS="${OPENSSL_CFLAGS}" \
    LDFLAGS="${COMMON_LDFLAGS}" \
    LDLIBS="-L${PREFIX}/lib -l:libc.so" \
    CC="${CLANG_WRAPPER}" \
    AR="ar" \
    RANLIB="ranlib" \
    perl ./Configure \
        --config="${BPF_CONF}" \
        --prefix="${PREFIX}" \
        --openssldir="/etc/ssl" \
        threads \
        no-tests no-rdrand no-egd no-ktls no-weak-ssl-ciphers no-cmp \
        --with-rand-seed=getrandom \
        bpf-unknown-none

    local JOBS="${OSS_BUILD_JOBS:-$(nproc)}"

    echo "=== Building libcrypto.a / libssl.a ==="
    make -j"${JOBS}" build_generated build_libs

    echo "=== 收集库产物 ==="
    local LIBCRYPTO=$(find "${OPENSSL_DIR}" -name libcrypto.a -not -path '*/test/*' 2>/dev/null | head -1)
    local LIBSSL=$(find "${OPENSSL_DIR}" -name libssl.a -not -path '*/test/*' 2>/dev/null | head -1)
    echo "libcrypto.a: ${LIBCRYPTO}"
    echo "libssl.a:     ${LIBSSL}"
    [ -n "${LIBCRYPTO}" ] && [ -n "${LIBSSL}" ] || {
        echo "[build_openssl] 未找到 libcrypto.a/libssl.a（build_libs 失败？）" >&2
        exit 1
    }

    mkdir -p "${PREFIX}/lib" "${PREFIX}/include" "${PREFIX}/bin"
    cp -f "${LIBCRYPTO}" "${PREFIX}/lib/libcrypto.a"
    cp -f "${LIBSSL}" "${PREFIX}/lib/libssl.a"

    # 头文件：install_sw 只装头+库（不装 man），失败则手工拷。
    if ! make install_sw DESTDIR="${BUILD_DIR}/install_root" >/dev/null 2>&1; then
        echo "[build_openssl] make install_sw 失败，手工拷头"
        mkdir -p "${PREFIX}/include/openssl"
        cp -f "${OPENSSL_DIR}"/include/openssl/*.h "${PREFIX}/include/openssl/"
        cp -f "${OPENSSL_DIR}"/include/openssl/opensslconf.h "${PREFIX}/include/openssl/"
    else
        rm -rf "${PREFIX}/include/openssl"
        if [ -d "${BUILD_DIR}/install_root${PREFIX}/include/openssl" ]; then
            cp -r "${BUILD_DIR}/install_root${PREFIX}/include/openssl" "${PREFIX}/include/openssl"
        fi
    fi
    echo "libcrypto.a / libssl.a / 头文件安装完成"

    # 合成 .so（依赖链 libssl.so -> libcrypto.so -> libc.so，需 libc.so 已存在）。
    echo "=== 合成 libcrypto.so / libssl.so (bpfvm-ld -shared) ==="
    "${BPFVM_LD}" -shared --soname libcrypto.so \
        "${PREFIX}/lib/libcrypto.a" \
        -L "${PREFIX}/lib" -l:libc.so \
        -o "${PREFIX}/lib/libcrypto.so"
    "${BPFVM_LD}" -shared --soname libssl.so \
        "${PREFIX}/lib/libssl.a" \
        -L "${PREFIX}/lib" -l:libcrypto.so -l:libc.so \
        -o "${PREFIX}/lib/libssl.so"

    # CLI：make build_programs 让 OpenSSL 自链 apps/openssl（静态自包含 PIE）。
    echo "=== Building openssl CLI (apps/openssl via make build_programs) ==="
    cd "${OPENSSL_DIR}"
    make -j"${JOBS}" build_programs
    [ -x "${OPENSSL_DIR}/apps/openssl" ] || {
        echo "[build_openssl] make 未产出 apps/openssl（build_programs 失败？）" >&2
        exit 1
    }
    cp -f "${OPENSSL_DIR}/apps/openssl" "${PREFIX}/bin/openssl"
    echo "OpenSSL 完成: ${PREFIX}/bin/openssl + lib/{libcrypto,libssl}.{a,so}"
}

# ----------------------------------------------------------------------------
# 调度：默认构建基础库 + busybox；命令行参数指定额外组件（dash / sbase / openssl）。
# ----------------------------------------------------------------------------
# 先校验参数，避免用户传错时白跑完整基础构建。
for comp in "$@"; do
    case "$comp" in
        dash|sbase|openssl) ;;
        *) echo "[build_root] 未知组件: $comp（可用: dash / sbase / openssl）" >&2; exit 1 ;;
    esac
done

build_musl
build_libc_bpfso
build_libcxx
build_busybox

for comp in "$@"; do
    case "$comp" in
        dash)    build_dash ;;
        sbase)   build_sbase ;;
        openssl) build_openssl ;;
    esac
done
