#!/bin/bash
# 构建 OpenSSL for BPF（root/lib/{libcrypto,libssl}.{a,so} + root/include/openssl/ +
# root/bin/openssl）。源码浅克隆 openssl-3.0 到 thirdparty/openssl/。
#   - .a 由 make build_libs 产出；.so 从 .a 合成（synth_so，依赖 libc.so）。
#   - CLI 由 make build_programs 让 OpenSSL 自链为静态自包含 PIE（ssl/crypto/libc 全静态打入）。
# 依赖：基础构建（libc.so 用于 .so 合成与 CLI 链接）、宿主 perl。
# Configure 配置见 cmake/openssl-bpf.conf；no-* 裁剪理由见该文件尾部注释。
set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
make_ld_wrapper
require_base

OPENSSL_DIR="${ROOT_DIR}/thirdparty/openssl"
PREFIX="${ROOT_DIR}/root"
BUILD_DIR="${ROOT_DIR}/build/openssl"
BPF_CONF="${ROOT_DIR}/cmake/openssl-bpf.conf"

clone_if_missing "${OPENSSL_DIR}" https://github.com/openssl/openssl.git openssl-3.0

# bn_local.h 的 BN_UMULT_HIGH/LOHI 段整体包在 !defined(OPENSSL_NO_ASM) 守卫内，而
# Configure 对 no-asm 目标把 OPENSSL_NO_ASM 写进生成的 configuration.h（头文件里的
# #define，命令行 -U 压不掉），__int128 分支因此永远不可达，bn_mul_words 等 bignum
# 原语退化成 32 位学校书乘（每个 limb 乘 ~35 条 BPF 指令，genrsa 慢数百倍的主因）。
# 对 BPF 目标放开该守卫：__BPF__ 下命中的唯一分支是 int128 宏（其余分支由 x86/arm
# 等 CPU 宏门控，BPF 皆不匹配），asm 源文件列表由 build.info 的 !$disabled{asm}
# 控制，不因此拉入任何 asm。
# 幂等：已含 __BPF__ 的行不再匹配。
perl -i -pe 's{^\#if !defined\(OPENSSL_NO_ASM\) && !defined\(OPENSSL_NO_INLINE_ASM\) && !defined\(PEDANTIC\)$}{\#if (!defined(OPENSSL_NO_ASM) || defined(__BPF__)) \&\& !defined(OPENSSL_NO_INLINE_ASM) \&\& !defined(PEDANTIC)}' \
    "${OPENSSL_DIR}/crypto/bn/bn_local.h"

# out-of-tree 构建（从构建目录调 $srcdir/Configure，OpenSSL 3.0 官方支持），
# 源码树保持干净
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

echo "=== openssl: Configure (bpf-unknown-none) ==="
# OpenSSL 专属 CFLAGS 调整（在 CFLAGS_NOG 基础上）：
#   再剥 -fstack-size-section：与 -g 同属 #213714 的 ICE 触发面。
#   -Wno-error=int-conversion：o_str.c 的 strerror_r(int)->char* 赋值（仅错误路径）。
#   -bpf-stack-size=131072：apps 大函数（s_client/s_server/s_speed）单帧 >16KB；
#     curve25519/curve448 域运算也需大栈（SIXTY_FOUR_BIT_LONG 下展开更大）。
#   -UOPENSSL_NO_ASM：剥掉 Configure 可能经命令行注入的 -DOPENSSL_NO_ASM（belt and
#       braces；configuration.h 里的 #define 由上方 bn_local.h 补丁放行）。
# __SIZEOF_INT128__ 全局启用：__int128 的乘/除/模/变量移位由 BpfSoftFp pass 改写
# 成虚拟指令软化（BPF_FP_MUL128 / BPF_FP_*DIV128/*REM128 / 拆半移位，覆盖 bn 的
# BN_UMULT_HIGH 与 curve448/curve25519 域运算）；add/sub/phi 等其余 i128 运算由
# BPF 后端原生拆成 (lo,hi) i64 处理。故不再触发 __multi3/__ashlti3 等。
OPENSSL_CFLAGS="${CFLAGS_NOG//-fstack-size-section/} -Wno-error=int-conversion"
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
perl "${OPENSSL_DIR}/Configure" \
    --config="${BPF_CONF}" \
    --prefix="${PREFIX}" \
    --openssldir="/etc/ssl" \
    threads \
    no-tests no-rdrand no-egd no-ktls no-weak-ssl-ciphers no-cmp \
    --with-rand-seed=getrandom \
    bpf-unknown-none

echo "=== openssl: make libcrypto.a / libssl.a ==="
make -j"${JOBS}" build_generated build_libs

echo "=== openssl: 收集库产物 ==="
LIBCRYPTO=$(find "${BUILD_DIR}" -name libcrypto.a -not -path '*/test/*' 2>/dev/null | head -1)
LIBSSL=$(find "${BUILD_DIR}" -name libssl.a -not -path '*/test/*' 2>/dev/null | head -1)
echo "libcrypto.a: ${LIBCRYPTO}"
echo "libssl.a:     ${LIBSSL}"
[ -n "${LIBCRYPTO}" ] && [ -n "${LIBSSL}" ] || {
    echo "错误: 未找到 libcrypto.a/libssl.a（build_libs 失败？）" >&2
    exit 1
}

mkdir -p "${PREFIX}/lib" "${PREFIX}/include" "${PREFIX}/bin"
cp -f "${LIBCRYPTO}" "${PREFIX}/lib/libcrypto.a"
cp -f "${LIBSSL}" "${PREFIX}/lib/libssl.a"

# 头文件：install_sw 只装头+库（不装 man），失败则手工拷。
if ! make install_sw DESTDIR="${BUILD_DIR}/install_root" >/dev/null 2>&1; then
    echo "make install_sw 失败，手工拷头"
    mkdir -p "${PREFIX}/include/openssl"
    cp -f "${OPENSSL_DIR}"/include/openssl/*.h "${PREFIX}/include/openssl/"
    # 生成的头（opensslconf.h 等）在构建目录，覆盖同名源码头
    cp -f "${BUILD_DIR}"/include/openssl/*.h "${PREFIX}/include/openssl/"
else
    rm -rf "${PREFIX}/include/openssl"
    if [ -d "${BUILD_DIR}/install_root${PREFIX}/include/openssl" ]; then
        cp -r "${BUILD_DIR}/install_root${PREFIX}/include/openssl" "${PREFIX}/include/openssl"
    fi
fi
echo "libcrypto.a / libssl.a / 头文件安装完成"

# 合成 .so（依赖链 libssl.so -> libcrypto.so -> libc.so）。
echo "=== openssl: 合成 libcrypto.so / libssl.so ==="
synth_so libcrypto
synth_so libssl -l:libcrypto.so

# CLI：make build_programs 让 OpenSSL 自链 apps/openssl（静态自包含 PIE）。
echo "=== openssl: make CLI (apps/openssl via build_programs) ==="
make -j"${JOBS}" build_programs
[ -x "${BUILD_DIR}/apps/openssl" ] || {
    echo "错误: make 未产出 apps/openssl（build_programs 失败？）" >&2
    exit 1
}
cp -f "${BUILD_DIR}/apps/openssl" "${PREFIX}/bin/openssl"
echo "done: root/bin/openssl + root/lib/{libcrypto,libssl}.{a,so} + include/openssl/"
