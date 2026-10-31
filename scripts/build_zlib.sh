#!/bin/bash
# 构建 zlib for BPF（root/lib/libz.{a,so} + root/include/{zlib.h,zconf.h}）。
# 源码浅克隆 madler/zlib 默认分支（develop）到 thirdparty/zlib/。
# CPython 的 zlib 扩展经 -lz 取用。依赖：基础构建。
set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
make_ld_wrapper
require_base

ZLIB_DIR="${ROOT_DIR}/thirdparty/zlib"
PREFIX="${ROOT_DIR}/root"
BUILD_DIR="${ROOT_DIR}/build/zlib"

clone_if_missing "${ZLIB_DIR}" https://github.com/madler/zlib.git

# out-of-tree 构建（configure 从构建目录调用，官方支持），源码树保持干净
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# 正式 configure（zlib 自带脚本，非 autoconf）：
#   CHOST=bpf：交叉模式，CROSS_PREFIX/架构探测不会误配宿主 x86；显式 CC/AR/
#   RANLIB 覆盖其工具推断。
#   --static：只编 libz.a；libz.so 由 synth_so 合成（上游共享库机制假定 gnu ld，
#   不适用）。
#   LDFLAGS 挂 libc.a：strerror/vsnprintf 等探测是链接型（无 -c），裸链没有
#   libc 必挂，会误判 No 并要求 --insecure。
echo "=== zlib: configure ==="
CHOST=bpf-unknown-linux CC="${CLANG_WRAPPER}" AR="ar" RANLIB="ranlib" \
    CFLAGS="${CFLAGS_NOG}" \
    LDFLAGS="${COMMON_LDFLAGS} ${PREFIX}/lib/libc.a" \
    "${ZLIB_DIR}/configure" --static --prefix="${PREFIX}"

echo "=== zlib: make libz.a ==="
make -j"${JOBS}" libz.a

# zlib.h 在源码树，zconf.h 由 configure 生成在构建目录
cp -f "${ZLIB_DIR}/zlib.h" zconf.h "${PREFIX}/include/"
cp -f libz.a "${PREFIX}/lib/"

echo "=== zlib: 合成 libz.so ==="
synth_so libz
echo "done: root/lib/libz.{a,so} + include/{zlib.h,zconf.h} (git $(git -C "${ZLIB_DIR}" log -1 --format=%h))"
