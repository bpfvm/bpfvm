#!/bin/bash
# 构建 dash for BPF（root/bin/dash，动态）。
# 依赖：thirdparty/dash 子模块（分支 bpf）、宿主 autoconf/automake（autogen）、基础构建。
# CC_FOR_BUILD=gcc 编 host 代码生成器（mkinit/mksyntax/mknodes/mksignames），与 bpf 侧
# clang 在一次 make 里交织——必须经 make_ld_wrapper 的 clang wrapper（见 env.sh）。
set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
make_ld_wrapper
require_base

DASH_DIR="${ROOT_DIR}/thirdparty/dash"
BUILD_DIR="${ROOT_DIR}/build/dash"

echo "=== dash: autogen ==="
cd "${DASH_DIR}"
./autogen.sh

echo "=== dash: configure (bpf-unknown-none) ==="
# out-of-tree 构建，源码树保持干净
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"
# 上次构建残留的 builtins 生成物会让 make 误判已生成，清掉
rm -f src/builtins.def src/builtins.c src/builtins.h
"${DASH_DIR}/configure" \
    --host=bpf-unknown-none \
    CC="${CLANG_WRAPPER}" \
    CC_FOR_BUILD="gcc" \
    CFLAGS="-std=gnu11 ${COMMON_CFLAGS} -DJOBS=1" \
    LDFLAGS="${COMMON_LDFLAGS}" \
    LIBS="${ROOT_DIR}/root/lib/libc.a" \
    --enable-fnmatch

echo "=== dash: make ==="
make -j"${JOBS}"
file src/dash
mkdir -p "${ROOT_DIR}/root/bin"
cp -f src/dash "${ROOT_DIR}/root/bin/dash"
echo "done: root/bin/dash"
