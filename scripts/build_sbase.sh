#!/bin/bash
# 构建 sbase 工具集 for BPF（root/bin/ 里的 eBPF 小程序）。
# 依赖：thirdparty/sbase（本地 git clone https://git.suckless.org/sbase，不入库）、基础构建。
set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
make_ld_wrapper
require_base

SBASE_DIR="${ROOT_DIR}/thirdparty/sbase"
[ -d "${SBASE_DIR}" ] || {
    echo "错误: ${SBASE_DIR} 不存在（git clone https://git.suckless.org/sbase）" >&2
    exit 1
}

# sbase 是纯 bpf（无 host cc）：直接给 make 设 COMPILER_PATH，bpf-gcc 就用 bpfvm-ld
# （两类程序区别对待见 env.sh make_ld_wrapper 的说明）。
# .c: 后缀规则一次性编译+链接。
# 上游新加了构建期宿主工具 scripts/make（all 的前置目标，被 all 的配方执行）：
# 它必须跑在宿主上，交叉 flags 下编译/链接必挂。先用宿主编译器单独构建它，
# 再让 all 用系统 make（SMAKE=make）驱动子构建（scripts/make 已存在不会重建）。
echo "=== sbase: 构建宿主工具 scripts/make ==="
cd "${SBASE_DIR}"
make CC=c99 scripts/make

echo "=== sbase: make ==="
COMPILER_PATH="${LD_WRAPPER_DIR}" make -j"${JOBS}" SMAKE=make \
    CC="clang" \
    CFLAGS="${COMMON_CFLAGS}" \
    LIB="libutf.a libutil.a ${ROOT_DIR}/root/lib/libc.a" \
    LDFLAGS="${COMMON_LDFLAGS}"

echo "=== sbase: 收集 eBPF 二进制到 root/bin ==="
mkdir -p "${ROOT_DIR}/root/bin"
find . -maxdepth 1 -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
    if file -b "$bin" | grep -q 'eBPF'; then
        cp -f "$bin" "${ROOT_DIR}/root/bin/"
    fi
done
echo "done: root/bin/（sbase 工具集）"
