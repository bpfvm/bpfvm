#!/bin/bash
# root/ 统一构建入口（调度器）。所有产物装到 root/：
#   root/include：guest 头（bpf_syscall.h/asm/linux）+ musl 头 + C++ 头（c++/v1/）
#               + openssl/readline 等组件头。
#   root/lib：   libc.a/libc.so/ld-bpf.so、libcxx.{a,so}、libcrypto/libssl/libz/libreadline.{a,so}...
#   root/bin：   dash/sbase 工具/busybox/openssl/python3.13。
#
# 用法：
#   ./scripts/build_root.sh                # 基础构建：guest 头 + musl（libc.a/libc.so/ldso）
#                                          #   + libcxx；组件需显式指定，不随基础构建
#   ./scripts/build_root.sh <组件>...       # 只构建指定组件（可多选），不跑基础构建
# 每个组件是 scripts/build_<comp>.sh（可独立运行，头部注释列各自的产物/依赖）；
# 第三方源码缺失时由各脚本自动 git clone 到 thirdparty/（见 env.sh clone_if_missing）。
set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

COMPONENTS="busybox dash sbase openssl zlib readline ffi python"

build_base() {
    # guest 头（include/{bpf_syscall.h,asm,asm-generic,linux}）：test 等 guest 程序
    # 编译时经 -isystem root/include 取用，独立于 musl 头，先装
    echo "=== root: 安装 guest 头到 root/include ==="
    mkdir -p "${ROOT_DIR}/root/include" "${ROOT_DIR}/root/bin"
    cp -vf "${ROOT_DIR}/include/bpf_syscall.h" "${ROOT_DIR}/root/include/"
    cp -rvf "${ROOT_DIR}/include/asm"          "${ROOT_DIR}/root/include/"
    cp -rvf "${ROOT_DIR}/include/asm-generic"  "${ROOT_DIR}/root/include/"
    cp -rvf "${ROOT_DIR}/include/linux"        "${ROOT_DIR}/root/include/"

    "${ROOT_DIR}/scripts/build_musl.sh"

    # 失败容忍（同 busybox）：libcxx.a 已有产物时复用，只挡真正缺库的情况
    if ! "${ROOT_DIR}/scripts/build_libcxx.sh"; then
        [ -f "${ROOT_DIR}/root/lib/libcxx.a" ] || { echo "错误: libcxx 构建失败且无既有产物" >&2; exit 1; }
        echo "libcxx 构建失败，复用既有 root/lib/libcxx.a"
    fi
}

# 先校验参数，避免用户传错时白跑构建
for comp in "$@"; do
    [ -x "${ROOT_DIR}/scripts/build_${comp}.sh" ] || {
        echo "错误: 未知组件 ${comp}（可用: $(echo "${COMPONENTS}" | tr ' ' ' / ')）" >&2
        exit 1
    }
done

if [ $# -eq 0 ]; then
    build_base
    exit 0
fi

require_base

for comp in "$@"; do
    if ! "${ROOT_DIR}/scripts/build_${comp}.sh"; then
        case "${comp}" in
            busybox) echo "busybox 构建失败，跳过（可选组件，不中断整体）" ;;
            *) exit 1 ;;
        esac
    fi
done
