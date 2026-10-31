#!/bin/bash
# 构建 GNU readline 8.2 for BPF（root/lib/libreadline.{a,so} + libhistory.{a,so} +
# root/include/readline/）。供 python readline 模块（及以后的交互式 guest 程序）链接。
# 源码 curl 解包 GNU tarball 到 thirdparty/readline/（上游无 git 镜像可锁）。
#   - termcap：readline 8.2 无内置实现，configure 探测 libc/-ltermcap/-lncurses；
#     musl 没有。scripts/termcap_shim.c 是最小实现（条目内置 xterm 系/vt100/dumb，
#     不读 /etc/termcap），编进 libreadline.a，configure 用 bash_cv_termcap_lib=libc
#     预置缓存跳过探测。
#   - .a 静态构建（make 默认目标）；.so 由 synth_so 合成。history 的对象并进同一
#     .a/.so（符号与 readline 侧不冲突，免 -lhistory 链）。
# 依赖：基础构建。
set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
make_ld_wrapper
require_base

RL_DIR="${ROOT_DIR}/thirdparty/readline"
PREFIX="${ROOT_DIR}/root"
BUILD_DIR="${ROOT_DIR}/build/readline"

if [ ! -f "${RL_DIR}/configure" ]; then
    echo "=== readline: download 8.2 tarball ==="
    mkdir -p "${RL_DIR}"
    curl -sL --max-time 120 -o "${RL_DIR}/rl.tar.gz" \
        https://ftp.gnu.org/gnu/readline/readline-8.2.tar.gz
    tar xzf "${RL_DIR}/rl.tar.gz" -C "${RL_DIR}" --strip-components=1
    rm -f "${RL_DIR}/rl.tar.gz"
fi

# out-of-tree 构建，源码树保持干净
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# bash_cv_termcap_lib 预置 libc：tgetent 等由 shim 提供并编入 .a；
# LDFLAGS 挂 libc.a 供 AC_CHECK_FUNCS 等链接型探测（无 -c 裸链必挂）。
echo "=== readline: configure (bpf-unknown-linux) ==="
bash_cv_termcap_lib=libc \
CFLAGS="${CFLAGS_NOG}" \
CPPFLAGS="-target bpf -mcpu=v4 -nostdinc -isystem ${PREFIX}/include" \
LDFLAGS="${COMMON_LDFLAGS} ${PREFIX}/lib/libc.a" \
CC="${CLANG_WRAPPER}" \
AR="ar" RANLIB="ranlib" \
"${RL_DIR}/configure" \
    --build=x86_64-linux-gnu \
    --host=bpf-unknown-linux \
    --prefix="${PREFIX}" \
    --disable-shared

echo "=== readline: make ==="
make -j"${JOBS}"

# termcap shim + history 并入 libreadline.a
"${CLANG_WRAPPER}" ${CFLAGS_NOG} -c "${ROOT_DIR}/scripts/termcap_shim.c" \
    -o "${BUILD_DIR}/termcap_shim.o"
cp -f libreadline.a libreadline-merge.a
ar r libreadline-merge.a termcap_shim.o $(ar t libhistory.a)
ranlib libreadline-merge.a

# 头文件闭包：readline.h -> rlstdc/rltypedefs/keymaps/tilde；keymaps -> chardefs
mkdir -p "${PREFIX}/include/readline"
cp -f "${RL_DIR}"/readline.h "${RL_DIR}"/keymaps.h "${RL_DIR}"/history.h \
      "${RL_DIR}"/rltypedefs.h "${RL_DIR}"/chardefs.h "${RL_DIR}"/rlstdc.h \
      "${RL_DIR}"/tilde.h "${RL_DIR}"/rlconf.h "${PREFIX}/include/readline/"
cp -f libreadline-merge.a "${PREFIX}/lib/libreadline.a"
cp -f libhistory.a "${PREFIX}/lib/libhistory.a"

echo "=== readline: 合成 libreadline.so / libhistory.so ==="
synth_so libreadline
# python 只链 -lreadline；libhistory.so 仅为 -lhistory 探测兜底，指向同产物
synth_so libhistory || true
echo "done: root/lib/libreadline.{a,so} + libhistory.{a,so} + include/readline/"
