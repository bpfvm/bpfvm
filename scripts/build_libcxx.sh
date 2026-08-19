#!/bin/bash
# 构建 BPF target 的 C++ runtime（libcxx.a）
# cmake -S runtimes -DLLVM_ENABLE_RUNTIMES=libcxx;libcxxabi
#
# 产物：root/include/c++/v1/（libc++ + libc++abi 头）；中间产物在 build/libcxx/。
#      libcxx.so 由 build_root.sh 从 libcxx.a 合成，不在本脚本。
#
# 用法：[LLVM_SRC=/path/to/llvm-project] ./scripts/build_libcxx.sh
# 需要：clang/clang++（host）、cmake、make、ar；musl 头已装到 root/include（先跑 build_musl）。

set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
cd "${ROOT_DIR}"

LLVM_TREE=""
for p in "${LLVM_SRC:-}" $(ls -d ${ROOT_DIR}/llvm /usr/local/llvm-* /usr/lib/llvm-* 2>/dev/null | sort -Vr); do
    [ -n "$p" ] || continue
    if [ -f "$p/runtimes/CMakeLists.txt" ] && [ -f "$p/libcxx/src/algorithm.cpp" ] \
       && [ -f "$p/libcxxabi/src/private_typeinfo.cpp" ]; then
        LLVM_TREE="$p"; break
    fi
done
if [ -z "$LLVM_TREE" ]; then
    echo "未找到 LLVM 源码树（需 monorepo 布局，含 runtimes/ + libcxx/ + libcxxabi/）。" >&2
    echo "请解压 LLVM 源码 tarball 到 ${ROOT_DIR}/llvm，或设 LLVM_SRC=/path/to/llvm-project" >&2
    exit 1
fi
echo "==> LLVM source tree: $LLVM_TREE"

BUILD_DIR="${ROOT_DIR}/build/libcxx"
CLANG_RES="$(clang++ -print-resource-dir)/include"

# BPF 交叉编译 flags（与 test/Makefile 的 CXX_FLAGS 同一套）。
# 注意不要在这里 -isystem 任何 C++ 头目录（源码 include 或生成的 build/include/c++/v1）：
# LLVM 的 runtimes 构建会把整套 libc++ 头拷进生成目录并以目标 -I（CXX_INCLUDES，
# 排命令行最前）引入；若再叠加同目录 -isystem，重复路径会让 cstddef/cstdint 的
# include_next 链在带 include guard 的包装副本处提前终止，musl 的 stddef.h/stdint.h
# 永远串不上（::int32_t 未定义）。目标 -I 在前、下面的 musl -isystem 在后，顺序天然正确。
BASE_FLAGS="-target bpf -mcpu=v4 -O1 -fno-builtin -fno-math-errno \
    -mllvm -bpf-stack-size=16384 -nostdinc -D_GNU_SOURCE \
    -isystem ${ROOT_DIR}/root/include -isystem ${ROOT_DIR}/include -isystem $CLANG_RES \
    -fpass-plugin=${PASS_WIDEARGS} \
    -fpass-plugin=${PASS_SOFTFP} \
    -fpass-plugin=${PASS_LIBCALLLOWER}"
CMAKE_C_FLAGS="$BASE_FLAGS"
CMAKE_CXX_FLAGS="-std=c++23 -fno-exceptions -frtti $BASE_FLAGS"

# 全量重建：避免改 flags/换 LLVM 版本后残留陈旧配置与对象（脚本不依赖增量）。
rm -rf "$BUILD_DIR"
mkdir -p root/lib

echo "==> configuring LLVM runtimes (libcxx + libcxxabi)"
#   -  EXCEPTIONS/SHARED=OFF（默认 ON）；STATIC_ABI_LIBRARY=ON（默认 OFF）；
#      UNWINDER/TESTS/DOCS/BENCHMARKS=OFF（默认 ON）。
#   -  时区数据库（LIBCXX_ENABLE_TIME_ZONE_DATABASE）Generic 平台默认 OFF，不传即关。
#      其实现读 /usr/share/zoneinfo 且落在不发布的 libc++experimental.a；若将来把
#      CMAKE_SYSTEM_NAME 改为 Linux（默认翻成 ON），须显式补 =OFF。
cmake -S "${LLVM_TREE}/runtimes" -B "$BUILD_DIR" \
    -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi" \
    -DCMAKE_C_COMPILER="$(command -v clang)" \
    -DCMAKE_CXX_COMPILER="$(command -v clang++)" \
    -DCMAKE_C_FLAGS="${CMAKE_C_FLAGS}" \
    -DCMAKE_CXX_FLAGS="${CMAKE_CXX_FLAGS}" \
    -DCMAKE_SYSTEM_NAME=Generic \
    -DCMAKE_SYSTEM_PROCESSOR=bpf \
    -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
    -DCMAKE_INSTALL_PREFIX="${ROOT_DIR}/root" \
    -DLIBCXX_ENABLE_EXCEPTIONS=OFF \
    -DLIBCXXABI_ENABLE_EXCEPTIONS=OFF \
    -DLIBCXX_ENABLE_SHARED=OFF \
    -DLIBCXXABI_ENABLE_SHARED=OFF \
    -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
    -DLIBCXX_HAS_PTHREAD_API=ON \
    -DLIBCXX_HAS_MUSL_LIBC=ON \
    -DLIBCXXABI_USE_LLVM_UNWINDER=OFF \
    -DLIBCXX_INCLUDE_BENCHMARKS=OFF \
    -DLIBCXX_INCLUDE_TESTS=OFF \
    -DLIBCXXABI_INCLUDE_TESTS=OFF \
    -DLIBCXX_INCLUDE_DOCS=OFF

echo "==> building libc++ / libc++abi"
cmake --build "$BUILD_DIR" -j"$(nproc)"

echo "==> installing headers + libc++.a to root/"
rm -rf "${ROOT_DIR}/root/include/c++"
cmake --install "$BUILD_DIR" >/dev/null

[ -f "$BUILD_DIR/lib/libc++.a" ] || { echo "libc++.a 未产出（构建失败？）" >&2; exit 1; }
cp -f "$BUILD_DIR/lib/libc++.a" "${ROOT_DIR}/root/lib/libcxx.a"
# 清掉 install 落地的原始命名/附属档案，rootfs 只保留 libcxx.a（单一 C++ 库入口）。
rm -f "${ROOT_DIR}/root/lib/libc++.a" "${ROOT_DIR}/root/lib/libc++abi.a" \
      "${ROOT_DIR}/root/lib/libc++experimental.a"
[ -f "${ROOT_DIR}/root/include/c++/v1/vector" ] || { echo "头文件未安装到 root/include/c++/v1" >&2; exit 1; }

echo "==> done: root/lib/libcxx.a ($(wc -c < root/lib/libcxx.a) bytes),"
echo "==>       root/include/c++/v1 ($(find root/include/c++/v1 -type f | wc -l) header files)"
