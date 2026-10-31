#!/bin/bash
# 构建 BPF ffi(ffi,仓库自带源码)-> root/lib/libffi.{a,so} +
# root/include/{ffi.h,ffitarget.h} + root/lib/pkgconfig/libffi.pc。
# 供 python _ctypes 链接:CPython 3.13 不再内置 libffi,configure 用
# PKG_CHECK_MODULES(libffi) 探测(build_python.sh 已设 PKG_CONFIG_LIBDIR=root/lib/pkgconfig)。
# 实现与 ABI 依据见 ffi/ffi.c 头注释。
# 依赖:基础构建。
set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
require_base

SRC_DIR="${ROOT_DIR}/ffi"
PREFIX="${ROOT_DIR}/root"
BUILD_DIR="${ROOT_DIR}/build/ffi"

# closure 分发栈帧约 25KB(args/staging 各 1024 项),给足上浮空间
FFI_CFLAGS="${CFLAGS_NOG/${STACK_FLAG}/-mllvm -bpf-stack-size=65536}"

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

echo "=== ffi: compile ==="
for f in ffi.c closures.c; do
    clang ${FFI_CFLAGS} -I "${ROOT_DIR}/include" -I "${SRC_DIR}" -c "${SRC_DIR}/${f}" -o "${f%.c}.o"
done
ar rcs libffi.a ffi.o closures.o

mkdir -p "${PREFIX}/include" "${PREFIX}/lib/pkgconfig"
# 头文件源头在 include/(第一方 guest 头目录);安装仍挂 ffi 组件,
# 避免 base 装出头文件却没有 libffi.so 的断层
cp -f "${ROOT_DIR}/include/ffi.h" "${ROOT_DIR}/include/ffitarget.h" "${PREFIX}/include/"
cp -f libffi.a "${PREFIX}/lib/"

echo "=== ffi: 合成 libffi.so ==="
synth_so libffi

# pcfiledir 相对路径:构建期由宿主 pkg-config 经 PKG_CONFIG_LIBDIR 找到
cat > "${PREFIX}/lib/pkgconfig/libffi.pc" <<'EOF'
Name: libffi
Description: libffi (bpfvm BPF target)
Version: 3.4.4
Libs: -L${pcfiledir}/.. -lffi
Cflags: -I${pcfiledir}/../../include
EOF

echo "done: root/lib/libffi.{a,so} + include/{ffi.h,ffitarget.h} + pkgconfig/libffi.pc"
