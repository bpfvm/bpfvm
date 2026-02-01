#!/bin/bash
set -e

ROOT_DIR=$(pwd)
CLANG_RES=$(clang -print-resource-dir)/include

COMMON_CFLAGS="-target bpf -mcpu=v4 -O1 -mllvm -bpf-stack-size=4096 -nostdinc -fno-builtin -isystem ${ROOT_DIR}/libc/include -isystem ${ROOT_DIR}/include -isystem ${CLANG_RES} -g"
COMMON_LDFLAGS="-target bpf -nostdlib -Wl,-e,_start"
ROOT_BIN_DIR="${ROOT_DIR}/root/bin"

mkdir -p "${ROOT_BIN_DIR}"

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
        CC="${ROOT_DIR}/bpf-cc" \
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

    make \
        CC="${ROOT_DIR}/bpf-cc" \
        CFLAGS="${COMMON_CFLAGS}" \
        LIB="libutf.a libutil.a ${ROOT_DIR}/libc/lib64/libpdclib.a" \
        LDFLAGS="${COMMON_LDFLAGS} -static"

    echo "Build complete. Binaries are in sbase"
    find . -maxdepth 1 -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
        if file -b "$bin" | grep -q 'eBPF'; then
            cp -f "$bin" "${ROOT_BIN_DIR}/"
        fi
    done
}

build_dash
build_sbase
