#!/bin/bash
set -e

# Get project root and clang resource dir
ROOT_DIR=$(pwd)
CLANG_RES=$(clang -print-resource-dir)/include

echo "Building sbase/ls..."

cd sbase

# Clean to start fresh
#make clean

# Build ls
# We override LIB to include pdclib.
# We override CFLAGS to include BPF targets and includes.
# We override LDFLAGS for BPF linking.

make \
    CC="${ROOT_DIR}/bpf-cc" \
    CFLAGS="-target bpf -mcpu=v4 -O1 -mllvm -bpf-stack-size=4096 -nostdinc -fno-builtin -isystem ${ROOT_DIR}/libc/include -isystem ${ROOT_DIR}/include -isystem ${CLANG_RES} -g" \
    LIB="libutf.a libutil.a ${ROOT_DIR}/libc/lib64/libpdclib.a" \
    LDFLAGS="-target bpf -Wl,-e,_start -nostdlib -static" \
    ls cal cat mkdir rmdir printf printenv basename dirname sort head false yes expand cut cmp comm fold join paste split strings tee tr true tsort unexpand uniq unlink wc \
    md5sum sha1sum sha224sum sha256sum sha384sum sha512-224sum sha512-256sum sha512sum \
    chmod chown chgrp echo pathchk pwd readlink mknod od mv ln link which nohup tar test uudecode uuencode xinstall cp du rm rev cols
 
echo "Build complete. Binary is at sbase"
