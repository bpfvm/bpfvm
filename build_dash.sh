#!/bin/bash
set -e

# Get project root and clang resource dir
ROOT_DIR=$(pwd)
CLANG_RES=$(clang -print-resource-dir)/include

echo "Running autogen.sh..."
cd dash
./autogen.sh
cd ..

echo "Configuring dash..."
mkdir -p build/dash
cd build/dash

# Clean previous build artifacts that might conflict
rm -f src/builtins.def src/builtins.c src/builtins.h

../../dash/configure \
    --host=bpf-unknown-none \
    CC="clang" \
    CC_FOR_BUILD="gcc" \
    CFLAGS="-std=gnu11 -target bpf -mcpu=v4 -O1 -mllvm -bpf-stack-size=4096 -nostdinc -fno-builtin -isystem $ROOT_DIR/libc/include -isystem $ROOT_DIR/include -isystem $CLANG_RES -g -DJOBS=0" \
    LDFLAGS="-target bpf -nostdlib -Wl,-e,_start" \
    LIBS="$ROOT_DIR/libc/lib64/libpdclib.a"


echo "Building dash..."
make -j4
find . -name '*.o' -exec llvm-objcopy --set-section-flags .rodata.str1.1=alloc,readonly,data {} \;
make
echo "Build complete. Binary is at build/dash/src/dash"
file src/dash
