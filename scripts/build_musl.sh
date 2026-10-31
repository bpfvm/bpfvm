#!/bin/bash
# 构建 musl for BPF（装到 root/{include,lib}）：musl 头 + libc.a（含 _start）+
# libc.so/ld-bpf.so（动态链接器，从 libc.a + ldso objects 合成）。
# 用法：[prefix=$ROOT_DIR/root] ./scripts/build_musl.sh
# 依赖：clang（>=19）、build/{libBpfWideArgs.so,libBpfSoftFp.so,bpfvm-ld}（cmake 产出）。
#
# 设计要点（详见 musl/arch/bpf/ 各头文件注释）：
#   - ARCH=bpf 由 configure 的 bpf*) 分支识别（musl/configure 已加）。
#   - CFLAGS 注入 -target bpf + 两个 pass 插件（BpfWideArgs 突破 5 参数/struct
#     返回/变参限制，BpfSoftFp 把浮点 IR 改写成 BPF_FP_* call）。
#   - --disable-shared：musl 自身的 .so 构建不可用，libc.so 由 bpfvm-ld 合成（见下）。
#   - LIBCC 置空：BPF 无 gcc 运行时（__adddf3 等由 BpfSoftFp + VM 处理）。
set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

PREFIX="${1:-$ROOT_DIR/root}"
MUSL_DIR="${ROOT_DIR}/thirdparty/musl"
BUILD="$ROOT_DIR/build/musl"

# pass 插件路径（优先用项目 build/ 下的，回退到环境变量）
WIDEARGS="${WIDEARGS:-$ROOT_DIR/build/libBpfWideArgs.so}"
SOFTFP="${SOFTFP:-$ROOT_DIR/build/libBpfSoftFp.so}"

CFLAGS="-target bpf -mcpu=v4 -O1 -fno-builtin -Werror=macro-redefined \
  -mllvm -bpf-stack-size=16384 -ffunction-sections \
  -Xclang -target-feature -Xclang +alu32 \
  -Xclang -target-feature -Xclang -dwarfris \
  -Wno-unused-command-line-argument \
  -fpass-plugin=$WIDEARGS \
  -fpass-plugin=$SOFTFP \
  -fstack-size-section \
  -I$ROOT_DIR/root/include"

echo "=== musl: configure (ARCH=bpf) in $BUILD ==="
mkdir -p "$BUILD"
cd "$BUILD"

# AR/RANLIB 必须显式指宿主 GNU 工具：configure 从 --target=bpf 推导
# CROSS_COMPILE=bpf-，不覆盖则内部规则调 bpf-ar/bpf-ranlib（binutils-bpf）。
# BPF 对象是标准 ELF64，宿主 ar 可直接打包。
CC=clang AR=ar RANLIB=ranlib CFLAGS="$CFLAGS" LDFLAGS="" LIBCC="" \
  sh "$MUSL_DIR/configure" --target=bpf --disable-shared --prefix="$PREFIX"

# configure 的 tryflag 用 C 文件测 -Wa,--noexecstack，C 编译不触发汇编器路径，
# 误判为 yes。但 BPF clang 集成汇编器对 .s 文件加该 flag 会 segfault（LLVM bug）。
# musl 其他 arch 的 .s 不受影响（GNU as 接受），BPF arch 有 .s（clone.s）须移除。
sed -i 's/ -Wa,--noexecstack//g' "$BUILD/config.mak"

echo "=== musl: make lib/libc.a ==="
make -j"${JOBS}" lib/libc.a

# 只构建 crt1.o。其他 crt 在 BPF 上不需要：
#   - crti.o/crtn.o：BPF 无 .init_array/.fini_array 框架，编出来是空 .o，merge 进
#     libc.a 不贡献任何代码/符号，删掉省事。
#   - Scrt1.o：BPF clang 对地址引用本来就走重定位（lddw 带 R_BPF_64_64、call 带
#     R_BPF_64_32），-fPIC 与否对 crt1 这种简单代码产出一致；crt1.o 已能覆盖
#     PIE/.so 场景，不需要 Scrt1.o。
#   - rcrt1.o：静态 PIE 自启动，依赖 dlstart 动态链接器逻辑，BPF 不支持，编译必
#     失败（_start_c 签名冲突 + GETFUNCSYM 无前向声明）。
# make install 会连带编译 rcrt1.o 导致失败，故只单独构建 crt1.o，cp 到 lib/。
# 把 crt1 merge 进 libc.a，使其像 pdclib 那样自带 _start——链接时只链 libc.a 即可，
# 无需显式传 crt、无需关心顺序。
echo "=== musl: make crt1.o + merge 进 libc.a ==="
make obj/crt/crt1.o
ar rcs lib/libc.a obj/crt/crt1.o

# ldso object：dlstart.lo / dynlink.lo。标准 musl 把 ldso 代码放进 libc.so 而非
# libc.a（静态链接的程序不需要 ldso），故 lib/libc.a 不含它们；用 musl 自带 make
# 规则单独编译（它知道正确的 -fPIC + pass 插件 flags），供下方合成 ld-bpf.so。
echo "=== musl: make ldso objects (dlstart.lo, dynlink.lo) ==="
make obj/ldso/dlstart.lo obj/ldso/dynlink.lo

echo "=== musl: install 头 + 库到 $PREFIX ==="
# 手动安装（make install 会编译所有 crt 含 rcrt1.o 必失败）：
# 头到 <prefix>/include，库到 <prefix>/lib（libc.a 已合并 crt1 含 _start）。
# 与 build_root.sh / test/Makefile / scripts 共用同一份安装目录
# （-isystem root/include、-L root/lib）。
#
# bits/ 头来源：musl 的 arch 特化头在 arch/bpf/bits/，通用头在 arch/generic/bits/
# （fcntl.h/errno.h/dirent.h 等空占位或通用定义）。BPF arch 只覆盖了部分 bits
# （syscall.h.in/stat.h/signal.h 等），其余须从 generic 取。cp 顺序：先 generic，
# 后 bpf（bpf 特化覆盖 generic）。只装 bits/——arch 下的内部头（syscall_arch.h/
# atomic_arch.h 等）不属于公共 sysroot。
mkdir -p "$PREFIX/include/bits" "$PREFIX/lib"
cp -r obj/include/* "$PREFIX/include/"
cp -r "$MUSL_DIR/include/"* "$PREFIX/include/"
cp -r "$MUSL_DIR/arch/generic/bits/"* "$PREFIX/include/bits/" 2>/dev/null || true
cp -r "$MUSL_DIR/arch/bpf/bits/"* "$PREFIX/include/bits/" 2>/dev/null || true
cp -f lib/libc.a "$PREFIX/lib/"
# 子库（libm.a/librt.a/libpthread.a/...）软链接到 libc.a：musl 把所有符号都合并在
# libc.a 里，-lm/-lrt/-lpthread 等即等价于 -lc。软链接而非空归档，是为了 busybox trylink
# 等只传 -lm（不带 -lc）的场景能解析到 libc 符号（strlen/stat/...）。
for sub in m rt pthread crypt util xnet resolv dl; do
    ln -sf libc.a "$PREFIX/lib/lib${sub}.a"
done

# 合成 libc.so + 动态链接器 ld-bpf.so。只构建一份二进制——libc.a + ldso objects，
# SONAME=libc.so，入口 _dlstart：
#   - root/lib/ld-bpf.so：这份二进制本体。链接时（-l:libc.so）读它的 dynsym（libc 符号
#     超集）+ DT_SONAME=libc.so，故链接进主程序/libcxx.so 的 DT_NEEDED 仍记 libc.so。
#     * PT_INTERP=/lib/ld-bpf.so -> VM loader find_library("ld-bpf.so") 命中，加载它，
#       入口 = load_base + e_entry（e_entry 指向 _dlstart，由 -e _dlstart 设定）。
#     * DT_NEEDED libc.so -> ldso 的 load_library 命中 is_self，直接复用已映射的 ldso。
#   - root/lib/libc.so：相对 symlink 指向 ld-bpf.so（同名二进制，供 -l:libc.so 命名）。
#   - 静态程序把 libc.a 直接链进去，不经过 .so，不受影响。
echo "=== musl: 合成 ld-bpf.so / libc.so ==="
"${BPFVM_LD}" -shared --soname libc.so -e _dlstart \
    "$PREFIX/lib/libc.a" \
    "$BUILD/obj/ldso/dlstart.lo" "$BUILD/obj/ldso/dynlink.lo" \
    -o "$PREFIX/lib/ld-bpf.so"
ln -sf ld-bpf.so "$PREFIX/lib/libc.so"
# 子库的 .so 软链 -> libc.so：与静态侧 lib<sub>.a->libc.a 对称，
# 否则 -lm/-lrt/-lpthread/-ldl 等在 -L root/lib 找不到 .so 会漏到 host
# /usr/lib 的同名 linker script（非 ELF）-> bpfvm-ld 加载失败。
for sub in m rt pthread crypt util xnet resolv dl; do
    ln -sf libc.so "$PREFIX/lib/lib${sub}.so"
done

echo "done: $PREFIX/lib/libc.a（含 _start）+ ld-bpf.so + musl 头"
