#!/bin/bash
# 公共构建环境（被各 build 脚本 source，不要直接执行）。
# 统一：ROOT_DIR（脚本相对）、COMMON_CFLAGS、pass .so 探测、LD wrapper 工厂。
# 被 source 时 BASH_SOURCE[0] 指向本文件，其目录的上一级即项目根。

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLANG_RES="$(clang -print-resource-dir)/include"
BPFVM_LD="${ROOT_DIR}/build/bpfvm-ld"

# BPF pass 插件路径常量。COMMON_CFLAGS 按 if-exist 探测加入；
# libcxx 的 STL_CXX_FLAGS 直接引用这些常量（去掉硬编码 build/libBpf*.so）。
PASS_WIDEARGS="${ROOT_DIR}/build/libBpfWideArgs.so"
PASS_SOFTFP="${ROOT_DIR}/build/libBpfSoftFp.so"
PASS_LIBCALLLOWER="${ROOT_DIR}/build/libBpfLibcallLower.so"

# BPF 交叉编译 flags（C 源：musl/dash/sbase/busybox）。
# -nostdinc：不用宿主 glibc 头，只用 musl(root/include，由 musl/build.sh 安装) + BPF guest 头(include)。
# -fno-builtin：必须保留。否则 clang 会把 mempcpy/strchr/stpcpy/... 等 builtin
#   优化成对 memcpy 等的调用，而 BPF 后端在 ISel 拒绝这类 builtin lowering
#   （实测 dash 的 arith_yylex.c:mempcpy 即触发）。强制走 libc 的库实现即可。
#   浮点由 BpfSoftFp pass 在 IR 层处理（见 CLAUDE.md），不依赖 -fno-builtin。
# -D_GNU_SOURCE：musl 的 bits/*.h 用 _POSIX/_GNU/_BSD feature 宏门控；显式开启全部
#   POSIX/GNU/BSD 接口（musl 应用惯例，避免 struct sigaction 等类型缺失）。
# -mllvm -bpf-stack-size=16384：dash cd.c:setpwd 等函数局部超限，统一用 16384（与 musl/test 一致）。
COMMON_CFLAGS="-target bpf -mcpu=v4 -O1 -mllvm -bpf-stack-size=16384 -nostdinc -fno-builtin -D_GNU_SOURCE"
[ -f "$PASS_WIDEARGS" ] && COMMON_CFLAGS="$COMMON_CFLAGS -fpass-plugin=$PASS_WIDEARGS"
[ -f "$PASS_SOFTFP" ] && COMMON_CFLAGS="$COMMON_CFLAGS -fpass-plugin=$PASS_SOFTFP"
# BpfLibcallLower：intrinsic -> musl libcall（memcpy/memmove/memset/trap/floor/ceil/trunc/round）。
[ -f "$PASS_LIBCALLLOWER" ] && COMMON_CFLAGS="$COMMON_CFLAGS -fpass-plugin=$PASS_LIBCALLLOWER"
COMMON_CFLAGS="$COMMON_CFLAGS -isystem ${ROOT_DIR}/root/include -isystem ${ROOT_DIR}/include -isystem ${CLANG_RES} -g -fstack-size-section"
# -fstack-size-section：让 clang 产出 .stack_sizes 段（每函数一条：函数地址 + ULEB128 栈大小）。
#   bpfvm-ld 在链接期据此修复 DW_OP_fbreg 偏移（clang BPF 后端把栈变量偏移算错的 bug，
#   见 README「工具链 / bpfvm-ld -> 调试信息 (DWARF)」一节）

COMMON_LDFLAGS="-target bpf -nostdlib"

# 让 clang -target bpf 的链接前端（bpf-gcc）改用 bpfvm-ld，绕过 binutils bpf-ld。
# clang -target bpf 把链接委托给 /usr/bin/bpf-gcc，bpf-gcc 再用 /usr/lib/gcc/bpf/14/ld
# （binutils bpf-ld）。让它改用 bpfvm-ld 的三个坑：
#   -  clang 不把 -B 转发给 bpf-gcc（实测 -### 里没有 -B；-Wl,-B 传给 ld 也没用）；
#   -  -fuse-ld=bpfvm-ld 被 bpf-gcc 拒绝（只认 bfd/gold/lld）；
#   -  bpf-gcc 认 COMPILER_PATH 环境变量——但它对所有 gcc 生效（含 host gcc）。
# 两类程序区别对待：
#   - sbase/busybox：纯 bpf（无 host cc），直接给 make 设 COMPILER_PATH 即可。
#   - dash：用 CC_FOR_BUILD=gcc 编 host 代码生成器(mkinit/mksyntax/mknodes/mksignames)，
#     与 bpf shell(clang) 在一次 make 里交织——不能给整条 make 设 COMPILER_PATH（会污染
#     host gcc 的链接）。所以只 wrap clang：wrapper 内部 export COMPILER_PATH，bpf-gcc（clang
#     的子进程）继承得到，host gcc（make 直接调）沾不到。
# 共用一个 ld->bpfvm-ld 目录（COMPILER_PATH 指向它）；失败会直接报错，不再被 bpf-ld 静默替掉。
# 调用：make_ld_wrapper -> 设 LD_WRAPPER_DIR / CLANG_WRAPPER，并在 EXIT 时清理。
make_ld_wrapper() {
    LD_WRAPPER_DIR=$(mktemp -d -p "${ROOT_DIR}" bpfvm-ldpath.XXXXXX)
    ln -sf "${BPFVM_LD}" "${LD_WRAPPER_DIR}/ld"
    REAL_CLANG="$(command -v clang)"
    cat > "${LD_WRAPPER_DIR}/clang" <<EOF
#!/bin/bash
export COMPILER_PATH="${LD_WRAPPER_DIR}"
exec "${REAL_CLANG}" "\$@"
EOF
    chmod +x "${LD_WRAPPER_DIR}/clang"
    CLANG_WRAPPER="${LD_WRAPPER_DIR}/clang"
    trap 'rm -rf "${LD_WRAPPER_DIR}"' EXIT
}
