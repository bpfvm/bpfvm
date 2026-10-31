#!/bin/bash
# 构建 CPython 3.13 for BPF（交叉编译：动态 PIE 主程序 + lib-dynload 动态扩展）。
# 由 scripts/build_root.sh python 调用，也可单独执行。
#
# 产物：root/bin/python3.13（动态 PIE，DT_NEEDED libc.so/libssl.so/libcrypto.so，
#       导出全部非 hidden 全局符号——动态扩展的 Py* UND 向它解析）
#       + root/lib/python3.13/（stdlib .py + lib-dynload/*.so 动态扩展）
#       + root/include/python3.13/ + root/lib/libpython3.13.a。
# 两步：先用系统工具链编宿主 build python（--with-build-python 要求与目标版本
# 完全一致，交叉构建期用它生成 frozen modules / 运行构建脚本），再交叉 configure+make。
# 交叉探测缓存见 scripts/config.site-bpf（CONFIG_SITE）。
# 源码：thirdparty/cpython/ 缺失时自动 git clone v3.13.1 并应用
#       patches/cpython-3.13.1-bpfvm.patch（幂等）。
#
# 依赖：基础构建（root/lib/libc.so + root/include 的 musl 头）与 openssl 组件
# （--with-openssl=root）；zlib 组件可选（缺失则 configure 不编 zlib 模块）。
set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
make_ld_wrapper
require_base

# _ctypes 依赖 ffi 组件(root/lib/libffi.{a,so} + pkgconfig/libffi.pc);
# 未构建时 configure 探测不到 libffi,静默跳过 _ctypes 模块
if [ ! -f "${ROOT_DIR}/root/lib/pkgconfig/libffi.pc" ]; then
    echo "提示: root/lib/pkgconfig/libffi.pc 不存在,先跑 ./scripts/build_root.sh ffi,否则 _ctypes 不会编译" >&2
fi

PY_SRC="${ROOT_DIR}/thirdparty/cpython"
HOST_INSTALL="${ROOT_DIR}/build/python-host-install/opt/py313-build"
BUILD_DIR="${ROOT_DIR}/build/python-bpf"
PREFIX="${ROOT_DIR}/root"

# 缺失时克隆 v3.13.1（bpfvm patch 是 3.13.1 专属，必须锁 tag）；随后应用 patch
# （--forward 幂等：已应用时跳过不报错）
clone_if_missing "${PY_SRC}" https://github.com/python/cpython.git v3.13.1
patch -d "${PY_SRC}" -p1 --forward \
    < "${ROOT_DIR}/patches/cpython-3.13.1-bpfvm.patch" >/dev/null || true

# 宿主 build python：一次性构建，之后复用 build/python-host-install
if [ ! -x "${HOST_INSTALL}/bin/python3.13" ]; then
    echo "=== python: 构建 host build-python (3.13.1) ==="
    mkdir -p "${ROOT_DIR}/build/python-host"
    cd "${ROOT_DIR}/build/python-host"
    "${PY_SRC}/configure" --prefix=/opt/py313-build
    make -j"${JOBS}"
    make install DESTDIR="${ROOT_DIR}/build/python-host-install"
    cd "${ROOT_DIR}"
fi

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

echo "=== python: configure (bpf-unknown-linux) ==="
# CFLAGS 在 CFLAGS_NOG（COMMON_CFLAGS 去 -g，见 env.sh）基础上：
#   -DTHREAD_STACK_SIZE=0x1000000：musl 默认 128KB 不足，16MB 线程栈足够
#   worker 跑完整解释器调用链 + Py_C_RECURSION_LIMIT 深度。
#   -Wno-error：pass 改写 IR 后部分 warning 与源码字面类型不一致。
# emutls：CPython 3.13 的 _Py_thread_local 按编译期判定展开（thread_local 宏 ->
# _Thread_local -> __thread 三级都会被 clang 对 BPF 目标拒绝）。clang 对纯 extern
# 声明不生成 annotate 元数据，跨 TU 引用侧无法被 pass 识别，故只在定义侧
# pystate.c（_Py_tss_tstate 的唯一定义/写点）经 Makefile 追加规则注入
# -Dthread_local=annotate("emutls")（宏预处理期替换，Sema 见不到 TLS 关键字），
# BpfEmutls pass 改写为 __emutls_get_address 调用（运行时在 musl emutls.c）。
# 引用侧（pyport.h 的 __BPF__ 分支）走 PyThread_tss 回退读 tstate。
# emutls pass 插件全局注入（对无 annotate 源是 no-op）。
PY_CFLAGS="-std=gnu11 ${CFLAGS_NOG}"
if [ -f "${ROOT_DIR}/build/libBpfEmutls.so" ]; then
    PY_CFLAGS="${PY_CFLAGS} -fpass-plugin=${ROOT_DIR}/build/libBpfEmutls.so"
fi
# mimalloc 用裸 _Thread_local/__thread（宏替换覆盖不到），禁用走 pymalloc；
# 帧上限 384KB（libmpdec transpose 的 buf1/buf2 两个 128x128 u64 缓冲即 256KB）。
# PKG_CONFIG_LIBDIR 指向目标侧空目录：隔断宿主 .pc（否则 pkg-config 探到宿主
# zlib -> 误开 binascii 的 USE_ZLIB_CRC32，-nostdinc 下 zlib.h 必然找不到）
PY_CFLAGS="${PY_CFLAGS//-bpf-stack-size=16384/-bpf-stack-size=393216}"
PY_CFLAGS="${PY_CFLAGS} -DTHREAD_STACK_SIZE=0x1000000 -Wno-error"
export PKG_CONFIG_LIBDIR="${PREFIX}/lib/pkgconfig"

# CPPFLAGS：configure 的 $CPP 探测（platform_triplet 等）默认按 host 预处理，
# 会把目标误判成 x86_64-linux-gnu（perf trampoline 误开）。带上与 CFLAGS 一致的
# target/头路径，让 __BPF__/musl 特征可见。
# MODULE_BUILDTYPE=shared + LIBS=-l:libc.so + LDSHARED/BLDSHARED 直指 bpfvm-ld：
#   - stdlib C 扩展编译为 lib-dynload/*.so，import 时经 guest ldso dlopen；
#     扩展的 Py* UND 符号向主程序解析（DYNAMIC_EXE 导出全部非 hidden 全局符号）。
#   - 主程序链 libc.so（而非 libc.a）：libc.a 里的 dlopen 是弱桩（stub_dlopen，
#     "Dynamic loading not supported"），真 dlopen 只在 ld-bpf.so；静态链入即
#     无法动态加载扩展。
#   - bpf-gcc 驱动会把 -shared 吞掉不传给 ld（实测 collect2 参数里没有），
#     LDSHARED 绕开驱动直接调 bpfvm-ld -shared；-L 补库搜索路径（扩展链接
#     行只带 MODULE_*_LDFLAGS 的 -lm/-lssl 等，无 LIBS 的 -L）。
# --prefix=/ 是 guest 内的运行期路径（烧进二进制；宿主绝对路径在 guest 不存在，
#     会让无 PYTHONHOME 的启动找不到 stdlib）；安装落点由 make install 的 DESTDIR 决定。
CONFIG_SITE="${ROOT_DIR}/scripts/config.site-bpf" \
MODULE_BUILDTYPE=shared \
CFLAGS="${PY_CFLAGS}" \
CPPFLAGS="-target bpf -mcpu=v4 -nostdinc -isystem ${PREFIX}/include -isystem ${CLANG_RES}" \
LDFLAGS="${COMMON_LDFLAGS}" \
LIBS="-L${PREFIX}/lib -l:libc.so" \
LDSHARED="${BPFVM_LD} -shared -L${PREFIX}/lib" \
BLDSHARED="${BPFVM_LD} -shared -L${PREFIX}/lib" \
CC="${CLANG_WRAPPER}" \
CC_FOR_BUILD="gcc" \
AR="ar" \
RANLIB="ranlib" \
"${PY_SRC}/configure" \
    --build=x86_64-linux-gnu \
    --host=bpf-unknown-linux \
    --prefix=/ \
    --with-build-python="${HOST_INSTALL}/bin/python3.13" \
    --disable-test-modules \
    --without-ensurepip \
    --without-mimalloc \
    --with-openssl="${PREFIX}" \
    --with-openssl-rpath=no
# Makefile 的 OPT 行自带 -g（configure 生成）：LLVM #213714（-target bpf -g 对
# 部分函数声明 ICE，expat 即触发），剥掉
sed -i 's/\(OPT=\t*-DNDEBUG\) -g /\1 /' Makefile

# _Py_tss_tstate 的定义独占 pystate.c:per-target 注入 emutls(thread_local ->
# annotate)。其余 TU 无该宏,pyport.h 的 __BPF__ 分支走 PyThread_tss 回退
echo "Python/pystate.o: PY_CORE_CFLAGS += -DBPFVM_EMUTLS_TSTATE -Dthread_local='__attribute__((annotate(\"emutls\")))'" >> Makefile

echo "=== python: make ==="
make -j"${JOBS}"
[ -x "${BUILD_DIR}/python" ] || { echo "[build_python] 未产出 python 二进制" >&2; exit 1; }

echo "=== python: install 到 root/ ==="
make install DESTDIR="${PREFIX}"
ln -sf python3.13 "${PREFIX}/bin/python3"

# pip：交叉构建下 ensurepip 无效（make install 用宿主 build-python 跑它，宿主自身
# 已装 pip，ensurepip 判定已安装直接跳过，装不进 DESTDIR），故禁用 ensurepip、
# 这里直接解包宿主 build-python 捆绑的 pip wheel（纯 Python，跨目标通用）
PIP_WHEEL=$(ls "${HOST_INSTALL}"/lib/python3.13/ensurepip/_bundled/pip-*.whl | head -1)
mkdir -p "${PREFIX}/lib/python3.13/site-packages"
unzip -qo "${PIP_WHEEL}" -d "${PREFIX}/lib/python3.13/site-packages/"
echo "pip: $(basename "${PIP_WHEEL}") -> site-packages/"

# 预编译字节码（发行版惯例）：宿主 build-python 与目标同版本，pyc 跨平台通用。
# checked-hash 校验不依赖 mtime（同步目录时间戳漂移安全），也免去 guest 首次
# import 现场编译+回写 pyc（实测 pip import 26.7s -> 12.2s）
"${HOST_INSTALL}/bin/python3.13" -m compileall -q -j "$(nproc)" \
    --invalidation-mode checked-hash "${PREFIX}/lib/python3.13"
echo "done: root/bin/python3.13 + root/lib/python3.13/ + include/python3.13/ + libpython3.13.a"
