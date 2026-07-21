#!/bin/bash
# 构建 BPF target 的 C++ runtime（libcxx.a）。
#
# 由两部分组成：
#   1. libc++ 源文件（-frtti，LIBCXX_BUILDING_LIBCXXABI）：algorithm/string/vector/
#      regex/iostream/thread/filesystem 等 + exception.cpp（走官方 exception_libcxxabi.ipp，
#      用 cxa_noexception.cpp 的 __cxa_* 实现 exception_ptr/uncaught_exceptions）。
#   2. libc++abi 源文件（-frtti）：private_typeinfo（RTTI/dynamic_cast 全实现）、
#      cxa_noexception（-fno-exceptions 下的 __cxa_uncaught_exceptions 等）、
#      cxa_virtual（__cxa_pure_virtual）、cxa_handlers/cxa_default_handlers
#      （terminate/new_handler）、cxa_vector/cxa_demangle/fallback_malloc/abort_message、
#      stdlib_typeinfo/stdlib_exception/stdlib_stdexcept/cxa_aux_runtime、
#      cxa_guard（static 局部守卫，GlobalMutex 实现）、stdlib_new_delete（operator new/delete
#      20 个弱符号变体，含 nothrow/对齐版）。
#
# 用法：./scripts/build_libcxx.sh
# 产物：root/lib/libcxx.a（最终库安装到 root/lib，与 musl 的 libc.a/libc.so 同目录）
# 中间：build/libcxx_obj/*.o（编译对象，被 .gitignore 的 build/ 覆盖）
#
# 配合系统 clang 自带的 libc++ 头文件（header-only 部分）+ BpfLibcallLower pass，
# 支持 vector/string/map/sort/optional/expected/memory_resource/variant/
# unique_ptr/regex/iostream/thread/filesystem 等常用 STL。

set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
cd "${ROOT_DIR}"

# 探测 libc++ 头目录：让 clang 自己给（-print-file-name=include/c++/v1 直接返回
LIBCXX_INC=$(clang++ -print-file-name=include/c++/v1 2>/dev/null)
if ! [ -f "$LIBCXX_INC/vector" ]; then
    echo "libc++ headers not found: clang -print-file-name=include/c++/v1 -> '$LIBCXX_INC'" >&2
    exit 1
fi
echo "==> libc++ headers: $LIBCXX_INC"

mkdir -p root/lib build/libcxx_obj

# 编译 libc++ 源文件（algorithm/string/vector/regex/iostream/thread/...）。
# 这些源文件来自系统 libc++，用 STL_CXX_FLAGS（含 libc++ 头 + 绕过宏）编译。
# 探测 libc++ 源码目录。Debian 的 libc++-dev 包只装头和预编译 .a，不含 .cpp 源码，
# 故源码需手动提供（LLVM 源码 tarball 解压到 /tmp/llvm-toolchain-* 或类似位置）。
# 候选（取最新版本）：/tmp/llvm-toolchain-*/libcxx/src、/usr/local/llvm-*/src/libcxx 等。
LIBCXX_SRC=""
for p in $(ls -d /tmp/llvm-toolchain-*/libcxx/src /usr/local/llvm-*/src/libcxx /usr/lib/llvm-*/src/libcxx 2>/dev/null | sort -Vr); do
    if [ -f "$p/algorithm.cpp" ]; then LIBCXX_SRC="$p"; break; fi
done
# LIBCXX_BUILDING_LIBCXXABI：让 libc++ 源知道 ABI 库是 libc++abi（与下面编译的
#   libc++abi 源配对）。影响 3 个 libc++ 源：
#   exception.cpp  → 走 exception_libcxxabi.ipp + exception_pointer_cxxabi.ipp，
#     自动用 cxa_noexception.cpp 提供的 __cxa_uncaught_exceptions /
#     __cxa_increment/decrement_exception_refcount / __cxa_current_primary_exception /
#     __cxa_rethrow_primary_exception 实现 std::exception_ptr / uncaught_exceptions /
#     nested_exception。
#   new_handler.cpp → set/get_new_handler 交给 libc++abi cxa_default_handlers.cpp。
#   typeinfo.cpp → ~type_info 交给 libc++abi stdlib_typeinfo.cpp。
STL_CXX_FLAGS="-std=c++23 -target bpf -mcpu=v4 -O1 -fno-exceptions -frtti -fno-builtin -fno-math-errno \
    -mllvm -bpf-stack-size=16384 \
    -nostdinc \
    -D_GNU_SOURCE \
    -D_LIBCPP_HAS_THREAD_API_PTHREAD \
    -D_LIBCPP_HAS_MUSL_LIBC \
    -D_LIBCPP_HAS_NO_INT128 \
    -D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_NONE \
    -D_LIBCPP_BUILDING_LIBRARY \
    -DLIBCXX_BUILDING_LIBCXXABI \
    -isystem $LIBCXX_INC \
    -isystem root/include/ \
    -isystem include \
    -I $LIBCXX_SRC \
    -fpass-plugin=${PASS_LIBCALLLOWER} \
    -fpass-plugin=${PASS_WIDEARGS} \
    -fpass-plugin=${PASS_SOFTFP}"

OBJS=""
if [ -d "$LIBCXX_SRC" ]; then
    echo "==> libc++ sources detected: $LIBCXX_SRC"
    # 编译 $LIBCXX_SRC 下全部 .cpp，仅排除少数在 BPF 上编不过或有冲突的：
    #   charconv.cpp      — 浮点 to_chars 调 ryu/d2s.cpp 等（__multi3 int128 乘法，BPF
    #                       后端拒绝）；charconv.cpp 本身可编但浮点路径链接期缺 ryu 符号，
    #                       排除避免库带未定义引用。整数 to_chars 是 header-only，不受影响。
    #   new.cpp           — 与 stdlib_new_delete.cpp 的 operator new/delete 符号完全重叠
    #                       （二选一取 libc++abi 版的 stdlib_new_delete.cpp）。
    # memory_resource.cpp 靠 stdlib_new_delete 的对齐版 operator new/delete
    #   （St11align_val_t）满足 pmr 引用。expected.cpp 在 c++23 下
    # #if _LIBCPP_STD_VER >= 23 门控的声明可见（STL_CXX_FLAGS 已是 c++23）。
    # 其余全部纳入（algorithm/string/vector/regex/iostream/thread/memory_resource/expected/
    #   atomic/chrono/random/strstream/...）。fstream.cpp 编译为 0 符号（模板实例化被 #if 包），无副作用。
    EXCLUDE="charconv.cpp new.cpp"
    n=0
    for src in "$LIBCXX_SRC"/*.cpp; do
        b=$(basename "$src")
        case " $EXCLUDE " in *" $b "*) continue;; esac
        clang++ $STL_CXX_FLAGS -c "$src" -o "build/libcxx_obj/${b%.cpp}.o"
        OBJS="$OBJS build/libcxx_obj/${b%.cpp}.o"
        n=$((n+1))
    done
    echo "   [OK] libc++ sources ($n, excluded: $EXCLUDE)"

    # filesystem 子系统（解锁 <filesystem>）。编译 $LIBCXX_SRC/filesystem/ 下全部 .cpp。
    # 关键：必须配合 -D_LIBCPP_HAS_NO_INT128（见上 STL_CXX_FLAGS）——BPF 后端不支持
    #   __int128 乘除法（__multi3/__divti3/__muloti4），而 file_clock::rep 默认是
    #   __int128_t。定义该宏让 rep 退化为 long long；int128_builtins.cpp 整体被 #if 包裹，
    #   定义后变空 TU（不产 __muloti4 符号，也无冲突）。
    for src in "$LIBCXX_SRC"/filesystem/*.cpp; do
        b=$(basename "$src")
        clang++ $STL_CXX_FLAGS -c "$src" -o "build/libcxx_obj/fs_${b%.cpp}.o"
        OBJS="$OBJS build/libcxx_obj/fs_${b%.cpp}.o"
    done
    echo "   [OK] filesystem"
else
    echo "==> libc++ sources not found (only stub will be in libcxx.a)" >&2
    exit 1
fi

# 编译 libc++abi 源文件，提供 C++ RTTI runtime（typeid/dynamic_cast）+ no-exception
# 运行时（__cxa_uncaught_exceptions 等）+ terminate/new_handler。
# libc++abi 用 -frtti 编（必须，否则 typeinfo vtable 不发）；上面 libc++ 源也用 -frtti
# （库符号的 vtable/typeinfo 必须与用户代码 RTTI 设置匹配，否则跨模块引用 typeinfo 会 undefined）。
# 探测 libc++abi 源码目录（同 LIBCXX_SRC，Debian 包不含源码，取最新版本 tarball）。
# 候选优先用 LIBCXX_SRC 的同级目录（tarball 里 libcxx/libcxxabi 并列），再回退到通配符扫描。
LIBCXXABI_SRC=""
if [ -n "$LIBCXX_SRC" ] && [ -f "$LIBCXX_SRC/../libcxxabi/src/private_typeinfo.cpp" ]; then
    LIBCXXABI_SRC="$LIBCXX_SRC/../libcxxabi/src"
fi
if [ -z "$LIBCXXABI_SRC" ]; then
    for p in $(ls -d /tmp/llvm-toolchain-*/libcxxabi/src /usr/local/llvm-*/src/libcxxabi/src /usr/lib/llvm-*/src/libcxxabi/src 2>/dev/null | sort -Vr); do
        if [ -f "$p/private_typeinfo.cpp" ]; then LIBCXXABI_SRC="$p"; break; fi
    done
fi
if [ -n "$LIBCXXABI_SRC" ]; then
    LIBCXXABI_INC=$(cd "$LIBCXXABI_SRC/../include" && pwd)
    # ABI_FLAGS = STL_CXX_FLAGS（已是 -frtti + -I $LIBCXX_SRC）+ libc++abi include
    # （__cxxabi_config.h / cxxabi.h，cxa_aux_runtime.cpp 用；stdlib_stdexcept.cpp 的
    # #include "include/refstring.h" 由 -I $LIBCXX_SRC 解析）+ clang resource include
    # （unwind.h——cxa_exception.h 无条件 include，cxa_noexception.cpp 经它引入）。
    CLANG_INC="$(clang++ -print-resource-dir)/include"
    ABI_FLAGS="$STL_CXX_FLAGS -isystem $LIBCXXABI_INC -isystem $CLANG_INC"
    echo "==> libc++abi sources detected: $LIBCXXABI_SRC"
    # 编译 $LIBCXXABI_SRC 下全部 .cpp，仅排除在 BPF 上编不过的：
    #   cxa_exception.cpp          — 有异常版 __cxa_*（__cxa_throw/allocate_exception/...），
    #                                 与 cxa_noexception.cpp 的无异常版 9 个符号重复且语义冲突，
    #                                 -fno-exceptions 下用 cxa_noexception.cpp。
    #   cxa_exception_storage.cpp  — __cxa_get_globals（异常线程本地存储），-fno-exceptions 下
    #                                 无引用，纳入是死代码。
    #   cxa_personality.cpp        — 含 throw，-fno-exceptions 下编不过；异常人格函数，不需要。
    #   cxa_thread_atexit.cpp      — 用 __thread 原生 TLS，BPF 不支持，编不过。
    ABI_EXCLUDE="cxa_exception.cpp cxa_exception_storage.cpp cxa_personality.cpp cxa_thread_atexit.cpp"
    n=0
    for src in "$LIBCXXABI_SRC"/*.cpp; do
        b=$(basename "$src")
        case " $ABI_EXCLUDE " in *" $b "*) continue;; esac
        clang++ $ABI_FLAGS -c "$src" -o "build/libcxx_obj/abi_${b%.cpp}.o"
        OBJS="$OBJS build/libcxx_obj/abi_${b%.cpp}.o"
        n=$((n+1))
    done
    echo "   [OK] libc++abi ($n, excluded: $ABI_EXCLUDE)"
else
    echo "==> libc++abi sources not found (RTTI runtime required)" >&2
    exit 1
fi

# 打成静态库。先清空旧 .a：ar rcs 不会删除已存在但本次未列出的成员，
# 否则上次构建的陈旧 .o（如旧 pass 编的）会残留累积。
echo "==> creating root/lib/libcxx.a"
rm -f root/lib/libcxx.a
ar rcs root/lib/libcxx.a $OBJS
echo "==> done: root/lib/libcxx.a ($(wc -c < root/lib/libcxx.a) bytes)"
