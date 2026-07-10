# C++ 与 STL 支持现状

> 目标：在 bpfvm 上提供可用的 C++ 语言子集与 libc++ STL 子集。
> 本文描述**当前状态**（编译/链接/运行时如何工作、支持什么、不支持什么），不是进度日志。

## 1. 语言子集

bpfvm 支持 `clang++ -target bpf -fno-exceptions -frtti` + musl C 运行时的 C++ 子集。

**可用**（无需 C++ 运行时）：
- 模板、类/结构体、构造/析构、单继承、虚函数（vtable 分派）。
- 命名空间、`constexpr`、函数重载、引用、`auto`、lambda（含捕获）。
- `operator new`/`operator delete`（落 musl `malloc`/`free`，mangle 成 `_Znwm`/`_ZdlPv`）。
- 全局对象构造/析构：链接器合成 `.init_array`/`.fini_array` 边界符号
  （`__init_array_start/end`、`__fini_array_start/end`、`__dso_handle`），复用 musl 的
  `__libc_start_init`/`__libc_exit_fini` 循环，无 loader/VM 改动。
- emutls（`thread_local` 等价）：`__mythread` 宏（`address_space(256)`）+ `BpfEmutls` pass
  + VM 运行时（复用 FP 通道 `BPF_FP_EMUTLS_GET_ADDR`）。
- RTTI：`typeid`、`type_info::name()`/`hash_code()`/`operator==`/`before`、`dynamic_cast`
  （单/多继承、交叉转换、深度链、`nullptr`、无关类返回 null）。

**不支持**：
- **异常**：`throw`/`try`/`catch` —— 编译期被禁（`-fno-exceptions`）。`cxa_throw`/
  `cxa_personality`/libunwind 未移植。可行性调研见末节。
- **`thread_local` 关键字**：clang Sema 对 BPF target 拒绝；必须用 `__mythread` 宏。
- **取 emutls 变量地址**（`&var`）：编译错误（地址空间不匹配）。
- **跨 TU 的 `extern __mythread`**：不支持（控制块内部链接）。

### ABI 限制与对应的 LLVM pass

BPF 后端有三条硬限制（`BPFISelLowering.cpp` 拒绝），全部由 `src/passes/BpfWideArgs.cpp`
的 pass 透明消除，使代码可写标准 C++：

| 限制 | 根因 | 消除方式 |
|---|---|---|
| >5 参数 | "stack arguments are not supported" | `BpfWideArgsPass` 把第 5 参起 pack 成结构体经 `r5` 指针传 |
| 结构体返回 | "aggregate returns are not supported"（拒绝 `sret`） | `stripSret` 剥 `sret` 属性 |
| 变参 `...` | "variadic functions are not supported" | 改写 callee 加 `__va_base` 指针参数 + caller 在入口栈构造 vararg 包 + `va_start`/`va_arg`/`va_copy` intrinsic 降级 |

**按值传聚合参数**（C++ 最基础模式 `f(string)`/`f(vector)`/`f(pair)`）由 `lowerAggregateParams`
统一归一化：clang 把聚合按值参数分两路——
- 大聚合（≥3 word，如 `std::string` 24B）：clang 已 lower 成 `ptr byval(%T)`，两端本就是
  指针语义，pass 只剥 `byval` 属性（路径 A，覆盖直接/间接调用与外部声明 callee）。
- 小聚合（≤2 word，如 `std::pair`、`__bit_iterator=[2 x i64]`、`i128`）：clang 用聚合值
  类型，BPF 后端按字段展开成多个寄存器（`[2 x i64]` 占 2 个），易突破 5 寄存器上限。
  pass 重建签名为裸 `ptr`（恒占 1 寄存器）+ 入口 `load` 重建值 + call site `alloca`+`store`
  传指针（路径 B，直接产出裸 `ptr`，不造瞬态 `byval`）。

降级判据 `needsLowering`：聚合类型（`ArrayType`/`StructType`，按构成展开），或 `i128`
及更大标量（拆成 2 个 64 位寄存器）。排除指针、≤64 位标量。

**按值传 ≤8B 非平凡析构参数（`unique_ptr`）**：clang BPF 后端有 bug（
https://github.com/llvm/llvm-project/issues/207686 ，clang 19→23 trunk 全复现，两年未修）——
把 ≤8B 非平凡析构按值参数直接降级成 `i64`，但前端仍按 Itanium 不可见引用 ABI 在 caller
建备份临时并析构，callee 无法在 move-out 时置空临时 → double-free。`BpfByvalTmpPass`
（`eliminateByvalScalarTemporaries`）识别备份临时模式，在 caller 析构前插 `store null`
恢复语义。保守识别 + `getTypeAllocSize(tmp) > 8` 跳过（本 pass 只处理 ≤8B 的 i64 化参数，
即 `unique_ptr` 8B；string/shared_ptr 等大对象走 byval/ptr 共享路径，不受影响）。

### 其它必需 pass

- **`BpfLibcallLower`**（`src/passes/BpfLibcallLower.cpp`）：把 `@llvm.memcpy`/`memmove`/
  `memset`/`trap` + `floor`/`ceil`/`trunc`/`round` 改写成对 musl 函数的普通 call。`-fno-builtin`
  只阻止"libc 调用变 builtin"，不阻止"结构体隐式拷贝/数学优化变 intrinsic"，后者会被 BPF 后端
  ISel 拒绝。`OptimizerLastEP`（让优化器先消除可内联的小拷贝）+ `-O0` 兜底。floor 等数学
  intrinsic 改写从 `BpfSoftFp` 迁入。
- **`BpfAtomicLower`**（`src/passes/BpfWideArgs.cpp`）：把 `load atomic`/`store atomic` 降级
  为普通 `load`/`store`。**eBPF ISA 只有 RMW 类原子**（`atomic_add`/`xchg`/`cmpxchg`，全
  `SEQ_CST`），**无独立 plain atomic load/store 指令**（LLVM 21 才由 `BPF_LOAD_ACQ`/
  `STORE_REL` 补上，本项目用 LLVM 19）。`AtomicRMW`/`AtomicCmpXchg` 不动（后端原生支持）。
- **`BpfSoftFp`**：浮点软化（C++ STL 用到浮点比较，如 `sort`/`unordered_map` rehash 的
  `ceilf`），含 `fabs`/`copysign`（走 VM 虚拟指令）；`floor`/`ceil`/`trunc`/`round` 已迁到
  `BpfLibcallLower`。
- **`BpfEmutls`**：emutls，见上。

> **pass 重建后必须全量重编** musl（`find musl/build/obj -name '*.o' -delete && sh musl/build.sh`）
> → 重建 `libc.so` → `sh libcxx/build.sh` → `make -C test`。Make/CMake 的 musl/libcxx 构建只
> 看 `.c` 源码 mtime，不跟踪 `.so` 时间戳。

## 2. STL 子集（libc++ + `libcxx_bpf.a`）

musl `libc.a` 不含任何 C++ runtime 符号。本项目用系统自带的 libc++ 头文件（header-only 部分）
+ 自建的极简静态库 `libcxx/lib/libcxx_bpf.a` 提供库符号。

### libc++ 头配置

`#include <vector>` 之类需要绕过 libc++ `__config` 的若干检查。在 `test/Makefile` 的
`CXX_FLAGS` 和 `libcxx/build.sh` 的 `STL_CXX_FLAGS` 里统一用命令行 `-D` 宏（**不用**
`__config_site` 头——实测经 `-isystem` 配置后未被 `__config` 自动 include）：

| 宏 | 作用 |
|---|---|
| `_LIBCPP_HAS_THREAD_API_PTHREAD` | 直接定义 pthread 线程后端，短路 `__config` 的线程 API 自动探测（BPF target 无 `__linux__` 等 OS 宏，否则 `#error "No thread API"`）。让 `<thread>`/`<mutex>`/`<future>` 走 musl pthread |
| `_LIBCPP_HAS_MUSL_LIBC` | 派生 musl 的 rune table，解锁 `<__locale>` |
| `_LIBCPP_HAS_NO_INT128` | 关闭 libc++ 的 `__int128` 支持。BPF 后端不支持 `__int128` 乘除法（`__multi3`/`__divti3`/`__muloti4`，ISel 拒绝），而 `file_clock::rep` 默认是 `__int128_t`（`__chrono/file_clock.h` 的 `#if !defined(_LIBCPP_HAS_NO_INT128)`）。定义该宏让 `file_clock::rep` 退化为 `long long`，`<filesystem>` 的时间戳运算链不再触发后端拒绝；`int128_builtins.cpp` 整体被 `#if` 包裹变空 TU（不产 `__muloti4` 符号，无冲突） |
| `_LIBCPP_HARDENING_MODE=...NONE` | 关 libc++ 硬化检查 |
| `_LIBCPP_BUILDING_LIBRARY` | 编译 libc++ 源码时用（仅 `libcxx/build.sh`） |
| `_GNU_SOURCE` | 让 musl 头暴露 `locale_t` 等 |

`-isystem` 顺序：**libc++ 头在 musl 之前**（cstddef 的 `#include_next <stddef.h>` 要求
libc++ 的 `stddef.h` 先找到再串到 musl）。探测 libc++ 头时排除 `wasm32-wasi`（ABI
namespace 是 `__2`，与用户代码 `__1` 不匹配会链接报 undefined）。ABI namespace 用系统
`__config_site` 的默认 `__1`，两边都不显式设 `_LIBCPP_ABI_NAMESPACE`。

### `libcxx_bpf.a` 组成（`libcxx/build.sh`）

全量编译 + 排除少数编不过/冲突的，`set -e` 保证失败即退出（无 try/skip）。由两部分组成：

1. **libc++ 源文件**（`-std=c++23 -frtti -DLIBCXX_BUILDING_LIBCXXABI`，与用户代码 RTTI/语言
   版本设置一致，否则库符号的 typeinfo 不发会导致跨模块引用 undefined）：全量编译
   `$LIBCXX_SRC/*.cpp` + `$LIBCXX_SRC/filesystem/*.cpp`，仅排除 3 个——
   `barrier`（1 字节 `AtomicCmpSwap`，BPF 后端只支持 32/64 位原子，编不过）、
   `charconv`（浮点 `to_chars` 调 ryu 子目录源，ryu 用 `__multi3` int128 乘法编不过；纳入会让库带未定义引用）、
   `new`（与 `stdlib_new_delete.cpp` 符号完全重叠，二选一取 libc++abi 版）。
   纳入 43 个 + filesystem 7 个，覆盖 algorithm/string/vector/regex/iostream/thread/
   memory_resource/expected/atomic/chrono/random/strstream/... 全部库符号。
   `LIBCXX_BUILDING_LIBCXXABI` 让 `exception.cpp` 走 `exception_libcxxabi.ipp` +
   `exception_pointer_cxxabi.ipp`，自动用 libc++abi 的 `__cxa_uncaught_exceptions`/
   `__cxa_increment/decrement_exception_refcount`/`__cxa_current_primary_exception`/
   `__cxa_rethrow_primary_exception`（来自 `cxa_noexception.cpp`）实现
   `std::exception_ptr`/`uncaught_exceptions`/`nested_exception`。同理 `new_handler.cpp`
   的 `set/get_new_handler`、`typeinfo.cpp` 的 `~type_info` 交给 libc++abi 提供。
2. **libc++abi 源文件**（`-frtti`）：全量编译
   `$LIBCXXABI_SRC/*.cpp`，仅排除 4 个——
   `cxa_exception`（有异常版 `__cxa_*`，与 `cxa_noexception` 的无异常版 9 个符号重复且语义冲突）、
   `cxa_exception_storage`（`__cxa_get_globals`，`-fno-exceptions` 下无引用，死代码）、
   `cxa_personality`（含 throw，编不过）、`cxa_thread_atexit`（`__thread`，编不过；
   且 emutls 不为 `addrspace(256)` 全局登记析构，纳入无意义，见「emutls 限制」）。
   纳入 15 个，覆盖：`private_typeinfo`（`__dynamic_cast` 全实现 + 76 个基本 typeinfo 对象）、
   `cxa_noexception`（`-fno-exceptions` 下的 `__cxa_uncaught_exceptions` 等）、
   `cxa_virtual`（`__cxa_pure_virtual`）、`cxa_handlers`/`cxa_default_handlers`
   （terminate/new_handler）、`cxa_vector`/`cxa_demangle`/`fallback_malloc`/`abort_message`、
   `stdlib_typeinfo`/`stdlib_exception`/`stdlib_stdexcept`/`cxa_aux_runtime`、
   `cxa_guard`（static 局部初始化守卫，GlobalMutex 实现，见「`__cxa_guard_*` 线程安全」）、
   `stdlib_new_delete`（20 个 operator new/delete 弱符号变体，含 nothrow/对齐版，见「`__start_/__stop_` section 边界符号」）。

### 已验证可用的 STL

| 类别 | 头 | 状态 |
|---|---|---|
| 顺序容器 | `<vector>` `<deque>` `<list>` `<forward_list>` `<array>` `<queue>` `<stack>` `<priority_queue>` | ✅ |
| 关联容器 | `<map>` `<set>` `<unordered_map>` `<unordered_set>` | ✅（hash 容器需 `ceilf` 软化） |
| 字符串 | `<string>` 拼接/`c_str`/size/比较 | ✅ |
| 算法 | `<algorithm>` sort/accumulate/find/copy | ✅ |
| 内存 | `<memory>` `unique_ptr`/`make_unique`/`shared_ptr` | ✅（含按值传 `unique_ptr`） |
| 内存资源 | `<memory_resource>` `monotonic_buffer_resource`/`unsynchronized_pool_resource`/`synchronized_pool_resource`/`new_delete_resource`/`null_memory_resource`/`get/set_default_resource`/`polymorphic_allocator`+`pmr::vector` | ✅（pmr 内部用对齐版 `operator new(size_t, std::align_val_t)`，由 `stdlib_new_delete.cpp` 提供对齐变体） |
| 工具 | `<optional>` `<expected>`(C++23) `<variant>` `<tuple>` `<utility>` `<type_traits>` `<bitset>`（count/set/reset/flip/位运算/移位/to_string/64 位跨 word） | ✅（`<expected>` 需 C++23：默认 `-std=c++23`（见下），`and_then`/`or_else`/`transform` 单子操作、`expected<void,E>` 全过） |
| 函数对象 | `<functional>` `function` + lambda | ✅ |
| 随机 | `<random>` `mt19937` | ✅ |
| 正则 | `<regex>` match/search/replace、捕获组、`sregex_iterator`/`sregex_token_iterator`、量词/锚点/字符类/反向引用/交替、icase、`wregex` | ✅ |
| 流 | `<iostream>` cout/cerr + `<sstream>` ostringstream/istringstream + `endl`/`hex`/`dec`/`setw` | ✅（cin 在无 stdin 时为 eof，已容错） |
| 线程 | `<thread>` `<mutex>` `<shared_mutex>`/`<shared_lock>` `<future>` `<condition_variable>` std::thread/join、mutex/lock_guard、async+future、promise、condition_variable、call_once、hardware_concurrency | ✅ |
| 文件系统 | `<filesystem>` path 构造/迭代/分解、current_path get/set、create_directory/directories、exists/is_directory/is_regular_file、file_size、directory_iterator/recursive_directory_iterator、create_symlink/read_symlink/is_symlink/symlink_status、create_hard_link/hard_link_count、rename、remove/remove_all、copy（目录递归）、permissions/status、last_write_time、weakly_canonical/canonical、temp_directory_path、directory_entry::path/status | ✅（`copy_file`/`space()` 降级，见下） |
| RTTI | `<typeinfo>` typeid/type_info 成员、`dynamic_cast` | ✅（`-frtti`） |

每个 STL 测试跑 5 个 ctest 变体：static/dynamic × JIT/interp + host 对照基线。

### 未覆盖

| 项 | 原因 |
|---|---|
| `<filesystem>` 的 `copy_file` | libc++ `copy_file_impl` 编译期固定走 `::sendfile`（`_LIBCPP_FILESYSTEM_USE_SENDFILE`，因 musl 有 `<sys/sendfile.h>`），VM 未实现 `sendfile` syscall（`BPF_CALL_BASE` 占位 → ENOSYS）→ `copy_file` 返回错误。`copy`（目录）对子目录仍可用，仅文件复制失败。后续可补 `BPF_SYS_SENDFILE`（转发 host sendfile，guest fd→host fd）解除 |
| `<filesystem>` 的 `space()` | libc++ `__space` 调 `::statvfs` → musl `statvfs` → `syscall(SYS_statfs)`，VM 未实现 `statfs`/`fstatfs`（ENOSYS）→ `space()` 返回 capacity/free/available = `(uintmax_t)-1`。后续可补 `BPF_SYS_STATFS`/`BPF_SYS_FSTATFS` 解除 |
| `<barrier>` | libc++ `__arrive_barrier_algorithm_base` 用 1 字节 `AtomicCmpSwap`（`acq_rel acquire (s8)`），BPF 后端只支持 32/64 位原子（"unsupported atomic operation, please use 32/64 bit version"）。这是 eBPF ISA 限制（LLVM 21 才由 `BPF_LOAD_ACQ`/`STORE_REL` 补独立 plain atomic；本项目用 LLVM 19），编译期硬阻塞。 |
| `<charconv>` 的浮点 `to_chars` | libc++ 浮点 `to_chars` 调 `ryu/d2s.cpp`/`f2s.cpp`/`d2fixed.cpp`，后者用 `__multi3`（`__int128` 乘法），BPF 后端拒绝（"A call to built-in function '__multi3' is not supported"）。`charconv.cpp` 因此整体排除（否则库带未定义的 ryu 引用）。整数 `to_chars`/`to_chars_result` 是 header-only，不受影响可直接用。解除需把 ryu 的 int128 乘法软化（或定义 `_LIBCPP_HAS_NO_INT128` 让 ryu 走窄整型回退路径——待验证）。 |
| `<format>` (C++20) | "too many arguments" 已由 `lowerAggregateParams` 消除，但遇下一个 BPF 后端限制（`Do not know how to expand this operator's operand`，疑似向量/i128 展开），暂缓 |
| 异常 `throw`/`try`/`catch` | `-fno-exceptions`，见下节 |

> libc++ 源排除清单（`libcxx/build.sh` 的 `EXCLUDE`）：`barrier.cpp`（上）、`charconv.cpp`
> （上）、`new.cpp`（与 `stdlib_new_delete.cpp` 符号完全重叠，二选一取 libc++abi 版）。
>
> libc++abi 源排除清单（`ABI_EXCLUDE`）：`cxa_exception.cpp`（有异常版 `__cxa_*`，与
> `cxa_noexception.cpp` 的无异常版 9 个符号重叠且语义冲突）、`cxa_exception_storage.cpp`
> （`__cxa_get_globals`，`-fno-exceptions` 下无引用，死代码）、`cxa_personality.cpp`（含
> throw/try，`-fno-exceptions` 编不过）、`cxa_thread_atexit.cpp`（`__thread` 原生 TLS，编不过）。

### `<memory_resource>` 启用要点

`memory_resource.cpp` 引用对齐版 operator new/delete（`_ZnwmSt11align_val_t`/
`_ZdlPvmSt11align_val_t`），由 `stdlib_new_delete.cpp` 提供（20 个弱符号变体，落 musl
`aligned_alloc`）。对齐退化为 16——BPF 上最大自然对齐类型 `long double`/`double` 即 8/16，
VM mmap 本就页对齐。

### `<expected>` (C++23) 启用要点

`<expected>` 整体被 libc++ 的 `#if _LIBCPP_STD_VER >= 23` 门控，必须用 `-std=c++23`。
项目默认即 c++23（`libcxx/build.sh` 的 `STL_CXX_FLAGS`、`test/Makefile` 的 `CXX_FLAGS`/
`HOST_CXXFLAGS` 均是），`expected.cpp` 随主循环编译。c++23 是 c++20 的超集，现有测试无回归。

`expected<T,E>` 主体全是模板（在用户 TU 实例化），库只补 `bad_expected_access` 的
vtable/typeinfo/`what()`（`-fno-exceptions` 下抛出路径走 `_LIBCPP_VERBOSE_ABORT`，故 `what`
符号仍需链接）。跨语言版本链接无碍（符号 mangling 不依赖 `-std`）。

**host 对照例外**：`test_stl_expected.host` 单独用 `clang++ -stdlib=libc++`（而非默认 g++/libstdc++）——
Debian 12 的 gcc 12 自带 libstdc++ 还没有 `expected::transform`/`or_else`/`and_then`，而 clang 19
自带 libc++ 有完整支持，与 BPF 端同源。其余 C++ 测试的 host 对照仍用 g++。

### `__cxa_guard_*` 线程安全

static 局部变量初始化守卫（`__cxa_guard_acquire`/`release`/`abort`）由 libc++abi 的
`cxa_guard.cpp` 提供（GlobalMutex 实现：`pthread_mutex` + `pthread_cond`，底层 musl 走 futex）。
`test/test_cpp_guard.cpp` 验证多线程并发下 static 只构造一次、构造期间其它线程阻塞。

`cxa_guard_impl.h` 的 `#elif defined(SYS_futex)` 分支用裸 `syscall(SYS_futex, int* addr, ...)`
传指针。BPF 的 `syscall` 是宏（`__bpf_syscallN`，定参 `long`），C++ 下 `int*`→`long` 是硬错误
（C 下是 `-Wint-conversion` 警告，pragma 可抑制；C++ 不能）。`musl/arch/bpf/bits/syscall.h.in`
加 `#ifdef __cplusplus` 的指针重载（任一参为 `void*` 时命中，经 `intptr_t` 转 `long`），仅 C++ 生效
（C 不支持重载），C 用法不变。

> 注：cxa_guard 走 GlobalMutex 实现而非 Futex 实现（`CurrentImplementation` 未定义
> `_LIBCXXABI_USE_FUTEX`）。两者都线程安全；GlobalMutex 经 pthread_mutex 间接用 futex。
> `PlatformFutexWait/Wake`（走 `SYS_futex`）仅在 Futex 实现启用时使用，但符号仍被编译进来
> （上述指针重载让其编过）。

### `__start_/__stop_` section 边界符号

标准 ld 对任意 orphan section `<name>`，若有对 `__start_<name>`/`__stop_<name>` 的引用且该
section 存在，自动合成边界符号（值为 section 合并后的起止地址）。`bpfvm-ld` 支持此机制
（`src/elf_linker.cpp` 的 `collect_section_boundary_refs` + `define_section_boundary_symbols`），
与 `__init_array_start/end` 用同一套 `synthetic_globals_` 通路。

这支撑了 libc++ 的**可覆盖函数检测**（`overridable_function.h` 的 `__is_function_overridden`）：
operator new/delete 弱符号版被放进 `__lcxx_override` section，检测函数比较函数指针是否落在
`[__start___lcxx_override, __stop___lcxx_override)` 区间内，判断用户是否覆盖了它（用于
`-fno-exceptions` 下 nothrow 版 new 是否要调用户自定义的 throwing 版）。operator new/delete
由 `stdlib_new_delete.cpp` 以弱符号提供（20 个变体，含 nothrow/对齐版），用户可覆盖，
`__is_function_overridden` 可检测。`__cxa_thread_atexit*` 无定义：BPF 上 clang 不为
`addrspace(256)` emutls 全局生成该调用（`thread_local` 关键字被 Sema 拒），库内无任何引用。

## 3. 线程支持的 musl port 适配

`<thread>`/`<mutex>`/`<future>` 走 musl pthread 后端，需要两处 musl BPF port 适配：

1. **`musl/src/thread/bpf/__unmapself.c`** 覆盖通用版：detached 线程退出（如 `std::async`
   内部建的 detached 线程）会调 `__unmapself`，而通用版的 `CRTJMP` 在 BPF port 是占位
   （`__builtin_unreachable()`，注释假设"静态链接路径不执行"，但对 detached 退出不成立）→ UB。
   覆盖为不切栈、不 munmap、直接 `SYS_exit`——bpfvm 的 `PosixSyscall::fini` 在线程退出时
   已统一释放本 vm 的地址空间引用，线程栈映射由 VM 自动回收。
2. **`musl/src/internal/pthread_impl.h`** 的 `DEFAULT_STACK_SIZE` 1MB（`1<<20`，musl 默认 128KB）、
   `DEFAULT_GUARD_SIZE` 64KB（`1<<16`，默认 8KB）。原因：BPF target 每函数预留 `-mllvm
   -bpf-stack-size`（默认 16KB）给编译器局部变量，单函数栈消耗远大于原生，解释器下线程退出
   的深调用链（析构链 ~176KB）超过 musl 默认 128KB 栈。guard ≥ 单帧跨度 16KB 保证任何单帧
   跳跃都被拦住。

栈越界检测：解释器 `push_frame`/`alloca` 查整段新帧可写性（`mmu_w(addr, span)`，size 参数
要求整段落在同一映射，跨 guard 时返回 nullptr 报 stack access 错误），不单查帧头。

## 4. 链接器与 RTTI

RTTI 依赖 `bpfvm-ld` 一个通用 bug 修复：加载 SHT_REL 重定位时，旧版仅对已定义符号读
embedded addend（注释误以为"UND 符号的 patch 点是 clang 占位符"）。这对 `R_BPF_64_32`
（call，clang 写 `imm=-1` 占位符）成立，但对数据重定位（type 1/2/3/4：lddw/绝对指针/DWARF
段内偏移），UND 符号的 patch 点就是**真实 addend**（SHT_REL 标准语义）。C++ typeinfo 每个
对象第一槽是 `vtable+16` 指针（UND `_ZTVN10__cxxabiv1*` + addend=+16），旧链接器漏读 addend
→ 写回 `vtable+0` → 后续 `is_equal` 把它当 typeinfo 解引用崩。修复：数据重定位一律读
embedded addend（`bool read_embedded = (sym_defined || r.type != 10);`）。

## 5. `<filesystem>` 支持

`<filesystem>` 在 bpfvm 上可用（`test/test_stl_filesystem.cpp`，5 变体全过）。底层依赖
已就绪——VM 实现了全部所需文件系统 syscall（`openat`/`read`/`write`/`close`/`statx`/
`getdents64`/`mkdirat`/`unlinkat`/`symlinkat`/`linkat`/`renameat2`/`readlinkat`/`fchdir`/
`getcwd`/`fchmodat`/`utimensat`/`faccessat`/`truncate`/`ftruncate`/`fcntl`），musl 完成了
包装（`stat`/`lstat`/`fstat`→`statx`、`readdir`→`getdents64`、`chdir`→`open`+`fchdir`
覆盖版等）。libc++ 19 filesystem 在非 Windows 上**纯走 POSIX libc 函数**（不直接发
syscall、不直接用 getdents64），故 musl+VM 栈已覆盖其全部依赖。

### 启用要点

1. **`libcxx/build.sh`**：去掉 `-D_LIBCPP_HAS_NO_FILESYSTEM`，新增 7 个 filesystem 源文件
   编译循环（`int128_builtins`/`path`/`filesystem_error`/`filesystem_clock`/
   `directory_entry`/`directory_iterator`/`operations`，源在 `$LIBCXX_SRC/filesystem/`
   子目录，`.o` 加 `fs_` 前缀避免同名冲突）。
2. **`-D_LIBCPP_HAS_NO_INT128`**（关键）：BPF 后端不支持 `__int128` 乘除法（`__multi3`/
   `__divti3`/`__muloti4`，ISel 拒绝 "A call to built-in function '__multi3' is not
   supported"），而 `file_clock::rep` 默认是 `__int128_t`（`__chrono/file_clock.h`）。
   定义该宏让 `rep` 退化为 `long long`，`<filesystem>` 的时间戳运算链（`__last_write_time`/
   `__space` 的溢出检查等）不再触发后端拒绝。`int128_builtins.cpp` 整体被 `#if
   !defined(_LIBCPP_HAS_NO_INT128)` 包裹，定义后变空 TU（不产 `__muloti4` 符号，无冲突）。
   该宏对其它 STL 无影响（`__int128` 的 hash/charconv 特化消失，现有测试不依赖）。
3. **`test/Makefile` 的 CXX_FLAGS 去掉 `-g`**（关键，见下节 bug）。

### 已知降级（VM 未实现对应 syscall）

- **`copy_file`**：libc++ `copy_file_impl` 编译期固定走 `::sendfile`（`_LIBCPP_FILESYSTEM_USE_SENDFILE`，
  因 musl 有 `<sys/sendfile.h>`，`__has_include` 为真）。VM 未实现 `sendfile` syscall
  （`__NR_sendfile = BPF_CALL_BASE` 占位 → ENOSYS）→ `copy_file` 返回 false + error_code
  或抛 `filesystem_error`。`copy`（目录）对子目录创建仍可用，仅文件复制失败。后续可补
  `BPF_SYS_SENDFILE`（转发 host sendfile，guest fd→host fd）解除。
- **`space()`**：libc++ `__space` 调 `::statvfs` → musl `statvfs` → `syscall(SYS_statfs)`。
  VM 未实现 `statfs`/`fstatfs`（ENOSYS）→ `space()` 返回 capacity/free/available =
  `(uintmax_t)-1`。后续可补 `BPF_SYS_STATFS`/`BPF_SYS_FSTATFS` 解除。

### clang BPF `-g` declare 参数提升 bug

C++ 代码加 `-g` 编译时，clang BPF 后端会改坏某些成员函数 `declare` 的参数（`this` 被提升
为值类型、后续聚合参数丢失），导致 declare 与 call 签名不一致 → 链接后 caller/callee ABI
错位，`path::operator==` 等返回错误结果或崩溃。19/20 表现为生成错误 IR（miscompile），
21/22 恶化为编译器直接 crash。去掉 `-g` 在所有版本下正常。

- 上游 issue：https://github.com/llvm/llvm-project/issues/208141
  （含复现用例、版本矩阵、crash 栈）
- **绕过**：`test/Makefile` 的 `CXX_FLAGS` 去掉 `-g`（C 的 `CC_FLAGS` 保留 `-g`，C 不受此
  bug 影响）。代价：C++ 测试无源级调试信息（`bpf-objdump -S` 对 C++ 二进制不可用）。
  `libcxx/build.sh` 的 `STL_CXX_FLAGS` 本就不带 `-g`，库符号不受影响。

## 6. 异常支持可行性评估（未实现）

**结论**：方案 B（VM 内置 unwinder，工作量 ⭐⭐⭐ 中等）最优，但被 clang BPF 后端
`-O1` landingpad codegen crash 阻塞（19→22 trunk 全未修，仅 `-O0` 可绕）。

**关键事实**：
- clang BPF 后端**会**发完整 Itanium EH 元数据（`-O0 -fexceptions` 下：`.gcc_except_table`
  LSDA + `.eh_frame` CFI "zPL" + `landingpad` IR），引用 `__cxa_begin_catch`/
  `__gxx_personality_v0`/`_Unwind_Resume`/`__cxa_throw` 等。
- 但 `.eh_frame` 内容是**空壳**——BPF 后端不生成 `DW_CFA_*` 指令（CFA 定义、寄存器保存
  位置全空，FDE 全 `nop`），标准 libunwind 拿这个无法回溯。这是方案 A（移植 libunwind）
  的根本阻塞，不是 musl 参数问题（加 `-funwind-tables` 只让段发出，内容仍空壳）。
- bpfvm 栈帧是固定简单结构（正常帧 64B = 8 个 8B 槽：flags+len/r6/r7/r8/r9/old_r10/返回
  PC/unused；信号帧 128B），帧存在真实 guest 内存里、沿 `old_r10` 成单向链表，已有现成
  帧链遍历器（`log_mem_violation` 的 backtrace）和弹帧机制（`do_siglongjmp` 直接改 `r10`）。
  这使 VM 内置 unwinder 无需解析 CFI，直接读固定布局帧链。
- clang BPF 后端 `-O1`/`-O2` 编含 `landingpad` 的 TU **必崩**（`LiveVariables::
  HandleVirtRegUse` SIGSEGV，裸 clang 复现），`-O0` 正常。docker 横向验证 clang
  19.1.7/20.1.8/21.1.8/22.0.0 trunk 全 CRASH。

**方案对比**：

| | A 移植 libunwind | **B VM 内置 unwinder** | C SjLj 变体 |
|---|---|---|---|
| 需改 clang（补 CFI/sjlj codegen） | 是（大工程） | **否**（除 try/catch TU 强制 `-O0`） | 是 |
| 回溯 musl 帧 | 需先补 CFI | ✅ 走帧链 | ✅ |
| 工作量 | ⭐⭐⭐⭐⭐ | **⭐⭐⭐** | ⭐⭐⭐⭐ |

方案 B 工作量：拦 `__cxa_throw`（复用 `src_reg=2` 通道模式）→ 沿 `old_r10` 遍历帧链取返回
PC → 查 LSDA（可抄 libc++abi `scan_eh_tab` ~250 行）→ 调 `can_catch`（RTTI 阶段的
`private_typeinfo.cpp` 已具备）→ 设 `r10` 弹到 catch 帧（复用 `do_siglongjmp`）→ landing pad
传参 → `__cxa_begin_catch`/`__cxa_end_catch` 引用计数（复用 libc++abi `cxa_exception.cpp`）。
动手前需先实测两件事：clang BPF 的 `landingpad` codegen 传参机制；LSDA 表在链接/加载后是否
可达（`bpfvm-ld` 要保留 `.gcc_except_table` + 重定位）。

RTTI（决策 21 那批 libc++abi typeinfo 源文件）是异常的前置——catch 匹配走
`__shim_type_info::can_catch`。
