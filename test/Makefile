# 显式默认目标：CMake 的 bpf_programs_build fixture 调用 `make -C test`（无目标），
# 若不指定，make 会取第一个出现的普通目标（libgot.host.o 等），导致只构建单个
# 中间产物就退出。固定为 all，确保 fixture 从干净状态能构建全部用例。
.DEFAULT_GOAL := all

# === 源文件 ===
# 与 CMakeLists 的 glob（test_*.c + test_*.cpp）对齐：所有 test_*.c / test_*.cpp 都算测试。
# 编译 flags 按语言分派（C -> CC_FLAGS，C++ -> CXX_FLAGS）
SOURCES := $(filter-out libgot.c, $(wildcard *.c))
TARGETS := $(SOURCES:.c=.out)
DYN_TARGETS := $(SOURCES:.c=.linked)
# 动态链接的共享库（不作为独立测试，供 test_dyn_data 引用）
GOT_SO := libgot.so

CXX_SOURCES := $(wildcard test_*.cpp)
CXX_TARGETS := $(CXX_SOURCES:.cpp=.out)
CXX_DYN_TARGETS := $(CXX_SOURCES:.cpp=.linked)
CXX_HOST_TARGETS := $(CXX_SOURCES:.cpp=.host)

# libcxx.a 由 scripts/build_libcxx.sh 产出（C++ runtime：operator new/delete + __cxa_*
# stub + libc++ 库符号）。所有 C++ 测试统一链入——即使该用例不直接用 STL，链入也无害
# （静态库 first-wins：用例自定义的 operator new/delete 优先于库内的 cxxabi_stub 版）。
LIBCXX_BPFA := ../root/lib/libcxx.a
# libcxx.so 由 build_root.sh 的 build_libcxx 从 libcxx.a 合成（依赖 libc.so，DT_NEEDED），
# 放 ../root/lib/；动态链接用例链它，test 只引用，不自己构建。
LIBCXX_BPFSO := ../root/lib/libcxx.so
# libc.so 由 build_root.sh 的 build_libc_bpfso 产出（从 musl libc.a 合成，含 _start），
# 放 ../root/lib/；test 只引用，不自己构建（也不构建 libc.a，由 musl/build.sh 产出）。
LIBC_BPFSO := ../root/lib/libc.so

# === BPF pass 插件（clang -fpass-plugin=，语言无关，C/C++ 共用） ===
# 路径用 wildcard 探测，存在则注入（缺失时跳过，不报错——便于在 pass 未构建的环境复用）。
# BpfWideArgs：突破 BPF 5 参数限制 + 返回结构体支持 + lowerAggregateParams
#   （按值传聚合参数：路径 A 剥大聚合 byval 属性、路径 B 小聚合成值降级成 ptr）+
#   stripSret + 变参（详见 README.md「函数调用约定突破」）。C 和 C++ 都可能用到。
WIDEARGS := $(wildcard ../build/libBpfWideArgs.so)
# BpfSoftFp：浮点运算（fadd/fmul/fcmp/...）在 IR 层替换成 BPF_FP_* call（src_reg=2，
#   FP 专用通道），绕过 BPF 后端对浮点的拒绝；VM 侧 do_softfp 用宿主硬件浮点执行。
SOFTFP := $(wildcard ../build/libBpfSoftFp.so)
# BpfEmutls：把 annotate("emutls") 全局改写成 __emutls_get_address 调用，实现
#   thread_local 语义（机制见 README「模拟 TLS (emutls)」）。对无 emutls 标注的源是
#   no-op，故 C/C++ 统一注入无害；annotate 仅经 CXX_FLAGS 的 -Dthread_local 注入
#  （C 的 thread_local/_Thread_local 仍被 Sema 拒绝）。
EMUTLS := $(wildcard ../build/libBpfEmutls.so)
# BpfLibcallLower：@llvm.memcpy/memmove/memset/trap + floor/ceil/trunc/round intrinsic
#   -> 对 musl 函数的 call。C++ 结构体拷贝/vector realloc 必需
LIBCALL := $(wildcard ../build/libBpfLibcallLower.so)

# 所有 pass 对 C/C++ 统一注入（emutls pass 对无 emutls 标注的 C 源是 no-op）。
PASS_FLAGS :=
ifneq ($(WIDEARGS),)
PASS_FLAGS += -fpass-plugin=$(WIDEARGS)
endif
ifneq ($(SOFTFP),)
PASS_FLAGS += -fpass-plugin=$(SOFTFP)
endif
ifneq ($(LIBCALL),)
PASS_FLAGS += -fpass-plugin=$(LIBCALL)
endif
ifneq ($(EMUTLS),)
PASS_FLAGS += -fpass-plugin=$(EMUTLS)
endif

# === C 编译 flags ===
# -nostdinc: 不用宿主 glibc 头，只用 musl(../root/include) + BPF guest 头(../include)。
# -std=gnu11: gnu11 不定义 __STRICT_ANSI__，musl features.h 启用默认 feature 宏
#   （_GNU_SOURCE 等），struct sigaction 等类型可见。同时让 GNU 扩展
#   （`, ##__VA_ARGS__`）可用 —— 用户侧 syscall 宏（arch/bpf/bits/syscall.h.in）
#   依赖该扩展做 0..6 参 narg 分发；严格 -std=c11 下不删空变参前的逗号，
#   NARG() 误算成 1，syscall(GETTID) 错调 __bpf_syscall1 报参数不足。
# -fno-builtin: 必须保留。否则 clang 把 mempcpy/strchr/... 等 builtin 优化成对 memcpy
#   等的调用，BPF 后端在 ISel 拒绝（实测 dash 即触发）。强制走 musl 库实现。
# -fno-math-errno: 让 __builtin_sqrt 等数学 builtin 折叠成 @llvm.sqrt 等 intrinsic
#   （而非对库符号 sqrt 的调用），BpfSoftFp pass 才能在 IR 层接住并 lower 成
#   BPF_FP_SQRT_。去掉 errno 副作用不影响正确性（BPF 无 errno）。
# 浮点由 BpfSoftFp pass 在 IR 层处理，不依赖 -fno-builtin。
CC_FLAGS := -std=gnu11 -D_GNU_SOURCE -target bpf -mcpu=v4 -O1 -mllvm -bpf-stack-size=16384 \
            -nostdinc -fno-builtin -fno-math-errno -Werror=macro-redefined \
            -isystem ../root/include/ -g -fstack-size-section \
            $(PASS_FLAGS)

# === C++ 编译 flags ===
# 与 CC_FLAGS 共用 BPF target/CPU/栈大小/pass 插件，C++ 特有部分：
# - -std=c++23：libc++ 内部需要 C++20+；升到 c++23 解锁 <expected> 等 C++23 头。
#   c++23 是 c++20 的超集，现有测试无回归；libcxx.a 跨版本混编无碍（mangling 不依赖语言版本）。
# - libc++ 头（$LIBCXX_INC）必须在 musl 之前：cstddef 的 #include_next <stddef.h>
#   要求 libc++ 的 stddef.h 先被找到，再 #include_next 串联到 musl 的。
# - -fno-exceptions -frtti：异常禁用（BPF 无异常 runtime，throw/try 编译期被拒）；
#   RTTI 启用——libcxx.a 含 libc++abi 的 typeinfo 子集（__dynamic_cast/__cxa_bad_typeid 等），
#   typeid/dynamic_cast 可用。
# libc++ 头目录：root/include/c++/v1（scripts/build_libcxx.sh 安装，与库同源）。
# 用 wildcard 校验 vector 后置空（未构建时报缺头，不静默漏链）。
LIBCXX_INC := ../root/include/c++/v1
LIBCXX_INC := $(if $(wildcard $(LIBCXX_INC)/vector),$(LIBCXX_INC),)
CXX_FLAGS := -std=c++23 -D_GNU_SOURCE -target bpf -mcpu=v4 -O1 \
             -mllvm -bpf-stack-size=16384 -nostdinc \
             -fno-builtin -fno-math-errno -fno-exceptions -frtti \
             $(if $(LIBCXX_INC),-isystem $(LIBCXX_INC)) \
             -isystem ../root/include/ \
             -Dthread_local='__attribute__((annotate("emutls")))' \
             $(PASS_FLAGS)

# === Host 原生构建 ===
# 用宿主 glibc 编译同一批 .c/.cpp，产出 <name>.host 原生可执行文件，
# 作为 BPF/musl/bpfvm 实现的对照基线：同一段测试逻辑在标准 glibc 下也应通过。
# ctest 的 host 变体（cmake/RunBpfProgram.cmake）直接运行这些二进制。
HOST_CC      := clang
HOST_CFLAGS  := -O1 -D_GNU_SOURCE -g -Wall
# -pthread + -lm 统一作为默认链接库（线程类需要 -pthread；test_softfp 等需要 -lm）。
# 后续若还有其它库依赖，直接加到这里，不做逐测试特化。
HOST_LDFLAGS := -pthread -lm

HOST_TARGETS := $(SOURCES:.c=.host)

# C++ host 对照（g++ 编宿主 glibc，与 BPF 版同一份 .cpp 源码做行为对照）。
# -std=c++23 -frtti 与 BPF 版 CXX_FLAGS 对齐（host 仍 -fno-exceptions，对照异常禁用语义）。
HOST_CXX      := clang++
HOST_CXXFLAGS := -std=c++23 -O1 -D_GNU_SOURCE -g -Wall -fno-exceptions -frtti

# 通用规则：单文件直接编译链接。host 用 gcc/g++，target=宿主。
%.host: %.c
	$(HOST_CC) $(HOST_CFLAGS) $< -o $@ $(HOST_LDFLAGS)
%.host: %.cpp
	$(HOST_CXX) $(HOST_CXXFLAGS) $< -o $@ $(HOST_LDFLAGS)
# test_stl_expected 的 host 对照改用 clang++/libc++：Debian 12 的 gcc 12 自带 libstdc++
# 还没有 expected::transform/or_else/and_then（C++23 后期才加），而 clang 19 自带 libc++
# 有完整 expected 支持——与 BPF 端同源，作对照基线更一致。HOST_CXXFLAGS 已是 c++23。
test_stl_expected.host: test_stl_expected.cpp
	clang++ -stdlib=libc++ $(HOST_CXXFLAGS) $< -o $@ $(HOST_LDFLAGS)

# libgot host 版（供 test_dyn_data.host 链接）。
libgot.host.o: libgot.c
	$(HOST_CC) $(HOST_CFLAGS) -fPIC $< -c -o $@
libgot.host.a: libgot.host.o
	ar rcs $@ $<
libgot.host.so: libgot.host.o
	$(HOST_CC) -shared $< -o $@

# test_dyn_data.host / test_mixed_link.host：链入 libgot.host.a（host 上跨模块直接静态链，
# 验证逻辑等价）。两用例引用的 got_* 符号都在 libgot.host.a 内。
test_dyn_data.host: test_dyn_data.c libgot.host.a
	$(HOST_CC) $(HOST_CFLAGS) $< libgot.host.a -o $@ $(HOST_LDFLAGS)
test_mixed_link.host: test_mixed_link.c libgot.host.a
	$(HOST_CC) $(HOST_CFLAGS) $< libgot.host.a -o $@ $(HOST_LDFLAGS)

host-build: $(HOST_TARGETS) $(CXX_HOST_TARGETS) libgot.host.so

all: $(TARGETS) $(DYN_TARGETS) $(CXX_TARGETS) $(CXX_DYN_TARGETS) host-build

# === 链接 ===
# 静态链接（-static）：.o + libc.a（含 _start）-> 自包含 ET_EXEC。
# 动态链接（默认）：.o 引用 libc.so（自带 _start）-> PIE ET_DYN + DT_NEEDED（运行时 mmap .so）。
# C++ 用例：
#   - 静态（.out）：链 libcxx.a（C++ runtime + libc++ 库符号，静态链入）。
#   - 动态（.linked）：链 libcxx.so（生成 DT_NEEDED libcxx.so，运行时走 PLT/GOT + .rela.dyn）。
# C 用例不链 libcxx——保持 C 测试对 C++ 库零依赖（纯净环境未构建 libcxx 时 C 测试仍可用）。
# test_dyn_data / test_mixed_link 另有显式规则（需额外链 libgot.so/libgot.a），从静态/动态
# 模式规则里排除，避免 recipe 重叠（"overriding recipe" 警告）；它们仍在 $(TARGETS)/
# $(DYN_TARGETS) 里，由 all 构建。
STATIC_OUT     := $(filter-out test_dyn_data.out test_mixed_link.out,$(TARGETS))
STATIC_LINKED  := $(filter-out test_dyn_data.linked test_mixed_link.linked,$(DYN_TARGETS))
$(STATIC_OUT): %.out: %.o
	../build/bpfvm-ld -static $< -L ../root/lib -l:libc.a -o $@
$(STATIC_LINKED): %.linked: %.o $(LIBC_BPFSO)
	../build/bpfvm-ld $< -L ../root/lib -l:libc.so -o $@
$(CXX_TARGETS): %.out: %.o $(LIBCXX_BPFA)
	../build/bpfvm-ld -static $< $(LIBCXX_BPFA) -L ../root/lib -l:libc.a -o $@
$(CXX_DYN_TARGETS): %.linked: %.o $(LIBCXX_BPFSO) $(LIBC_BPFSO)
	../build/bpfvm-ld $< -L ../root/lib -l:libcxx.so -L ../root/lib -l:libc.so -o $@

%.o: %.c
	clang $(CC_FLAGS) $< -c

%.o: %.cpp
	clang++ $(CXX_FLAGS) $< -c

# === 动态链接（运行时 PLT/GOT + .rela.dyn）===
# libgot 建成 .so：导出 got_add/got_counter/got_hash（不带 _start，PIE）。
# 内部调 libc strlen -> 依赖 libc.so（DT_NEEDED），构造主程序->libgot->libc 的链式依赖。
$(GOT_SO): libgot.o $(LIBC_BPFSO)
	../build/bpfvm-ld -shared --soname libgot.so $< -L ../root/lib -l:libc.so -o $@
libgot.a: libgot.o
	ar rcs $@ $<

# test_dyn_data：验证跨模块函数调用（got_add 走 PLT/GOT）+ 数据引用（got_counter 走 .rela.dyn）
#              + 链式依赖（got_hash 内部调 libc strlen，由 loader 递归 DT_NEEDED 解析）
# 覆盖通用规则：需要 libgot.so/libgot.a 依赖，且链接命令带 -l:libgot.so / libgot.a
test_dyn_data.linked: test_dyn_data.o $(GOT_SO)
	../build/bpfvm-ld $< -L ../root/lib -l:libc.so -L . -l:libgot.so -o $@
test_dyn_data.out: test_dyn_data.o libgot.a
	../build/bpfvm-ld -static $< libgot.a -L ../root/lib -l:libc.a -o $@

# test_mixed_link：混合链接（.a 静态库 + .so 动态库）。
# .linked：libgot.a + libc.a（静态链入）+ libgot.so + libc.so（动态依赖）。
# .out：纯静态对照（与 test_dyn_data.out 同构）。
test_mixed_link.linked: test_mixed_link.o libgot.a $(GOT_SO)
	../build/bpfvm-ld $< libgot.a -L ../root/lib -l:libc.a -L . -l:libgot.so -L ../root/lib -l:libc.so -o $@
test_mixed_link.out: test_mixed_link.o libgot.a
	../build/bpfvm-ld -static $< libgot.a -L ../root/lib -l:libc.a -o $@

# 标记 .o 为中间文件，make 构建后会自动删除（和其他 .o 行为一致）
.INTERMEDIATE: libgot.o test_dyn_data.o test_mixed_link.o libgot.host.o

clean:
	rm -f $(TARGETS) $(DYN_TARGETS) $(HOST_TARGETS) \
	      $(CXX_TARGETS) $(CXX_DYN_TARGETS) $(CXX_HOST_TARGETS) \
	      *.o $(GOT_SO) libgot.a \
	      libgot.host.so libgot.host.a *.tmp
