SOURCES := $(filter-out libgot.c, $(wildcard *.c))
TARGETS := $(SOURCES:.c=.out)
OBJECTS := $(TARGETS:.out=.o)
DYN_TARGETS := $(SOURCES:.c=.linked)
# 动态链接的共享库（不作为独立测试，供 test_dyn_data 引用）
GOT_SO := libgot.so

# libc.so 由 build_root.sh 的 build_libc_bpfso 产出（从 musl libc.a 合成，含 _start），
# 放 ../libc/lib/；test 只引用，不自己构建（也不构建 libc.a，由 musl/build.sh 产出）。
LIBC_BPFSO := ../libc/lib/libc.so

# BPF 编译 flags（clang 直接编译，无 wrapper）
# -nostdinc: 不用宿主 glibc 头，只用 musl(../libc/include) + BPF guest 头(../include)。
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
            -nostdinc -fno-builtin -fno-math-errno \
            -isystem ../libc/include/ -isystem ../include -g

# BpfWideArgs pass 插件：突破 BPF 5 参数限制 + 返回结构体支持。
WIDEARGS := $(wildcard ../build/libBpfWideArgs.so)
ifneq ($(WIDEARGS),)
CC_FLAGS += -fpass-plugin=$(WIDEARGS)
endif

# BpfSoftFp pass 插件：把浮点运算（fadd/fmul/fcmp/...）在 IR 层替换成对
# extern __ksym __bpf_fp_<ID> 的调用，经 bpfvm-ld 改写成 BPF_FP_* call
# （src_reg=2，FP 专用通道），绕过 BPF 后端对浮点的拒绝；
# VM 侧 do_softfp 用宿主硬件浮点执行。
SOFTFP := $(wildcard ../build/libBpfSoftFp.so)
ifneq ($(SOFTFP),)
CC_FLAGS += -fpass-plugin=$(SOFTFP)
endif

all: $(TARGETS) $(DYN_TARGETS)

# 静态链接（-static）：.o + libc.a（含 _start）→ 自包含 ET_EXEC
%.out: %.o
	../build/bpfvm-ld -static $< -L ../libc/lib -l:libc.a -o $@

# 动态链接（默认）：.o 引用 libc.so（自带 _start）→ PIE ET_DYN + DT_NEEDED（运行时 mmap .so）
%.linked: %.o $(LIBC_BPFSO)
	../build/bpfvm-ld $< -L ../libc/lib -l:libc.so -o $@

%.o: %.c
	clang $(CC_FLAGS) $< -c

# === 动态链接（运行时 PLT/GOT + .rela.dyn）===
# libgot 建成 .so：导出 got_add/got_counter/got_hash（不带 _start，PIE）。
# 内部调 libc strlen → 依赖 libc.so（DT_NEEDED），构造主程序→libgot→libc 的链式依赖。
$(GOT_SO): libgot.o $(LIBC_BPFSO)
	../build/bpfvm-ld -shared --soname libgot.so $< -L ../libc/lib -l:libc.so -o $@
libgot.a: libgot.o
	ar rcs $@ $<

# test_dyn_data：验证跨模块函数调用（got_add 走 PLT/GOT）+ 数据引用（got_counter 走 .rela.dyn）
#              + 链式依赖（got_hash 内部调 libc strlen，由 loader 递归 DT_NEEDED 解析）
# 覆盖通用规则：需要 libgot.so/libgot.a 依赖，且链接命令带 -l:libgot.so / libgot.a
test_dyn_data.linked: test_dyn_data.o $(GOT_SO)
	../build/bpfvm-ld $< -L ../libc/lib -l:libc.so -L . -l:libgot.so -o $@
test_dyn_data.out: test_dyn_data.o libgot.a
	../build/bpfvm-ld -static $< libgot.a -L ../libc/lib -l:libc.a -o $@

# 标记 .o 为中间文件，make 构建后会自动删除（和其他 .o 行为一致）
.INTERMEDIATE: libgot.o test_dyn_data.o

clean:
	rm -f $(TARGETS) $(DYN_TARGETS) *.o $(GOT_SO) libgot.a *.tmp
