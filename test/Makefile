TARGETS := test_arg.out test_execve.out test_signal.out test_path.out test_readdir.out
OBJECTS := $(TARGETS:.out=.o)

all: $(TARGETS)

%.out: %.o
	bpf-ld $< ../libc/lib64/libpdclib.a -e _start -o $@

%.o: %.c
	clang -std=c11 -target bpf -mcpu=v4 -O1 -mllvm -bpf-stack-size=4096 -nostdinc -fno-builtin -isystem ../include  -isystem ../libc/include/ -g $< -c
	llvm-objcopy --set-section-flags .rodata.str1.1=alloc,readonly,data $@

clean:
	rm -f $(TARGETS) $(OBJECTS)
