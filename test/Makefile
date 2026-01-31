TARGETS := test_arg.out test_execve.out test_signal.out test_path.out test_readdir.out test_umask.out test_setjmp.out test_va.out test_cloexec.out test_cloexec_child.out
OBJECTS := $(TARGETS:.out=.o)

all: $(TARGETS)

%.out: %.o
	bpf-ld $< ../libc/lib64/libpdclib.a -e _start -o $@

%.o: %.c
	../bpf-cc -std=c11 -target bpf -mcpu=v4 -O1 -mllvm -bpf-stack-size=4096 -nostdinc -fno-builtin -isystem ../libc/include/  -isystem ../include -g $< -c

clean:
	rm -f $(TARGETS) $(OBJECTS) *.tmp
