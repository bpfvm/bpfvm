a.out: test.o
	bpf-ld test.o  libc/lib64/libpdclib.a -e _start

test.o: test.c
	clang -std=c11 -target bpf -mcpu=v4 -O1 -mllvm -bpf-stack-size=4096 -isystem libc/include/ -g test.c -c
	llvm-objcopy --set-section-flags .rodata.str1.1=alloc,readonly,data test.o

clean:
	rm -f test.o a.out
