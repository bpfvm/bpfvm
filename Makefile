a.out: test.o
	bpf-ld test.o  libc/lib64/libpdclib.a -e main

test.o: test.c
	clang -std=c11 -target bpf -mcpu=v4 -O1 -mllvm -bpf-stack-size=4096 -D__STDC_WANT_LIB_EXT1__=1 -isystem libc/include/ -g test.c -c

clean:
	rm -f test.o a.out
