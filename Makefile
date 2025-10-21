a.out: test.o
	bpf-ld test.o  libc/lib64/libpdclib.a -e main

test.o: test.c
	clang-19 -nostdinc -Ilibc/include -target bpf -Os -g test.c -c

clean:
	rm -f test.o a.out
