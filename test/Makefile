SOURCES := $(wildcard *.c)
TARGETS := $(SOURCES:.c=.out)
OBJECTS := $(TARGETS:.out=.o)

all: $(TARGETS)

%.out: %.o
	bpf-ld $< ../libc/lib64/libpdclib.a -e _start -o $@

%.o: %.c
	../bpf-cc -std=c11 -target bpf -mcpu=v4 -O1 -mllvm -bpf-stack-size=4096 -nostdinc -fno-builtin -isystem ../libc/include/  -isystem ../include -g $< -c

clean:
	rm -f $(TARGETS) $(OBJECTS) *.tmp
