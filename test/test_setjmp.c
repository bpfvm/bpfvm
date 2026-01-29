#include <stdio.h>
#include <setjmp.h>

jmp_buf env;

void func(int n) {
    printf("func(%d) calling longjmp\n", n);
    longjmp(env, n);
}

int main(void) {
    int val;
    printf("main: before setjmp\n");
    val = setjmp(env);
    if (val == 0) {
        printf("main: setjmp returned 0, calling func\n");
        func(42);
    } else {
        printf("main: setjmp returned %d, success\n", val);
    }
    return (val == 42) ? 0 : 1;
}

