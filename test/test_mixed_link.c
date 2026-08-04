/* test_mixed_link.c — 混合链接（静态 .a + 动态 .so）回归用例。
 *   - libgot.a（静态）：got_add 静态链入主程序。
 *   - libgot.so（动态）：got_hash 经 PLT/GOT 跨模块调用，内部依赖 libc.so。
 * 链接方式见 test/Makefile。
 */

#include <stdio.h>

extern int got_add(int, int);      /* 来自 libgot.a（静态链入） */
extern int got_hash(const char *); /* 来自 libgot.so（动态） */

int main(void) {
    int r = got_add(19, 23);        /* 42：跨静态/动态边界的内部 call */
    int h = got_hash("hello");      /* strlen("hello")+100 = 105：PLT/GOT 跨模块 */
    if (r != 42) {
        printf("FAIL: got_add(19,23)=%d (expected 42)\n", r);
        return 1;
    }
    if (h != 105) {
        printf("FAIL: got_hash(\"hello\")=%d (expected 105)\n", h);
        return 1;
    }
    printf("mixed link ok: got_add=%d, got_hash=%d\n", r, h);
    return 0;
}
