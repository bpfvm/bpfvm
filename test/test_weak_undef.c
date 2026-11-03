/* weak UND 符号链接/解析回归测试(#2,根因分析见 PR)。
 *
 * 两条断言:
 *   - libc 提供的 weak 引用:各链接变体(dynamic 运行期 ldso 解析 / static 从
 *     libc.a 拉入强定义 / host glibc)都必须取到非空地址且调用成功。dynamic
 *     变体覆盖修复本体:若 linker 把 weak UND 的 call 构建期烧向 guest 0,
 *     运行期 lddw 被填真地址后调用即跳进 ELF header 崩溃。
 *   - 不存在的 weak 引用:判空必须成立(NULL fallback,GNU ld weak-UND 语义)。
 */
#include <stdio.h>
#include <unistd.h>

extern int getentropy(void *, unsigned long) __attribute__((weak));
extern int getentropy_bpfvm_missing(void *, unsigned long) __attribute__((weak));

int main(void) {
    if (&getentropy == 0) {
        printf("BUG: libc-provided weak symbol resolved to NULL\n");
        return 1;
    }
    unsigned char buf[8];
    if (getentropy(buf, sizeof(buf)) != 0) {
        printf("BUG: weak symbol call failed\n");
        return 2;
    }

    if (&getentropy_bpfvm_missing != 0) {
        printf("BUG: missing weak symbol non-null\n");
        return 3;
    }

    printf("weak undef ok\n");
    return 0;
}
