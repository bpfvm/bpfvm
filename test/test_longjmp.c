#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * setjmp/longjmp 回归测试。
 *
 * 这里覆盖 longjmp 的全部关键语义，每条都对应一个历史 bug 的表现面：
 *   -  longjmp 让 setjmp「第二次返回」，返回值 == 传入的 val；
 *   -  val==0 时归一化为 1（ISO C 要求）；
 *   -  嵌套 setjmp（多层 jmp_buf）按 LIFO 正确回溯；
 *   -  longjmp 之后不 fall-through（控制流确实跳走，而非继续往下）。
 *
 * 任何一个语义被破坏都返回非 0；全过返回 0。早期 bug 里 longjmp 会
 * 把 setjmp 的「第二次返回值」弄成 0、甚至直接 fall-through，这些
 * 用退出码断言都能抓到（CTest 期望退出码 0）。
 */

/* ---- 工具：在已知好的路径上累计「到达点」，便于失败时定位 ---- */
static int phase = 0;

/* ---- case 1 & 4：基本跳转 + 返回值 + 不 fall-through ---- */
static jmp_buf buf1;
static void jump_with(int val) {
    longjmp(buf1, val);
    /* longjmp 是 _Noreturn；落到这里即 fall-through bug */
    printf("FAIL: longjmp returned in jump_with\n");
    exit(101);
}

static int case_basic(void) {
    int r = setjmp(buf1);
    if (r == 0) {
        jump_with(7);
        printf("FAIL: jump_with returned to caller\n");
        return 11;
    }
    if (r != 7) {
        printf("FAIL: basic: setjmp 2nd return = %d, expected 7\n", r);
        return 12;
    }
    return 0;
}

/* ---- case 2：val==0 归一化为 1 ---- */
static jmp_buf buf2;
static int case_val_zero(void) {
    int r = setjmp(buf2);
    if (r == 0) {
        longjmp(buf2, 0);
        printf("FAIL: longjmp(0) returned\n");
        return 21;
    }
    if (r != 1) {
        printf("FAIL: val_zero: setjmp 2nd return = %d, expected 1\n", r);
        return 22;
    }
    return 0;
}

/* ---- case 3：嵌套 jmp_buf，LIFO 回溯 ---- */
static jmp_buf outer, inner;
static int case_nested(void) {
    int r = setjmp(outer);
    if (r == 0) {
        /* 进入内层 setjmp 后从内层 longjmp，应只回到 inner */
        int ri = setjmp(inner);
        if (ri == 0) {
            longjmp(inner, 5);   /* 回到 inner，ri=5 */
        }
        if (ri != 5) {
            printf("FAIL: nested inner 2nd return = %d, expected 5\n", ri);
            return 31;
        }
        /* 内层正确后，再从外层 longjmp 验证外层 buf 仍有效 */
        longjmp(outer, 9);       /* 回到 outer，r=9 */
        printf("FAIL: longjmp(outer) returned\n");
        return 32;
    }
    if (r != 9) {
        printf("FAIL: nested outer 2nd return = %d, expected 9\n", r);
        return 33;
    }
    return 0;
}

int main(void) {
    int rc;
    phase = 1;
    if ((rc = case_basic()) != 0)    return rc;
    phase = 2;
    if ((rc = case_val_zero()) != 0) return rc;
    phase = 3;
    if ((rc = case_nested()) != 0)   return rc;
    printf("all longjmp cases passed\n");
    return 0;
}
