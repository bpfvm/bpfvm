/*
 * 验证 siglongjmp 回跳后，调用者能正常进行后续的函数调用与返回。
 *
 * 模拟 ash Ctrl+C 场景：
 *   ash_main: setjmp -> state=4 -> cmdloop() ──┐
 *     cmdloop 深层 longjmp 回 ash_main          │ 进程不退出
 *   ash_main: longjmp 返回 -> 调 post_fn() ─────┘
 *     post_fn 必须正确返回到 ash_main（而非返回到别处）
 *
 * 若 VM siglongjmp 破坏了调用者的帧头，post_fn 的 return 会跳到错误地址，
 * 表现为 post_fn_ret_mismatch 或 crash。
 *
 * 预期：state=4, post_fn returned correctly, rc=0
 */
#include <setjmp.h>
#include <stdio.h>

static sigjmp_buf top_buf;

static void deep_longjmp(void) {
    volatile int x = 0x1234;
    (void)x;
    siglongjmp(top_buf, 1);
}
static void level3(void) { deep_longjmp(); }
static void level2(void) { level3(); }
static void level1(void) { level2(); }

/* 模拟 longjmp 回来后 ash_main 要调的函数（如 exitreset/reset） */
static int post_fn(volatile int *state_p) {
    volatile int local = 0x5678;
    /* 再做一次嵌套调用，增加栈帧层数 */
    (void)local;
    return *state_p + 1;
}

int main(void) {
    volatile int state = 0;
    volatile int rc = 999;

    int r = sigsetjmp(top_buf, 1);
    if (r == 0) {
        state = 4;
        level1();        /* 深层 longjmp */
        printf("FAIL: level1 returned\n");
        return 1;
    }

    /* longjmp 回来：state 应为 4 */
    printf("after longjmp: state=%d r=%d\n", state, r);
    if (state != 4) {
        printf("FAIL: state=%d expected 4\n", state);
        return 1;
    }

    /* 关键：调用一个函数，它必须正确返回 */
    rc = post_fn(&state);
    printf("post_fn returned rc=%d\n", rc);
    if (rc != 5) {
        printf("FAIL: post_fn returned %d expected 5\n", rc);
        return 1;
    }
    printf("PASS: reentry after siglongjmp OK\n");
    return 0;
}
