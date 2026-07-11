/*
 * 验证 siglongjmp 跨函数跳转后，setjmp 所在函数的自动变量（含 volatile）
 * 保持 longjmp 调用时的值，而不是被恢复成 setjmp 时的值。
 *
 * 这是 ash/dash 等交互式 shell 正确处理 Ctrl+C 的关键：
 *   ash_main 有 volatile smallint state; setjmp 后 state 会被改成 4（cmdloop），
 *   深层 read_line_input 里 siglongjmp 回 ash_main 的 setjmp，此时 state 必须仍为 4，
 *   否则 ash_main 会误判 "state==0" 而 exitshell。
 *
 * 预期输出：state_after=4（PASS），退出码 0。
 * 若 VM 错误恢复 state：state_after=0，打印 FAIL，退出码 1。
 */
#include <setjmp.h>
#include <stdio.h>

static sigjmp_buf top_buf;

/* 模拟 ash 的深层调用：read_line_input → ... → raise_exception → siglongjmp */
static void deep_call_then_longjmp(void) {
    /* 中间做一些调用，产生多层栈帧（模拟 ash 的 read_line_input 调用深度） */
    volatile int marker = 0xABCD;
    (void)marker;
    siglongjmp(top_buf, 1);
}

static void level3(void) { deep_call_then_longjmp(); }
static void level2(void) { level3(); }
static void level1(void) { level2(); }

int main(void) {
    /* volatile：对标 ash_main 的 volatile smallint state */
    volatile int state = 0;
    volatile int counter = 100;

    int r = sigsetjmp(top_buf, 1);
    if (r == 0) {
        /* 模拟 ash_main 初始化后推进 state */
        state = 4;       /* cmdloop */
        counter = 200;
        level1();        /* 深层 longjmp 回来 */
        printf("FAIL: level1 returned\n");
        return 1;
    }

    /* longjmp 回到这里：state 必须是 4（longjmp 时的值），不是 0（setjmp 时的值） */
    printf("state_after=%d counter_after=%d\n", state, counter);
    if (state != 4) {
        printf("FAIL: state restored to %d (expected 4) — longjmp clobbered volatile local\n", state);
        return 1;
    }
    if (counter != 200) {
        printf("FAIL: counter restored to %d (expected 200)\n", counter);
        return 1;
    }
    printf("PASS: volatile locals preserved across siglongjmp\n");
    return 0;
}
