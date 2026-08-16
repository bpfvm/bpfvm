#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

/*
 * sigsetjmp/siglongjmp 回归测试，聚焦信号掩码保存/恢复语义。
 *
 * 覆盖三点：
 *   -  sigsetjmp(env, 1) 在 setjmp 点保存当前掩码；之后 block 一个信号再
 *      siglongjmp 回去，掩码必须恢复到 setjmp 时（被 block 的信号重新可投递）。
 *   -  sigsetjmp(env, 0) 不保存掩码；siglongjmp 后掩码保持 siglongjmp 调用时的
 *      状态（仍被 block）。
 *   -  setjmp/longjmp 基本回跳仍正确（防止改动引入回归）。
 *
 * BPF 上 setjmp == sigsetjmp(env, 1)（总是保存掩码），故 case 3 等价于 case 1。
 * 掩码查询用 sigprocmask(SIG_BLOCK, NULL, &set) 读当前掩码，检查目标位是否置位。
 */

static int mask_has(int sig) {
    sigset_t set;
    sigemptyset(&set);
    sigprocmask(SIG_BLOCK, NULL, &set);
    return sigismember(&set, sig) ? 1 : 0;
}

/* case 1：sigsetjmp(env, 1) 保存掩码，siglongjmp 后恢复 */
static sigjmp_buf buf1;
static int case_savemask(void) {
    /* 起点：确保 SIGUSR1 未被 block */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    if (mask_has(SIGUSR1)) {
        printf("FAIL: savemask: SIGUSR1 unexpectedly blocked at start\n");
        return 11;
    }

    int r = sigsetjmp(buf1, 1);
    if (r == 0) {
        /* 在 setjmp 之后 block SIGUSR1，再回跳：掩码应恢复成未 block */
        sigprocmask(SIG_BLOCK, &set, NULL);
        if (!mask_has(SIGUSR1)) {
            printf("FAIL: savemask: SIGUSR1 not blocked before siglongjmp\n");
            return 12;
        }
        siglongjmp(buf1, 7);
        printf("FAIL: siglongjmp returned\n");
        return 13;
    }
    if (r != 7) {
        printf("FAIL: savemask: 2nd return = %d, expected 7\n", r);
        return 14;
    }
    if (mask_has(SIGUSR1)) {
        printf("FAIL: savemask: SIGUSR1 still blocked after siglongjmp (mask not restored)\n");
        return 15;
    }
    return 0;
}

/* case 2：sigsetjmp(env, 0) 不保存掩码，siglongjmp 后掩码保持调用时状态 */
static sigjmp_buf buf2;
static int case_nosavemask(void) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    if (mask_has(SIGUSR2)) {
        printf("FAIL: nosavemask: SIGUSR2 unexpectedly blocked at start\n");
        return 21;
    }

    int r = sigsetjmp(buf2, 0);
    if (r == 0) {
        sigprocmask(SIG_BLOCK, &set, NULL);
        if (!mask_has(SIGUSR2)) {
            printf("FAIL: nosavemask: SIGUSR2 not blocked before siglongjmp\n");
            return 22;
        }
        siglongjmp(buf2, 3);
        printf("FAIL: siglongjmp returned\n");
        return 23;
    }
    if (r != 3) {
        printf("FAIL: nosavemask: 2nd return = %d, expected 3\n", r);
        return 24;
    }
    /* savemask=0：掩码未恢复，SIGUSR2 应仍被 block */
    if (!mask_has(SIGUSR2)) {
        printf("FAIL: nosavemask: SIGUSR2 unblocked after siglongjmp (mask should persist)\n");
        return 25;
    }
    /* 清理：解除 block，避免影响后续 case */
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    return 0;
}

/* case 3：setjmp/longjmp 基本回跳（setjmp 在 BPF 上 == sigsetjmp(env,1)） */
static jmp_buf buf3;
static int case_basic_setjmp(void) {
    int r = setjmp(buf3);
    if (r == 0) {
        longjmp(buf3, 42);
        printf("FAIL: longjmp returned\n");
        return 31;
    }
    if (r != 42) {
        printf("FAIL: basic: 2nd return = %d, expected 42\n", r);
        return 32;
    }
    return 0;
}

int main(void) {
    int rc;
    if ((rc = case_savemask()) != 0)      return rc;
    if ((rc = case_nosavemask()) != 0)    return rc;
    if ((rc = case_basic_setjmp()) != 0)  return rc;
    printf("all sigsetjmp cases passed\n");
    return 0;
}
