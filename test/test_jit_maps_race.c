/*
 * #2 探测：JIT compile 路径遍历 vm->maps 无锁，与并发 mmap/munmap 竞争。
 *
 * 思路：CLONE_VM 线程共享同一份 maps。
 *   - 一组线程不停 mmap/munmap（修改 maps list → 迭代器/节点变动）
 *   - 另一组线程不停调用许多「不同」的函数（每个新函数入口触发 JIT compile，
 *     compile() 内部 for(auto& m : *v->maps) 无锁遍历找段边界）
 * 反复碰撞，期望触发：迭代器失效 → 崩溃 / 段错误 / 卡死。
 *
 * 通过标准：正常跑完打印 ok，退出码 0（无崩溃即说明该路径未被触发/已被容忍）。
 * host 基线：glibc 无此概念（host 的 malloc/mmap 走内核，不涉及 guest maps），
 *           本测试在 host 上只是验证「逻辑正确不 self-crash」。
 */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

/* 一堆互不相同的函数，强制 JIT 为不同入口（增加 compile 命中） */
#define FN(i) static long __attribute__((noinline)) f##i(long x){ return x*3+i; }
FN(0) FN(1) FN(2) FN(3) FN(4) FN(5) FN(6) FN(7) FN(8) FN(9)
FN(10) FN(11) FN(12) FN(13) FN(14) FN(15) FN(16) FN(17) FN(18) FN(19)
FN(20) FN(21) FN(22) FN(23) FN(24) FN(25) FN(26) FN(27) FN(28) FN(29)
#undef FN

static volatile int stop = 0;

/* worker A：反复 mmap/munmap，制造 maps list 变动 */
static void *mapper(void *arg) {
    (void)arg;
    size_t pg = sysconf(_SC_PAGESIZE);
    while (!stop) {
        void *p = mmap(NULL, pg * 4, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            memset(p, 0, pg * 4);
            munmap(p, pg * 4);
        }
    }
    return NULL;
}

/* worker B：调用许多不同函数，触发 JIT compile 遍历 maps */
static void *computer(void *arg) {
    (void)arg;
    volatile long acc = 0;
    while (!stop) {
        acc += f0(acc); acc += f1(acc); acc += f2(acc); acc += f3(acc); acc += f4(acc);
        acc += f5(acc); acc += f6(acc); acc += f7(acc); acc += f8(acc); acc += f9(acc);
        acc += f10(acc); acc += f11(acc); acc += f12(acc); acc += f13(acc); acc += f14(acc);
        acc += f15(acc); acc += f16(acc); acc += f17(acc); acc += f18(acc); acc += f19(acc);
        acc += f20(acc); acc += f21(acc); acc += f22(acc); acc += f23(acc); acc += f24(acc);
        acc += f25(acc); acc += f26(acc); acc += f27(acc); acc += f28(acc); acc += f29(acc);
    }
    return (void *)acc;
}

int main(void) {
    pthread_t m[3], c[3];
    for (int i = 0; i < 3; i++) pthread_create(&m[i], NULL, mapper, NULL);
    for (int i = 0; i < 3; i++) pthread_create(&c[i], NULL, computer, NULL);

    struct timespec ts = {2, 0};   /* 压 2 秒 */
    nanosleep(&ts, NULL);
    stop = 1;

    for (int i = 0; i < 3; i++) pthread_join(m[i], NULL);
    for (int i = 0; i < 3; i++) pthread_join(c[i], NULL);

    printf("jit maps race: survived\n");
    return 0;
}
