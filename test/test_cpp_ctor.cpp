// 全局构造/析构框架测试：验证 .init_array/.fini_array 在 bpfvm 上正确工作。
//
// 机制（见 README.md 的全局构造/析构说明与 src/elf_linker.cpp 的 init_array 处理）：
//   - clang 把带非平凡 ctor 的全局对象的构造函数指针放进 .init_array（SHT_INIT_ARRAY），
//     析构经 __cxa_atexit 登记（由 musl 在 exit 时倒序调用）。
//   - bpfvm-ld 收集 .init_array section（保证段内连续）、合成 __init_array_start/end
//     边界符号（覆盖 musl 的 weak UND）；musl 的 __libc_start_init 循环自动消费。
//   - 静态模式构建期 patch 函数指针；PIE 模式经 .rela.dyn 由 loader 运行时填。
//
// 覆盖：ctor 在 main 前跑、dtor 在 exit 时跑、构造按定义顺序、析构逆序、
// __cxa_atexit 登记的析构正确触发。

#include <stdio.h>

// 用一个全局序号记录构造/析构顺序，验证顺序正确性。
static int seq = 0;

struct Tracker {
    const char *name;
    int ctor_seq;
    int dtor_seq;
    Tracker(const char *n) : name(n), ctor_seq(++seq), dtor_seq(0) {
        printf("[%d] ctor %s\n", ctor_seq, name);
    }
    ~Tracker() {
        dtor_seq = ++seq;
        printf("[%d] dtor %s\n", dtor_seq, name);
    }
};

// 定义顺序 = 构造顺序（a 先于 b）；析构逆序（b 先于 a）。
Tracker a("alpha");
Tracker b("beta");

// 验证 ctor 改了的状态能保留到 main
struct State {
    int v;
    State() : v(42) {}
    ~State() { printf("State dtor v=%d\n", v); }
};
State g;

int main() {
    printf("main: g.v=%d a.ctor_seq=%d b.ctor_seq=%d\n", g.v, a.ctor_seq, b.ctor_seq);
    g.v = 99;
    // a 应先构造(seq=1)，b 后构造(seq=2)
    if (a.ctor_seq != 1 || b.ctor_seq != 2) {
        printf("FAIL ctor order: a=%d b=%d\n", a.ctor_seq, b.ctor_seq);
        return 1;
    }
    if (g.v != 99) {
        printf("FAIL state: g.v=%d\n", g.v);
        return 1;
    }
    printf("main done, exiting (dtors should run in reverse order: beta, alpha, State)\n");
    return 0;
}
