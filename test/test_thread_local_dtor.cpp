// 验证非平凡可析构的 thread_local 变量在每个线程的副本上各自被析构
//（机制见 README「模拟 TLS (emutls)」）。
//
// 用「聚合构造 + 用户析构」的形态（struct{int v; ~T(){...}}）：带用户构造函数的
// thread_local 会被 pass 编译期拒绝，但聚合构造 + 非平凡析构是支持的。

#include <pthread.h>
#include <stdio.h>

// 非平凡析构（用户定义 ~T），平凡聚合构造（{v} 初始化）。
struct Tracker {
    int v;
    ~Tracker();
};

// 全局析构计数。析构在各线程退出时单独跑、join 已同步，无并发竞争。用 volatile
// 防止被优化掉。
static volatile int g_dtor_count = 0;
static volatile int g_dtor_values = 0;   // 累加各副本析构时的 v，便于校验

Tracker::~Tracker() {
    g_dtor_count = g_dtor_count + 1;
    g_dtor_values = g_dtor_values + v;
}

// 非零初始化的 thread_local（首次访问 memcpy 模板值 7 到本线程副本）。
thread_local Tracker g_tls{7};

struct Arg {
    int id;
    int observed;   // 该线程读到的 g_tls.v（应为模板 7）
};

static void *worker(void *p) {
    struct Arg *a = (struct Arg *)p;
    // 首次访问触发本线程副本分配 + 注册析构；改写副本 v，析构时累加。
    a->observed = g_tls.v;
    g_tls.v = a->id;
    return 0;
}

int main() {
    // (1) 主线程首次访问（构造在 .init_array 已跑过，此处读副本）
    int main_v = g_tls.v;
    if (main_v != 7) {
        printf("FAIL main init: g_tls.v=%d expected 7\n", main_v);
        return 1;
    }
    g_tls.v = 100;   // 主线程副本改写，析构时 +100

    // (2) 两个子线程：各自首次访问 -> 各自分配副本（v=7）-> 各自改 v=id -> 退出各自析构
    struct Arg args[2] = {{1, 0}, {2, 0}};
    pthread_t threads[2];
    for (int i = 0; i < 2; i++)
        pthread_create(&threads[i], 0, worker, &args[i]);
    for (int i = 0; i < 2; i++)
        pthread_join(threads[i], 0);

    // 子线程应都已析构：g_dtor_count==2（每个子线程副本一次），析构值之和=1+2=3。
    // 修复前：子线程副本不析构，此处在 main 内检查时 g_dtor_count==0。
    if (g_dtor_count != 2) {
        printf("FAIL child dtor: g_dtor_count=%d expected 2\n", g_dtor_count);
        return 1;
    }
    if (g_dtor_values != 3) {
        printf("FAIL child dtor values: g_dtor_values=%d expected 3\n", g_dtor_values);
        return 1;
    }
    // 子线程读到模板初值 7（证明各自独立副本 + memcpy 模板）
    if (args[0].observed != 7 || args[1].observed != 7) {
        printf("FAIL child observed: %d %d expected 7 7\n", args[0].observed, args[1].observed);
        return 1;
    }

    printf("child dtor_count=%d dtor_values=%d observed=%d,%d\n",
           g_dtor_count, g_dtor_values, args[0].observed, args[1].observed);
    // 注：主线程副本的析构在 main 返回后由 exit() 触发（g_dtor_count 最终=3，
    // g_dtor_values 最终=103），但无法在 main 内断言（已在退出路径）。
    return 0;
}
