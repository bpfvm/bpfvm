// emutls spike：验证 thread_local 变量在 bpfvm 上正确工作。
// 机制见 README「模拟 TLS (emutls)」。
//
// 覆盖：零初始化、非零初始化模板、单线程读写、多线程隔离、数组/struct 的 GEP 访问、
// 取地址 &var（函数内逃逸：ret/call arg/store）、聚合初始化非平凡类型（无用户构造函数）。

#include <pthread.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

// 零初始化（控制块 value=NULL，副本靠 mmap 清零）
thread_local int counter = 0;
// 非零初始化（控制块 value 指向模板 __emutls_t.init_val，首次访问 memcpy）
thread_local int init_val = 42;
// 数组（经 GEP 访问）
thread_local int arr[4] = {10, 20, 30, 40};
// struct（经 GEP 访问字段）
struct Point { int x; int y; };
thread_local Point pt = {1, 2};

// 聚合初始化的非平凡类型（无用户构造函数，initializer 直接进 GV；非平凡析构由
// collectDtors 处理）——「带析构的 thread_local」的可用形态。
struct Tracker { int v; ~Tracker(); };
thread_local Tracker tracked{7};

// 函数内取地址 &var：pass 把 &var 在使用点改写为 __emutls_get_address 返回的副本
// 指针。覆盖三种逃逸形态：ret / call arg / store。
static int *get_counter_addr() { return &counter; }       // ret 形态
// consume_ptr 标 noinline，确保 &init_val 真正跨越函数边界（call arg 形态）而非被
// -O1 内联消解掉。
extern "C" int consume_ptr(int *p) __attribute__((noinline));
static int via_call_arg() { return consume_ptr(&init_val); } // call arg 形态

struct Arg {
    int id;
    int result;
};

// consume_ptr：返回 *p，验证传入的是有效副本指针。
extern "C" __attribute__((noinline)) int consume_ptr(int *p) { return *p; }

// Tracker 的析构定义：累加到全局计数，便于校验主线程副本被析构。
static volatile int g_tracked_dtor_sum = 0;
Tracker::~Tracker() { g_tracked_dtor_sum += v; }

static void *worker(void *p) {
    struct Arg *a = (struct Arg *)p;
    // 各线程写独立值，验证与主线程/其他线程隔离
    counter = a->id;
    init_val = a->id * 1000;
    arr[a->id] = a->id * 10;     // 数组写入
    pt.x = a->id;                // struct 字段写入
    for (int i = 0; i < 100; i++) {
        counter++;
        init_val++;
        pt.y++;
    }
    a->result = counter + init_val + arr[a->id] + pt.x + pt.y;
    return nullptr;
}

int main() {
    // (1) 单线程基本读写（含数组 + struct）
    counter = 5;
    counter++;
    int c = counter;       // 6
    int iv = init_val;     // 42（模板初始化）
    arr[2] = 99;           // 改数组
    int arr_sum = arr[0] + arr[1] + arr[2] + arr[3];  // 10+20+99+40 = 169
    pt.x = 7; pt.y = 8;    // 改 struct
    int pt_sum = pt.x + pt.y;  // 15

    if (c != 6 || iv != 42 || arr_sum != 169 || pt_sum != 15) {
        printf("FAIL single-thread: c=%d iv=%d arr=%d pt=%d\n", c, iv, arr_sum, pt_sum);
        return 1;
    }

    // (1b) 聚合初始化非平凡类型：tracked.v 应为模板初值 7（首次访问 memcpy 模板）
    int tv = tracked.v;
    tracked.v = 100;
    int tv2 = tracked.v;
    if (tv != 7 || tv2 != 100) {
        printf("FAIL tracked: tv=%d tv2=%d expected 7,100\n", tv, tv2);
        return 1;
    }

    // (1c) 取地址 &var：
    //   get_counter_addr() 返回 counter 副本指针 -> 经它写入应改 counter
    //   via_call_arg() 把 &init_val 传入外部函数 -> 应读到模板初值 42
    counter = 11;
    int *cp = get_counter_addr();
    *cp = 22;   // 经指针写，counter 应变 22
    int counter_via_ptr = counter;   // 直接读验证
    counter = 33;
    int counter_via_ptr2 = *get_counter_addr();  // 再次经指针读
    int iv_via_call = via_call_arg();  // &init_val 经 call arg
    if (counter_via_ptr != 22 || counter_via_ptr2 != 33 || iv_via_call != 42) {
        printf("FAIL &var: cp=%d cp2=%d iv_call=%d expected 22,33,42\n",
               counter_via_ptr, counter_via_ptr2, iv_via_call);
        return 1;
    }

    // (2) 多线程隔离
    counter = -1;
    init_val = 999;
    struct Arg args[3] = {{1, 0}, {2, 0}, {3, 0}};
    pthread_t threads[3];
    for (int i = 0; i < 3; i++)
        pthread_create(&threads[i], nullptr, worker, &args[i]);
    for (int i = 0; i < 3; i++)
        pthread_join(threads[i], nullptr);

    // 主线程的 TLS 值应完全不受子线程影响
    if (counter != -1 || init_val != 999) {
        printf("FAIL main isolation: counter=%d init_val=%d\n", counter, init_val);
        return 1;
    }
    // 每个子线程：
    //   counter = id+100, init_val = id*1000+100, arr[id] = id*10,
    //   pt.x = id（覆盖模板值 1）, pt.y = 2+100（模板值 2 + 100 次自增）
    //   result = (id+100) + (id*1000+100) + (id*10) + id + (2+100)
    //          = id*1012 + 302
    for (int i = 0; i < 3; i++) {
        int id = i + 1;
        int expected = id * 1012 + 302;
        if (args[i].result != expected) {
            printf("FAIL thread %d: result=%d expected=%d\n", id, args[i].result, expected);
            return 1;
        }
    }

    // (3) fork 继承：子进程应继承父进程当前的 TLS 值（POSIX fork 语义）
    counter = 555;
    init_val = 777;
    pid_t pid = fork();
    if (pid == 0) {
        // 子进程：counter/init_val 应等于父 fork 时的值（555/777），而非模板初值
        _exit(counter == 555 && init_val == 777 ? 0 : 1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            printf("FAIL fork inherit: child exit status=%d\n", status);
            return 1;
        }
    } else {
        perror("fork");
        return 1;
    }
    // fork 后父进程的值不变
    if (counter != 555 || init_val != 777) {
        printf("FAIL fork parent: counter=%d init_val=%d\n", counter, init_val);
        return 1;
    }

    printf("counter=%d init_val=%d results=%d,%d,%d\n",
           counter, init_val, args[0].result, args[1].result, args[2].result);
    return 0;
}
