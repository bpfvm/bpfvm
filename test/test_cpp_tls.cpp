// emutls spike：验证 address_space(256) 标记的 TLS 变量在 bpfvm 上正确工作。
//
// 机制（见 AGENTS.md "emutls via address_space(256)" 与 src/passes/BpfEmutls.cpp）：
//   - `__mythread` 宏：BPF 上展开成 `__attribute__((address_space(256)))`，绕过
//     clang 对 thread_local 的拒绝；host 上展开成真正的 thread_local 作对照。
//   - BpfEmutls pass 把对 addrspace(256) 全局的访问改写成 `__bpf_fp_<EMUTLS_ID>`
//     调用（复用 FP 通道 src_reg=2），VM 的 do_softfp 按 ID 分配/查每线程副本。
//
// 覆盖：零初始化、非零初始化模板、单线程读写、多线程隔离。
// 不覆盖（后续扩展）：数组/struct 的 getelementptr 访问、取地址 &var（addrspace
// 不兼容会编译错，是已知限制）。

#ifdef __BPF__
#define __mythread __attribute__((address_space(256)))
#else
#define __mythread thread_local
#endif

#include <pthread.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

// 零初始化（控制块 value=NULL，副本靠 mmap 清零）
__mythread int counter = 0;
// 非零初始化（控制块 value 指向模板 __emutls_t.init_val，首次访问 memcpy）
__mythread int init_val = 42;
// 数组（经 GEP 访问）
__mythread int arr[4] = {10, 20, 30, 40};
// struct（经 GEP 访问字段）
struct Point { int x; int y; };
__mythread Point pt = {1, 2};

struct Arg {
    int id;
    int result;
};

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
