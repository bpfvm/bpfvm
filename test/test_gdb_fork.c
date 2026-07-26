//
// 多进程 GDB 调试测试程序：fork 出一个子进程，父子各自循环输出不同的计数。
// 用于验证 bpfvm gdbserver 的：
//   - multiprocess+ 扩展（info inferiors / info threads 显示父子两个进程）
//   - 真 all-stop（子进程命中断点时父进程也停下）
//   - vCont per-thread action（单独单步/继续某个进程）
//   - fork 子进程继承断点（do_clone 里 child 继承父 VM_DEBUG_ATTACHED + 断点集）
//
// 运行方式：
//   1. CTest 自动跑（非 GDB 模式）：作为普通 test_* 用例被 CMake glob 自动注册，
//      ./build/bpfvm test/test_gdb_fork.out 直接跑完，验证 fork + waitpid 基本功能
//      （父子各循环 3 次，父 waitpid 收到子 exit 42，最终 exit 0）。
//   2. 手测（需 patched GDB，见 patches/README.md）——多进程调试专项验证。
//      对齐 QEMU -gdb/-S 的两种启动模式 + 可重复 attach：
//
//      默认模式（VM 全速 JIT 跑，GDB 连上才 attach，停在当前 pc）：
//        终端1: ./build/bpfvm --gdb 12345 test/test_gdb_fork.out
//        终端2:
//          gdb
//          (gdb) set architecture bpf
//          (gdb) file test/test_gdb_fork.out
//          (gdb) target remote 127.0.0.1:12345   # 连上即 attach pid 1
//          (gdb) info registers                   # pc 应在某个非入口地址（连上前在跑）
//          (gdb) detach                           # 断开后 pid 1 恢复全速，server 等下次连接
//          (gdb) target remote 127.0.0.1:12345   # 可重复 attach，再次停在当前 pc
//
//      冻结模式（run() 前冻结 pid 1 在入口，等 GDB 连）：
//        终端1: ./build/bpfvm --gdb 12345 --stop test/test_gdb_fork.out
//        终端2:
//          gdb
//          (gdb) set architecture bpf
//          (gdb) file test/test_gdb_fork.out
//          (gdb) target remote 127.0.0.1:12345   # pc 在程序入口
//          (gdb) info inferiors          # 应显示 2 个 inferior（fork 后）
//          (gdb) break parent_work
//          (gdb) break child_work
//          (gdb) continue
//          ...
//

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

// 标记函数，方便按符号名下断点（-O0 下不会内联）。
__attribute__((noinline)) int parent_work(int n) {
    printf("[parent] count=%d\n", n);
    return n + 1;
}

__attribute__((noinline)) int child_work(int n) {
    printf("[child ] count=%d\n", n);
    return n + 1;
}

int main(void) {
    pid_t pid = fork();
    if (pid < 0) {
        printf("fork failed\n");
        return 1;
    }

    if (pid == 0) {
        // 子进程：循环 3 次
        int n = 0;
        for (int i = 0; i < 3; i++) {
            n = child_work(n);
        }
        return n == 3 ? 42 : 1;
    }

    // 父进程：循环 3 次
    int n = 0;
    for (int i = 0; i < 3; i++) {
        n = parent_work(n);
    }

    // 等子进程退出
    int status = 0;
    waitpid(pid, &status, 0);

    // 子进程应正常退出且返回 42（WIFEXITED && WEXITSTATUS==42）
    return (n == 3 && WIFEXITED(status) && WEXITSTATUS(status) == 42) ? 0 : 1;
}
