/*
 * reparent 验证（leader 先于 last 退出的多线程变体）：
 *   pid1 fork 子 C；C 的 leader fork 孙 G 后 pthread_exit（非 last 退出），worker 睡 1s
 *   后退出（last）。整组退出时由 last 线程（worker）的 fini 扫描 pid_map 把 ppid==C tgid
 *   的 G 重定向到 pid 1。G 轮询 getppid()==1 即成功。
 *
 * 这条路径验证 reparent 修复的关键点：reparent 不再挂在 leader、改由 last 线程按 tgid
 * 匹配执行——leader 先退出时也不能漏 reparent。
 *
 * 当前预期：撞预存的 CoW UAF（fork+跨进程并发写缺页，G 写 .data 段触发深拷贝时读到已
 * munmap 的页 → 段错误）。该 bug 与 reparent 改动无关，待单独修复；修好后本测试应通过。
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>

static void *worker(void *a){ (void)a; sleep(1); return NULL; }

int main(void){
    pid_t c = fork();
    if(c == 0){
        /* C：leader。创建 worker（使 C 多线程），fork 孙 G，然后 leader 先退出 */
        pthread_t t;
        pthread_create(&t, NULL, worker, NULL);
        pid_t g = fork();
        if(g == 0){
            /* G：等被 reparent 到 pid 1 */
            for(int i = 0; i < 30; i++){
                if(getppid() == 1) _exit(0);
                usleep(100000);
            }
            _exit(1);  /* 超时未 reparent */
        }
        pthread_exit(NULL);  /* leader 退出，非 last；worker 仍在，由 worker 收尾 reparent */
    }

    /* pid 1：先收 C，再收被 reparent 过来的 G */
    int st;
    waitpid(c, &st, 0);
    waitpid(-1, &st, 0);  /* G 现在是 pid 1 的孩子 */
    return WEXITSTATUS(st) == 0 ? 0 : 1;
}
