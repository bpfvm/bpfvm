/*
 * /proc/[pid]/task 子目录 + thread-self 符号链接穿透测试。
 *
 * 覆盖点（本次 procfs 重构新增的能力）：
 *   1. /proc/[pid]/task 目录可列举，单线程进程至少能看到 leader（自己的 tid）。
 *   2. 多线程时 task 目录列出每个 tid，数量与创建的线程一致。
 *   3. /proc/thread-self 是相对符号链接（"<tgid>/task/<tid>"），readlink 返回原始相对
 *      target；stat（follow）穿透到 /proc/[tgid]/task/[tid] 目录。
 *   4. /proc/[pid]/task/[tid]/comm 可读，内容是该线程的 comm。
 *   5. getdents 的 "." 和 ".." 条目存在。
 *
 * 通过标准：打印 ok 并退出码 0。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>

#define CHECK(expr, msg) do { if(!(expr)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while(0)

static volatile int g_ready = 0;
static volatile int g_done = 0;

static void* worker(void* arg) {
    (void)arg;
    g_ready = 1;
    /* 留在线程里，等主线程查验完 task 列表（g_done 置 1）再退出 */
    while (!g_done) usleep(50);
    return NULL;
}

/* 数 /proc/[pid]/task 下名为纯数字的条目（即 tid），并确认 leader_tid 在其中。 */
static int count_tasks(pid_t pid, pid_t leader_tid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", (int)pid);
    DIR* d = opendir(path);
    CHECK(d != NULL, "open task dir");
    int n = 0, saw_leader = 0, saw_dot = 0, saw_dotdot = 0;
    struct dirent* e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0) { saw_dot = 1; continue; }
        if (strcmp(e->d_name, "..") == 0) { saw_dotdot = 1; continue; }
        /* tid 条目是纯数字 */
        char* end;
        long tid = strtol(e->d_name, &end, 10);
        if (*end == '\0' && tid > 0) {
            n++;
            if (tid == leader_tid) saw_leader = 1;
        }
    }
    closedir(d);
    CHECK(saw_dot && saw_dotdot, "task dir has . and ..");
    CHECK(saw_leader, "task dir lists leader tid");
    return n;
}

int main(void) {
    pid_t pid = getpid();
    pid_t tid = gettid();

    /* 1. 单线程：task 至少有自己（leader） */
    int n1 = count_tasks(pid, tid);
    CHECK(n1 >= 1, "single-thread task count");

    /* 2. thread-self readlink 返回原始相对 target（"<tgid>/task/<tid>"） */
    char linkbuf[256];
    ssize_t ln = readlink("/proc/thread-self", linkbuf, sizeof(linkbuf) - 1);
    CHECK(ln > 0, "readlink thread-self");
    linkbuf[ln] = '\0';
    char expect[64];
    snprintf(expect, sizeof(expect), "%d/task/%d", (int)pid, (int)tid);
    CHECK(strcmp(linkbuf, expect) == 0, "thread-self target is relative <tgid>/task/<tid>");

    /* 3. stat(thread-self) follow 穿透后是目录 */
    struct stat st;
    CHECK(stat("/proc/thread-self", &st) == 0 && S_ISDIR(st.st_mode), "stat thread-self is dir");
    /* lstat 不穿透：是符号链接 */
    CHECK(lstat("/proc/thread-self", &st) == 0 && S_ISLNK(st.st_mode), "lstat thread-self is link");

    /* 4. 起一个线程，task 计数应增加 */
    pthread_t t;
    CHECK(pthread_create(&t, NULL, worker, NULL) == 0, "pthread_create");
    /* 等子线程真正起来 */
    while (!g_ready) usleep(100);

    int n2 = count_tasks(pid, tid);
    CHECK(n2 == n1 + 1, "task count increased by 1 after thread create");

    /* 5. 枚举 task，读每个 [tid]/comm 应非空 */
    {
        char base[64];
        snprintf(base, sizeof(base), "/proc/%d/task", (int)pid);
        DIR* d = opendir(base);
        CHECK(d != NULL, "reopen task dir");
        struct dirent* e;
        int read_comm_ok = 0;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
            char* end;
            long tid = strtol(e->d_name, &end, 10);
            if (*end == '\0' && tid > 0) {
                char cpath[128];
                snprintf(cpath, sizeof(cpath), "%s/%s/comm", base, e->d_name);
                int fd = open(cpath, O_RDONLY);
                CHECK(fd >= 0, "open task/[tid]/comm");
                char buf[128];
                ssize_t r = read(fd, buf, sizeof(buf) - 1);
                close(fd);
                CHECK(r > 0, "read task/[tid]/comm");
                read_comm_ok++;

                /* [tid]/status 的 Pid 字段应是该 tid（线程视角），Tgid 仍是组长 tgid */
                snprintf(cpath, sizeof(cpath), "%s/%s/status", base, e->d_name);
                fd = open(cpath, O_RDONLY);
                CHECK(fd >= 0, "open task/[tid]/status");
                r = read(fd, buf, sizeof(buf) - 1);
                close(fd);
                CHECK(r > 0, "read task/[tid]/status");
                buf[r > 0 ? r : 0] = '\0';
                char pid_line[32];
                snprintf(pid_line, sizeof(pid_line), "Pid:\t%ld", tid);
                CHECK(strstr(buf, pid_line) != NULL, "task/[tid]/status Pid is tid");
                snprintf(pid_line, sizeof(pid_line), "Tgid:\t%d", (int)pid);
                CHECK(strstr(buf, pid_line) != NULL, "task/[tid]/status Tgid is tgid");
            }
        }
        closedir(d);
        CHECK(read_comm_ok == n2, "read comm for every tid");
    }

    /* 6. task/[tid] 不应再嵌套 task 子目录（真实 Linux：只有 tgid 目录才有 task） */
    {
        char no_task[128];
        snprintf(no_task, sizeof(no_task), "/proc/%d/task/%d/task", (int)pid, (int)tid);
        struct stat stbuf;
        CHECK(stat(no_task, &stbuf) < 0 && errno == ENOENT, "task/[tid]/task not nested");
    }

    /* 收尾：让子线程退出并 join */
    g_done = 1;
    pthread_join(t, NULL);

    printf("ok\n");
    return 0;
}
