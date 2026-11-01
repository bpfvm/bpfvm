// PR_SET_NAME/PR_GET_NAME：guest 头无 linux/prctl.h，常量按内核值定义
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PR_SET_NAME 15
#define PR_GET_NAME 16

extern int prctl(int, ...);

static int read_comm_procfs(char* buf, size_t n) {
    FILE* f = fopen("/proc/self/comm", "r");
    if(!f) return -1;
    if(!fgets(buf, (int)n, f)) { fclose(f); return -1; }
    fclose(f);
    buf[strcspn(buf, "\n")] = 0;
    return 0;
}

int main(void) {
    char comm[32];

    if(prctl(PR_SET_NAME, "testprctl") != 0) {
        fprintf(stderr, "PR_SET_NAME failed\n");
        return 1;
    }
    if(prctl(PR_GET_NAME, comm) != 0 || strcmp(comm, "testprctl") != 0) {
        fprintf(stderr, "PR_GET_NAME got: %s\n", comm);
        return 2;
    }
    if(read_comm_procfs(comm, sizeof(comm)) != 0 || strcmp(comm, "testprctl") != 0) {
        fprintf(stderr, "/proc/self/comm got: %s\n", comm);
        return 3;
    }
    // 长名截断到 15 字节（TASK_COMM_LEN-1，同 Linux）
    if(prctl(PR_SET_NAME, "0123456789ABCDEFgh") != 0) {
        fprintf(stderr, "PR_SET_NAME long failed\n");
        return 4;
    }
    if(prctl(PR_GET_NAME, comm) != 0 || strcmp(comm, "0123456789ABCDE") != 0) {
        fprintf(stderr, "truncate got: %s\n", comm);
        return 5;
    }
    printf("prctl comm ok\n");
    return 0;
}
