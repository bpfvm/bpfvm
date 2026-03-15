#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    long page_size = sysconf(_SC_PAGESIZE);
    if(page_size <= 0) {
        printf("sysconf(_SC_PAGESIZE) failed\n");
        return 1;
    }

    char *buf = mmap((size_t)page_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(buf == MAP_FAILED) {
        perror("mmap");
        return 2;
    }

    errno = 0;
    if(getcwd(buf, (size_t)page_size) != NULL) {
        printf("getcwd unexpectedly succeeded\n");
        return 3;
    }
    if(errno != EFAULT) {
        printf("getcwd failed with errno=%d\n", errno);
        return 4;
    }

    puts("ok");
    return 0;
}
