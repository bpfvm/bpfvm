#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        perror("clock_gettime");
        return 1;
    }
    printf("clock_gettime(CLOCK_REALTIME): %ld.%09ld\n", (long)ts.tv_sec, (long)ts.tv_nsec);

    struct timeval tv;
    if (gettimeofday(&tv, NULL) == -1) {
        perror("gettimeofday");
        return 1;
    }
    printf("gettimeofday: %ld.%06ld\n", (long)tv.tv_sec, (long)tv.tv_usec);

    if (ts.tv_sec > tv.tv_sec || (ts.tv_sec == tv.tv_sec && ts.tv_nsec / 1000 > tv.tv_usec)) {
        printf("Time went backwards!\n"); // Should not happen if called close together
    } else {
        printf("Time is moving forward (or same).\n");
    }

    return 0;
}

