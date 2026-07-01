#include <stdio.h>
#include <pthread.h>

static long counter = 0;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

#define NTHREADS 4
#define ITERS 50000

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < ITERS; i++) {
        pthread_mutex_lock(&mtx);
        counter++;
        pthread_mutex_unlock(&mtx);
    }
    return NULL;
}

int main(void) {
    pthread_t threads[NTHREADS];
    for (int i = 0; i < NTHREADS; i++) {
        if (pthread_create(&threads[i], NULL, worker, NULL) != 0) {
            printf("pthread_create %d failed\n", i);
            return 1;
        }
    }
    for (int i = 0; i < NTHREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    long expected = (long)NTHREADS * ITERS;
    if (counter != expected) {
        printf("counter=%ld expected %ld\n", counter, expected);
        return 1;
    }
    printf("pthread mutex ok, counter=%ld\n", counter);
    return 0;
}
