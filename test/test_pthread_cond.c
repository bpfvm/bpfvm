#include <stdio.h>
#include <pthread.h>

static int produced = 0;
static int consumed = 0;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

#define NITEMS 1000

static void *producer(void *arg) {
    (void)arg;
    for (int i = 0; i < NITEMS; i++) {
        pthread_mutex_lock(&mtx);
        produced++;
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&mtx);
    }
    return NULL;
}

static void *consumer(void *arg) {
    (void)arg;
    while (consumed < NITEMS) {
        pthread_mutex_lock(&mtx);
        while (produced <= consumed) {
            pthread_cond_wait(&cond, &mtx);
        }
        consumed++;
        pthread_mutex_unlock(&mtx);
    }
    return NULL;
}

int main(void) {
    pthread_t p, c;
    if (pthread_create(&p, NULL, producer, NULL) != 0) {
        printf("create producer failed\n");
        return 1;
    }
    if (pthread_create(&c, NULL, consumer, NULL) != 0) {
        printf("create consumer failed\n");
        return 1;
    }
    pthread_join(p, NULL);
    pthread_join(c, NULL);
    if (produced != NITEMS || consumed != NITEMS) {
        printf("produced=%d consumed=%d expected %d\n", produced, consumed, NITEMS);
        return 1;
    }
    printf("pthread cond ok\n");
    return 0;
}
