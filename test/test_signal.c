#include <stdio.h>
#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t got_term = 0;

static void on_term(int sig) {
    (void)sig;
    got_term++;
}

int main(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_term;
    if (sigaction(SIGTERM, &sa, NULL) != 0) {
        perror("sigaction");
        return 1;
    }

    if (kill(getpid(), SIGTERM) != 0) {
        perror("kill");
        return 2;
    }

    if (kill(getpid(), SIGTERM) != 0) {
        perror("kill");
        return 2;
    }

    printf("got_term=%d\n", (int)got_term);
    return (got_term == 2) ? 0 : 3;
}
