#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>

static volatile sig_atomic_t got_usr1 = 0;

static void on_usr1(int sig) {
    got_usr1 = 1;
}

int main(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_usr1;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        perror("sigaction");
        return 1;
    }
    
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // Child: wait a bit then signal parent
        sleep(1);
        printf("Child sending SIGUSR1 to parent %d\n", getppid());
        kill(getppid(), SIGUSR1);
        _exit(0);
    } else {
        // Parent: long sleep
        printf("Parent sleeping for 5 seconds...\n");
        unsigned int rem = sleep(5);
        printf("Parent woke up, rem=%u, got_usr1=%d\n", rem, (int)got_usr1);
        
        int status;
        wait(&status);
        
        if (got_usr1 == 1 && rem > 0) {
            printf("Test passed: sleep was interrupted\n");
            return 0;
        } else {
            printf("Test failed: sleep was not interrupted or signal not received (rem=%u, got_usr1=%d)\n", rem, (int)got_usr1);
            return 1;
        }
    }
}