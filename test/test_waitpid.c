#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    pid_t pid = fork();
    if (pid < 0) {
        printf("fork failed\n");
        return 1;
    }

    if (pid == 0) {
        // Child process: infinite loop waiting to be killed
        while (1) {
        }
        return 0;
    }

    // Parent process
    // Sleep purely to ensure the child starts scheduling
    sleep(2);

    // Send SIGKILL
    if (kill(pid, SIGKILL) != 0) {
        printf("kill failed\n");
        return 1;
    }

    // Wait for the killed child
    int status = 0;
    pid_t wpid = waitpid(pid, &status, 0);
    
    if (wpid != pid) {
        printf("waitpid returned %d, expected %d\n", wpid, pid);
        return 1;
    }

    int code = ((unsigned int)status >> 8) & 0xff;
    int expected = 128 + SIGKILL;
    
    if (code != expected) {
        printf("Child exited with %d, expected %d\n", code, expected);
        return 1;
    }

    printf("waitpid successfully collected killed child\n");
    return 0;
}
