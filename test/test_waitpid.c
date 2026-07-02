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

    // Wait for the killed child. POSIX 语义：被信号杀死时 WIFSIGNALED 为真，
    // WTERMSIG 给出信号号（SIGKILL=9）。status 低 7 位 = 信号号，WIFEXITED 为假。
    int status = 0;
    pid_t wpid = waitpid(pid, &status, 0);

    if (wpid != pid) {
        printf("waitpid returned %d, expected %d\n", wpid, pid);
        return 1;
    }

    if (!WIFSIGNALED(status)) {
        printf("expected WIFSIGNALED, got status=0x%x\n", status);
        return 1;
    }
    if (WTERMSIG(status) != SIGKILL) {
        printf("WTERMSIG=%d expected %d\n", WTERMSIG(status), SIGKILL);
        return 1;
    }

    printf("waitpid successfully collected killed child\n");
    return 0;
}
