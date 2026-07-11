#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    pid_t pid=fork();
    if(pid==0){
        struct timespec ts={5,0}, rem={0};
        int rc=nanosleep(&ts,&rem);
        printf("child: nanosleep rc=%d errno=%d rem=%ld.%03ld\n",rc,errno,(long)rem.tv_sec,(long)rem.tv_nsec/1000000);
        _exit(rc==0?0:1);
    }
    usleep(300000);
    kill(pid, SIGTSTP);
    int st;
    for(int i=0;i<20;i++){ if(waitpid(pid,&st,WUNTRACED|WNOHANG)) break; usleep(100000);}
    printf("parent: after SIGTSTP stopped=%d\n", WIFSTOPPED(st));
    usleep(200000);
    kill(pid, SIGCONT);
    usleep(1000000);
    int rc=waitpid(pid,&st,WNOHANG);
    printf("parent: after SIGCONT waitpid(WNOHANG)=%d (0=still sleeping correct, %d=exited early BUG)\n",rc,pid);
    if(rc==0){ printf("PASS: still sleeping\n"); kill(pid,SIGKILL); waitpid(pid,&st,0); return 0;}
    printf("FAIL: exited early\n");
    return 1;
}
