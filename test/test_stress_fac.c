/* Stress: call faccessat with flag=0 (3-arg path) many times via musl wrapper,
 * check for inconsistent results (garbage r4 causing sporadic EINVAL/wrong perm). */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
int main(void){
    int fails=0;
    for(int i=0;i<200;i++){
        int r=faccessat(AT_FDCWD,"/bin",R_OK|X_OK,0);
        if(r!=0){ printf("iter %d: faccessat failed errno=%d\n",i,errno); fails++; if(fails>5)break;}
    }
    printf("stress: %d failures\n",fails);
    return fails?1:0;
}
