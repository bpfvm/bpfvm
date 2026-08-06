/* Stress: call faccessat with flag=0 (3-arg path) many times via musl wrapper,
 * check for inconsistent results (garbage r4 causing sporadic EINVAL/wrong perm).
 * 样本用 guest 自建文件（跨沙箱环境一致，不依赖系统路径如 /bin）。 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
int main(void){
    int fd = open("stress_fac_sample", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { printf("create sample failed errno=%d\n", errno); return 1; }
    write(fd, "x", 1);
    close(fd);
    int fails=0;
    for(int i=0;i<200;i++){
        int r=faccessat(AT_FDCWD,"stress_fac_sample",R_OK,0);
        if(r!=0){ printf("iter %d: faccessat failed errno=%d\n",i,errno); fails++; if(fails>5)break;}
    }
    unlink("stress_fac_sample");
    printf("stress: %d failures\n",fails);
    return fails?1:0;
}
