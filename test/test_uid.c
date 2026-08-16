// test_uid.c — 验证 bpfvm 的身份查询 syscall（getuid/geteuid/getgid/getegid/getgroups）。
//
// bpfvm 是单用户系统，uid/euid/gid/egid 恒为 0，无补充组。
// 关键正确性点（而非具体 uid 值，使其同时适用于 bpfvm 与 host 对照）：
//   -  返回值非负（不是 -ENOSYS=-38 的负值）——验证 syscall 已实现。
//   -  uid==euid 且 gid==egid（无 setuid/setgid 差异 -> OPENSSL_issetugid 返 0）。
//   -  getgroups 一致：getgroups(0)==n 后 getgroups(n,buf)==n（无补充组在 bpfvm 下 n==0）。
//
// 这三条对 bpfvm（uid=0,n=0）和 host（如 uid=1000,n=14）都成立，故 host 对照也通过。

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <errno.h>

int main(void) {
    int fails = 0;

    uid_t uid = getuid();
    uid_t euid = geteuid();
    gid_t gid = getgid();
    gid_t egid = getegid();

    printf("uid=%u euid=%u gid=%u egid=%u\n", uid, euid, gid, egid);

    /* -  非 -ENOSYS：uid_t 是无符号，但 musl/bpfvm 下未实现时 raw 返回 -38，
     *    强转 uint 后是 0xFFFFFFDA。用 (int) 强转判负检测这条（host 上不会触发）。 */
    if ((int)uid < 0)  { printf("FAIL getuid: 返回负值 %d（syscall 未实现？）\n", (int)uid); fails++; }
    if ((int)euid < 0) { printf("FAIL geteuid: 返回负值 %d\n", (int)euid); fails++; }
    if ((int)gid < 0)  { printf("FAIL getgid: 返回负值 %d\n", (int)gid); fails++; }
    if ((int)egid < 0) { printf("FAIL getegid: 返回负值 %d\n", (int)egid); fails++; }

    /* -  OPENSSL_issetugid 判定的核心：uid==euid && gid==egid（非 setugid 运行）。 */
    if (uid != euid) { printf("FAIL: uid(%u) != euid(%u) -> issetugid 会误判\n", uid, euid); fails++; }
    if (gid != egid) { printf("FAIL: gid(%u) != egid(%u) -> issetugid 会误判\n", gid, egid); fails++; }

    /* -  getgroups 一致性：先查个数，再取列表，两次返回值应相等。 */
    int n = getgroups(0, NULL);
    if (n < 0) { printf("FAIL getgroups(0): %d (%s)\n", n, strerror(errno)); fails++; }
    else {
        gid_t groups[64];
        int m = getgroups(n < 64 ? n : 64, groups);
        if (m != n) { printf("FAIL getgroups: 个数 %d 与实取 %d 不一致\n", n, m); fails++; }
        else printf("getgroups: %d 组（一致）\n", n);
    }

    if (fails == 0) {
        printf("PASS uid/gid\n");
        return 0;
    }
    printf("%d FAIL(s)\n", fails);
    return 1;
}
