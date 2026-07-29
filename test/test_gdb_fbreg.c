/* GDB fbreg 修复验证程序。
 *
 * 用途：在 bpfvm --gdb 下断点 sum，检查 spill 到栈的局部变量 x/y/z 读出的值正确
 *      （依赖 bpfvm-ld 用 .stack_sizes 修复 DW_OP_fbreg 偏移）。手动验证步骤：
 *        bpfvm --gdb <port> --stop test_gdb_fbreg.out
 *        gdb> break test_gdb_fbreg.c:7
 *        gdb> continue
 *        gdb> print x   # 期望 11
 *        gdb> print y   # 期望 22
 *        gdb> print z   # 期望 33
 *
 * 作为 ctest：只验证能编译链接运行（exit 0）；fbreg 正确性靠上面的 GDB 手动步骤。
 * sum 的 x/y/z 因 volatile + 跨 call 被 spill 到栈，产生 DW_OP_fbreg。
 */
int __attribute__((noinline)) sum(int a, int b) {
    volatile int x = a, y = b;
    volatile int z = x + y;
    return (x + y + z) & 0x7f;   /* a*2 + b*2 = 2*(11+22)=66 */
}
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    int r = sum(11, 22);
    return r == 66 ? 0 : 1;   /* 66 = 2*(11+22)；正确则 exit 0 */
}
