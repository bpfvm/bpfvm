/* test_dyn_data.c — 验证跨模块数据引用、PLT/GOT 调用、以及链式依赖。

   依赖拓扑（动态版）：
     test_dyn_data.linked
        └─ (DT_NEEDED) libgot.so
              └─ (DT_NEEDED) libc.so     <- libgot 内部调用 strlen

   验证：
   - got_counter（STT_OBJECT, libgot 导出）：主程序 .rela.dyn 运行时 patch
   - got_add（STT_FUNC, libgot 导出）：主程序经 PLT/GOT 调用
   - got_hash（STT_FUNC, libgot 导出，内部调 libc strlen）：链式 PLT/GOT
     - loader 必须递归加载 libgot 的 DT_NEEDED（libc.so），否则 strlen 解析失败
     - libgot 自身也走 PLT 调用 libc，验证 .so 内部 PLT 桩在运行期可解析
   - .so 可在任意地址加载（PIE，p_vaddr=0）

   静态版（.out）把 libgot.a + libpdclib.a 直接链入，构建期 patch，应当通过。 */

#include <stdio.h>

extern int got_add(int, int);
extern int got_hash(const char *);
extern int got_counter;

int main(void) {
    int before = got_counter;     /* 100 */
    int r = got_add(19, 23);       /* 42 */
    int after = got_counter;       /* 仍 100（got_add 不改 counter） */
    int h = got_hash("hello");     /* strlen("hello") + 100 = 105 */

    if (before != 100) {
        printf("FAIL: got_counter before=%d (expected 100)\n", before);
        return 1;
    }
    if (r != 42) {
        printf("FAIL: got_add(19,23)=%d (expected 42)\n", r);
        return 1;
    }
    if (after != 100) {
        printf("FAIL: got_counter after=%d (expected 100)\n", after);
        return 1;
    }
    if (h != 105) {
        printf("FAIL: got_hash(\"hello\")=%d (expected 105)\n", h);
        return 1;
    }
    printf("data reloc ok: counter=%d, got_add=%d, got_hash=%d\n", after, r, h);
    return 0;
}
