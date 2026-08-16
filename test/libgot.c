/* libgot.c — 共享库：导出函数/变量，且内部调用 libc（构造链式依赖）。
   不带 _start（由 libc.so 提供）。
   - got_counter  : STT_OBJECT 导出（走 .rela.dyn）
   - got_add      : STT_FUNC 导出，简单加法（走 PLT/GOT）
   - got_hash     : STT_FUNC 导出，内部调 libc 的 strlen -> libgot.so DT_NEEDED libc.so
                    主程序只直接依赖 libgot.so，间接依赖 libc.so（链式） */
#include <string.h>

__attribute__((used))
int got_counter = 100;

__attribute__((used))
int got_add(int a, int b) {
    return a + b;
}

__attribute__((used))
int got_hash(const char *s) {
    return (int)strlen(s) + got_counter;
}
