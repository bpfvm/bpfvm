/* test_dlopen.c — 运行期动态加载（dlopen/dlsym/dlclose）验证。

   与 test_dyn_data 的加载期 DT_NEEDED 解析不同，本用例在程序运行中由 guest
   ldso（libc.so 内置的 dynlink.c，含 BPF lddw 双槽重定位）显式 dlopen libgot.so，
   即 CPython 扩展模块（import xxx 背后的 dlopen("xxx.so")）的加载路径。

   依赖拓扑（运行期构建）：
     test_dlopen(.linked)
        └─ (dlopen) libgot.so
              └─ (DT_NEEDED) libc.so     <- libgot 内部调用 strlen，ldso 运行期解析

   验证：
   - dlopen 成功返回句柄
   - dlsym 函数符号（got_add）并跨模块调用
   - dlsym 数据符号（got_counter）：读 + 写回（可写数据段映射，另一符号内可见）
   - 链式依赖：dlopen 的库自身 DT_NEEDED libc.so 被解析（got_hash 内部调 strlen）
   - dlsym 未知符号返回 NULL 且 dlerror 报错
   - 重复 dlopen 同库返回同句柄（引用计数），dlclose 两次后才卸载
   - 首次 dlclose 后库仍存活（引用计数尚余 1），函数仍可调用

   库定位：argv[0] 所在目录（.linked 与 libgot.so 同在 test/；host 版对应
   libgot.host.so）。

   静态版（.out）链入的 libc.a 只含弱桩 dlopen（"Dynamic loading not
   supported"），检测到该错误时打印 SKIP 返回 0——静态 PIE 的运行期动态加载
   不在本用例覆盖范围。 */

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>

#ifdef __bpf__
#define LIB_NAME "libgot.so"
#else
#define LIB_NAME "libgot.host.so"
#endif

static char dir_buf[512];
static char path_buf[600];

static const char *lib_path(const char *argv0) {
    snprintf(dir_buf, sizeof dir_buf, "%s", argv0);
    /* dirname 原地改写 dir_buf，path_buf 独立缓冲避免读写重叠 */
    snprintf(path_buf, sizeof path_buf, "%s/%s", dirname(dir_buf), LIB_NAME);
    return path_buf;
}

int main(int argc, char **argv) {
    const char *path = lib_path(argc > 0 ? argv[0] : "");

    /* dlopen 失败路径：错误经 error() -> dlerror() 对调用方可见 */
    void *badh = dlopen("/no/such/dir/libnone.so", RTLD_NOW | RTLD_LOCAL);
    const char *open_err = dlerror();
    if (badh != NULL || open_err == NULL) {
        printf("FAIL: dlopen nonexistent: h=%p dlerror=%s\n",
               badh, open_err ? open_err : "(null)");
        return 1;
    }

    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (h == NULL) {
        const char *err = dlerror();
        if (err && strcmp(err, "Dynamic loading not supported") == 0) {
            printf("SKIP: %s (static build links the weak dlopen stub)\n", err);
            return 0;
        }
        printf("FAIL: dlopen(%s): %s\n", path, err ? err : "(no error)");
        return 1;
    }

    int (*add)(int, int) = dlsym(h, "got_add");
    int (*hash)(const char *) = dlsym(h, "got_hash");
    int *counter = dlsym(h, "got_counter");
    if (!add || !hash || !counter) {
        const char *err = dlerror();
        printf("FAIL: dlsym: %s\n", err ? err : "(no error)");
        return 1;
    }

    if (add(2, 3) != 5) {
        printf("FAIL: got_add(2,3)=%d (expected 5)\n", add(2, 3));
        return 1;
    }
    if (*counter != 100) {
        printf("FAIL: got_counter=%d (expected 100)\n", *counter);
        return 1;
    }
    if (hash("hello") != 105) {
        printf("FAIL: got_hash(\"hello\")=%d (expected 105)\n", hash("hello"));
        return 1;
    }

    /* 数据段写回：counter 写 555 后 libgot 内部 hash 读到同一存储 */
    *counter = 555;
    if (hash("hello") != 560) {
        printf("FAIL: got_hash after write=%d (expected 560)\n", hash("hello"));
        return 1;
    }

    void *bad = dlsym(h, "no_such_symbol");
    const char *bad_err = dlerror();
    if (bad != NULL || bad_err == NULL) {
        printf("FAIL: dlsym unknown symbol: sym=%p dlerror=%s\n",
               bad, bad_err ? bad_err : "(null)");
        return 1;
    }

    /* 引用计数：同库再 dlopen 得同句柄；两次 dlclose 后才卸载，首关后仍可调用 */
    void *h2 = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (h2 != h) {
        printf("FAIL: second dlopen returned different handle\n");
        return 1;
    }
    if (dlclose(h2) != 0) {
        printf("FAIL: first dlclose\n");
        return 1;
    }
    if (add(40, 2) != 42) {
        printf("FAIL: got_add after first dlclose=%d (expected 42)\n", add(40, 2));
        return 1;
    }
    if (dlclose(h) != 0) {
        printf("FAIL: second dlclose\n");
        return 1;
    }

    printf("dlopen ok: %s (add/hash/counter/dlclose/refcount)\n", path);
    return 0;
}
