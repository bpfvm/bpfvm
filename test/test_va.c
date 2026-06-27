#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int check_format(const char *fmt, const char *expect, va_list ap) {
    va_list ap_copy;
    char buf[128];

    va_copy(ap_copy, ap);
    vsnprintf(buf, sizeof(buf), fmt, ap_copy);
    va_end(ap_copy);

    printf("fmt: \"%s\"\n", fmt);
    printf("out: \"%s\"\n", buf);
    return strcmp(buf, expect) == 0;
}

static int check_sum(int expect, va_list ap) {
    va_list ap_copy;
    long sum = 0;

    va_copy(ap_copy, ap);
    while (1) {
        int v = va_arg(ap_copy, int);
        if (v == 0) {
            break;
        }
        sum += v;
    }
    va_end(ap_copy);

    printf("sum: %ld\n", sum);
    return sum == expect;
}

static int check_copy_after_advance(int expect, va_list ap) {
    va_list ap_copy;
    long sum = 0;

    (void)va_arg(ap, int);
    va_copy(ap_copy, ap);
    while (1) {
        int v = va_arg(ap_copy, int);
        if (v == 0) {
            break;
        }
        sum += v;
    }
    va_end(ap_copy);

    printf("sum_after_advance: %ld\n", sum);
    return sum == expect;
}

static int check_copy_after_original(int expect, va_list ap) {
    va_list ap_copy;
    long sum = 0;

    va_copy(ap_copy, ap);
    while (1) {
        int v = va_arg(ap, int);
        if (v == 0) {
            break;
        }
    }
    while (1) {
        int v = va_arg(ap_copy, int);
        if (v == 0) {
            break;
        }
        sum += v;
    }
    va_end(ap_copy);

    printf("sum_after_original: %ld\n", sum);
    return sum == expect;
}

/* 变参包装：用标准的 va_start 构造 va_list，转交给上面的 helper。
 * （BpfWideArgs pass 自动把变参函数改写成定参 + lower va intrinsic） */
static int fmt_check(const char *fmt, const char *expect, ...) {
    va_list ap;
    va_start(ap, expect);
    int r = check_format(fmt, expect, ap);
    va_end(ap);
    return r;
}

static int sum_check(int expect, ...) {
    va_list ap;
    va_start(ap, expect);
    int r = check_sum(expect, ap);
    va_end(ap);
    return r;
}

static int copy_after_advance_check(int expect, ...) {
    va_list ap;
    va_start(ap, expect);
    int r = check_copy_after_advance(expect, ap);
    va_end(ap);
    return r;
}

static int copy_after_original_check(int expect, ...) {
    va_list ap;
    va_start(ap, expect);
    int r = check_copy_after_original(expect, ap);
    va_end(ap);
    return r;
}

int main(void) {
    int ok = 1;

    ok &= fmt_check("hello %s %d", "hello world 42", "world", 42);
    ok &= fmt_check("[%s] %d %s", "[va_copy] 7 ok", "va_copy", 7, "ok");

    ok &= sum_check(15, 1, 2, 3, 4, 5, 0);
    ok &= copy_after_advance_check(90, 10, 20, 30, 40, 0);
    ok &= copy_after_original_check(30, 3, 6, 9, 12, 0);

    printf("va_copy: %s\n", ok ? "ok" : "failed");
    return ok ? 0 : 1;
}
