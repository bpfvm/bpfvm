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

int main(void) {
    int ok = 1;

    {
        PDCLIB_MAKE_VA_LIST(_ap, "world", 42);
        va_list ap = _ap;
        ok &= check_format("hello %s %d", "hello world 42", ap);
    }

    {
        PDCLIB_MAKE_VA_LIST(_ap, "va_copy", 7, "ok");
        va_list ap = _ap;
        ok &= check_format("[%s] %d %s", "[va_copy] 7 ok", ap);
    }

    {
        PDCLIB_MAKE_VA_LIST(_ap, 1, 2, 3, 4, 5, 0);
        va_list ap = _ap;
        ok &= check_sum(15, ap);
    }

    {
        PDCLIB_MAKE_VA_LIST(_ap, 10, 20, 30, 40, 0);
        va_list ap = _ap;
        ok &= check_copy_after_advance(90, ap);
    }

    {
        PDCLIB_MAKE_VA_LIST(_ap, 3, 6, 9, 12, 0);
        va_list ap = _ap;
        ok &= check_copy_after_original(30, ap);
    }

    printf("va_copy: %s\n", ok ? "ok" : "failed");
    return ok ? 0 : 1;
}
