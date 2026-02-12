#include <stdio.h>
#include <stdint.h>

int main(void) {
    int ok = 1;

    /* 64-bit atomic add */
    {
        long val = 10;
        __sync_fetch_and_add(&val, 5);
        printf("atomic_add64: %ld\n", val);
        ok &= (val == 15);
    }

    /* 64-bit atomic or */
    {
        long val = 0x0F;
        __sync_fetch_and_or(&val, 0xF0);
        printf("atomic_or64: 0x%lx\n", val);
        ok &= (val == 0xFF);
    }

    /* 64-bit atomic and */
    {
        long val = 0xFF;
        __sync_fetch_and_and(&val, 0x0F);
        printf("atomic_and64: 0x%lx\n", val);
        ok &= (val == 0x0F);
    }

    /* 64-bit atomic xor */
    {
        long val = 0xAA;
        __sync_fetch_and_xor(&val, 0xFF);
        printf("atomic_xor64: 0x%lx\n", val);
        ok &= (val == 0x55);
    }

    /* 64-bit fetch_and_add (return old value) */
    {
        long val = 100;
        long old = __sync_fetch_and_add(&val, 20);
        printf("fetch_add64: old=%ld new=%ld\n", old, val);
        ok &= (old == 100 && val == 120);
    }

    /* 64-bit compare_and_swap */
    {
        long val = 42;
        long old = __sync_val_compare_and_swap(&val, 42, 99);
        printf("cas64 hit: old=%ld new=%ld\n", old, val);
        ok &= (old == 42 && val == 99);

        /* cas miss */
        old = __sync_val_compare_and_swap(&val, 42, 0);
        printf("cas64 miss: old=%ld val=%ld\n", old, val);
        ok &= (old == 99 && val == 99);
    }

    /* 32-bit atomic add */
    {
        int val = 10;
        __sync_fetch_and_add(&val, 5);
        printf("atomic_add32: %d\n", val);
        ok &= (val == 15);
    }

    /* 32-bit compare_and_swap */
    {
        int val = 42;
        int old = __sync_val_compare_and_swap(&val, 42, 99);
        printf("cas32 hit: old=%d new=%d\n", old, val);
        ok &= (old == 42 && val == 99);
    }

    printf("atomic: %s\n", ok ? "ok" : "failed");
    return ok ? 0 : 1;
}
