#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

int main(void) {
    int ok = 1;

    /* htons / ntohs */
    volatile uint16_t h16 = 0x0102;
    uint16_t n16 = htons(h16);
    printf("htons(0x%04x) = 0x%04x\n", (unsigned)h16, (unsigned)n16);
    ok &= (n16 == 0x0201);
    ok &= (ntohs(n16) == h16);

    /* htonl / ntohl */
    volatile uint32_t h32 = 0x01020304;
    uint32_t n32 = htonl(h32);
    printf("htonl(0x%08x) = 0x%08x\n", h32, n32);
    ok &= (n32 == 0x04030201);
    ok &= (ntohl(n32) == h32);

    /* 64-bit bswap (no htonll in POSIX, use builtin directly) */
    volatile uint64_t v64 = 0x0102030405060708ULL;
    uint64_t s64 = __builtin_bswap64(v64);
    printf("bswap64(0x%016llx) = 0x%016llx\n",
           (unsigned long long)v64, (unsigned long long)s64);
    ok &= (s64 == 0x0807060504030201ULL);
    ok &= (__builtin_bswap64(s64) == v64);

    /* edge: symmetric values */
    volatile uint16_t z16 = 0;
    volatile uint32_t z32 = 0;
    ok &= (htons(z16) == 0);
    ok &= (htonl(z32) == 0);

    volatile uint16_t f16 = 0xFFFF;
    volatile uint32_t f32 = 0xFFFFFFFF;
    ok &= (htons(f16) == 0xFFFF);
    ok &= (htonl(f32) == 0xFFFFFFFF);

    printf("endian: %s\n", ok ? "ok" : "failed");
    return ok ? 0 : 1;
}
