// test_atomic_bool.c — 验证窄原子（i8/i16）在 BPF 下的正确性。
//
// BpfAtomicLowerPass 把 i8/i16 的 cmpxchg/rmw 展开成对包含它的对齐 i32 槽的子字节
// CAS 循环。最容易出错的两点：
//   1) 相邻字节被破坏（越界写）——验证原子字段前后的普通字段值不变。
//   2) CAS 语义正确——compare_exchange 的成功/失败、旧值返回正确。
//
// 用 __atomic_* 内建（与 std::atomic 生成相同 IR：i8 cmpxchg/rmw）。
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

// 布局：前哨兵 + 原子字节 + 后哨兵，验证子字节 CAS 不越界写。
// val 不加 _Atomic 限定——原子性由 __atomic_* 内建保证（BPF 后端对 _Atomic T* 有约束）。
struct Padded {
    uint8_t before;          // 哨兵（CAS 不该碰）
    uint8_t val;             // 目标（窄原子操作的对象）
    uint8_t after;           // 哨兵（CAS 不该碰）
};

int main(void) {
    int ok = 1;

    // —— 1. compare_exchange 成功路径（_Bool，即 i8）——
    {
        _Bool b = 0;
        _Bool expected = 0;
        _Bool success = __atomic_compare_exchange_n(&b, &expected, 1, false,
                                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
        printf("cas_bool_success: ok=%d val=%d exp=%d\n", success, (int)b, (int)expected);
        ok &= success && b == 1 && expected == 0;
    }

    // —— 2. compare_exchange 失败路径（期望值不匹配）——
    {
        _Bool b = 1;
        _Bool expected = 0;
        _Bool success = __atomic_compare_exchange_n(&b, &expected, 1, false,
                                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
        printf("cas_bool_fail: ok=%d val=%d exp=%d\n", success, (int)b, (int)expected);
        // 失败：success=0，b 不变=1，expected 被更新为当前值 1。
        ok &= !success && b == 1 && expected == 1;
    }

    // —— 3. fetch_add（atomic_char，i8）——
    {
        uint8_t c = 100;
        uint8_t old = __atomic_fetch_add(&c, 5, __ATOMIC_SEQ_CST);
        printf("fetch_add_char: old=%d new=%d\n", (int)old, (int)c);
        ok &= old == 100 && c == 105;
    }

    // —— 4. 相邻字节完整性（子字节 CAS 越界检测）——
    // 关键测试：原子字段只有 1 字节，展开成 i32 CAS 会读写包含它的 4 字节槽。
    // 如果 mask/shift 算错，会写脏 before/after。
    {
        struct Padded p = {0xAB, 0x00, 0xCD};
        uint8_t expected = 0x00;
        _Bool success = __atomic_compare_exchange_n(&p.val, &expected, 0x42, false,
                                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
        printf("padded_cas: ok=%d before=0x%02x val=0x%02x after=0x%02x\n",
               success, p.before, (unsigned)p.val, p.after);
        ok &= success && p.before == 0xAB && p.val == 0x42 && p.after == 0xCD;

        // 失败路径：val 已是 0x42，期望 0x00 应失败，且 before/after 不变。
        expected = 0x00;
        success = __atomic_compare_exchange_n(&p.val, &expected, 0x99, false,
                                              __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
        printf("padded_cas_fail: ok=%d before=0x%02x val=0x%02x after=0x%02x\n",
               success, p.before, (unsigned)p.val, p.after);
        ok &= !success && p.before == 0xAB && p.val == 0x42 && p.after == 0xCD;
    }

    // —— 5. fetch_or on char（位运算 widen 分支）——
    {
        uint8_t c = 0x0F;
        uint8_t old = __atomic_fetch_or(&c, 0x30, __ATOMIC_SEQ_CST);
        printf("fetch_or_char: old=0x%02x new=0x%02x\n", (int)old, (int)c);
        ok &= old == 0x0F && c == 0x3F;
    }

    // —— 6. short (i16) fetch_add ——
    {
        uint16_t s = 1000;
        uint16_t old = __atomic_fetch_add(&s, 23, __ATOMIC_SEQ_CST);
        printf("fetch_add_short: old=%d new=%d\n", (int)old, (int)s);
        ok &= old == 1000 && s == 1023;
    }

    printf(ok ? "ALL OK\n" : "FAILED\n");
    return ok ? 0 : 1;
}
