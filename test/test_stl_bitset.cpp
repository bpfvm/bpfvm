// STL <bitset> 测试：验证 bitset 在 bpfvm 上正确工作。
//
// 解锁背景：<bitset> 的 count/find_first 等内部调 std::__count 的 __bit_iterator
// 特化版，其参数是 [2 x i64] 聚合（__bit_iterator = {ptr, unsigned}）。两个 bit_
// iterator + value + proj = 6 个 BPF 寄存器 > 上限 5 → "too many arguments"。
// BpfWideArgs 的 lowerAggregateParams 把小聚合成值参数直接归一成裸 ptr（恒占 1
// 寄存器），解锁 bitset 全部操作。
//
// host 变体用 g++ 编宿主 glibc 作对照基线。

#include <bitset>
#include <string>
#include <cstdio>

int main() {
    int failures = 0;

    // (1) 构造 + count：8 位 bitset，3 个置位。
    {
        std::bitset<8> b(0b00010101);  // 3 bits set
        if (b.count() != 3) {
            printf("FAIL count: %zu (expect 3)\n", b.count());
            ++failures;
        }
    }

    // (2) set/reset/test/flip。
    {
        std::bitset<8> b;
        b.set(1);
        b.set(3);
        b.flip(1);  // 清掉 1
        if (!b.test(3) || b.test(1)) {
            printf("FAIL set/test/flip: b=%zu\n", b.to_ulong());
            ++failures;
        }
        b.reset(3);
        if (b.any()) {
            printf("FAIL reset/any: b=%zu\n", b.to_ulong());
            ++failures;
        }
    }

    // (3) 运算符 & | ^ ~。
    {
        std::bitset<8> a(0b11001010), b(0b10110110);
        auto and_ = (a & b).to_ulong();
        auto or_  = (a | b).to_ulong();
        auto xor_ = (a ^ b).to_ulong();
        if (and_ != 0b10000010 || or_ != 0b11111110 || xor_ != 0b01111100) {
            printf("FAIL ops: &=%zu |=%zu ^=%zu\n", and_, or_, xor_);
            ++failures;
        }
    }

    // (4) 移位 << >>。
    {
        std::bitset<8> b(0b00000011);
        b <<= 4;
        if (b.to_ulong() != 0b00110000) {
            printf("FAIL shl: %zu\n", b.to_ulong());
            ++failures;
        }
        b >>= 2;
        if (b.to_ulong() != 0b00001100) {
            printf("FAIL shr: %zu\n", b.to_ulong());
            ++failures;
        }
    }

    // (5) 字符串转换 to_string / 构造自字符串。
    {
        std::bitset<8> b(std::string("10101010"));
        if (b.to_string() != "10101010" || b.count() != 4) {
            printf("FAIL str: %s count=%zu\n", b.to_string().c_str(), b.count());
            ++failures;
        }
    }

    // (6) 大 bitset（跨多个 word）：64 位，count（走 __bit_iterator 的 __count
    //     特化路径——本测试 lowerAggregateParams 验证的核心点）。
    {
        std::bitset<64> b;
        b.set(0);
        b.set(33);
        b.set(63);
        if (b.count() != 3) {
            printf("FAIL big count: %zu\n", b.count());
            ++failures;
        }
        if (!b.test(33) || b.test(34)) {
            printf("FAIL big test: 33=%d 34=%d\n", (int)b.test(33), (int)b.test(34));
            ++failures;
        }
    }

    // (7) all/any/none（全 1 时 all）。
    {
        std::bitset<4> b(0b1111);
        std::bitset<4> e;
        if (!b.all() || !b.any() || b.none()) {
            printf("FAIL all/any: b\n");
            ++failures;
        }
        if (e.all() || e.any() || !e.none()) {
            printf("FAIL none: e\n");
            ++failures;
        }
    }

    printf("stl_bitset: ok=%d failures=%d\n", (failures == 0), failures);
    return failures == 0 ? 0 : 1;
}
