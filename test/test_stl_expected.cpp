// STL <expected> 测试（C++23）：验证 std::expected 在 bpfvm 上正确工作。
//
// 机制（见 port_cplusplus.md）：
//   - <expected> 整体被 #if _LIBCPP_STD_VER >= 23 门控，用户代码必须 -std=c++23。
//   - libcxx.a 编译 expected.cpp，提供 bad_expected_access<void>
//     的 vtable/typeinfo/what()（-fno-exceptions 下 bad_expected_access 的抛出路径
//     走 _LIBCPP_VERBOSE_ABORT，故 what 符号仍需链接）。
//   - expected<T,E> 主体全是模板，在用户 TU 实例化，库只补运行时符号。
//
// 项目默认即 c++23（CXX_FLAGS / STL_CXX_FLAGS 均是），无需特殊规则。
//
// host 变体用 g++ -std=c++23 编宿主 glibc，作为对照基线。

#include <expected>
#include <string>
#include <cstdio>

int main() {
    int failures = 0;

    // (1) expected<T,E> 成功值
    {
        std::expected<int, std::string> e = 42;
        if (!e.has_value()) { printf("FAIL e has_value\n"); failures++; }
        if (e.value() != 42) { printf("FAIL e value\n"); failures++; }
        if (*e != 42) { printf("FAIL e deref\n"); failures++; }
        e = 100;
        if (*e != 100) { printf("FAIL e assign\n"); failures++; }
        if (failures == 0) printf("[OK] expected<T,E> success value\n");
    }

    // (2) unexpected
    {
        std::expected<int, std::string> e = std::unexpected(std::string("err"));
        if (e.has_value()) { printf("FAIL unexpected has_value\n"); failures++; }
        if (e.error() != "err") { printf("FAIL unexpected error\n"); failures++; }
        // value() 在 -fno-exceptions 下访问错误值会 abort，不测
        if (failures == 0) printf("[OK] unexpected\n");
    }

    // (3) and_then / or_else / transform 单子操作
    {
        std::expected<int, std::string> ok = 10;
        auto doubled = ok.and_then([](int x) {
            return std::expected<int, std::string>(x * 2);
        });
        if (doubled.value() != 20) { printf("FAIL and_then value=%d\n", doubled.value()); failures++; }

        std::expected<int, std::string> bad = std::unexpected(std::string("e"));
        auto recovered = bad.or_else([](const std::string &) {
            return std::expected<int, std::string>(999);
        });
        if (recovered.value() != 999) { printf("FAIL or_else value=%d\n", recovered.value()); failures++; }

        auto transformed = ok.transform([](int x) { return x + 5; });
        if (transformed.value() != 15) { printf("FAIL transform value=%d\n", transformed.value()); failures++; }

        if (failures == 0) printf("[OK] monadic ops\n");
    }

    // (4) expected<void,E>
    {
        std::expected<void, int> e{};
        if (!e.has_value()) { printf("FAIL void expected has_value\n"); failures++; }
        std::expected<void, int> err = std::unexpected(7);
        if (err.has_value()) { printf("FAIL void unexpected has_value\n"); failures++; }
        if (err.error() != 7) { printf("FAIL void error\n"); failures++; }
        if (failures == 0) printf("[OK] expected<void,E>\n");
    }

    // (5) error() 类型为 E，可携带复杂类型
    {
        std::expected<int, std::string> e = std::unexpected(std::string("complex"));
        if (e.error().size() != 7) { printf("FAIL error size=%zu\n", e.error().size()); failures++; }
        if (failures == 0) printf("[OK] error() with string\n");
    }

    if (failures == 0) {
        printf("ALL PASS\n");
        return 0;
    }
    printf("%d FAILURE(S)\n", failures);
    return 1;
}
