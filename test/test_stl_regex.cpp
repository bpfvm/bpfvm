// STL regex 测试：验证 <regex>（std::regex / std::wregex）在 bpfvm 上可用。
//
// 这是 port_cplusplus.md 里 regex 支持的端到端验证。机制（详见 md）：
//   - lowerAggregateParams 路径 A（BpfWideArgs，原 stripByval）解锁按值传 std::string/
//     sub_match 等结构体参数（regex 引擎内部大量 __add_range(basic_string, ...) 调用），
//     前端编译通过。
//   - libcxx.a 编入 regex.cpp + locale 子系统（locale.cpp/ios.cpp/ostream.cpp/
//     ios.instantiations.cpp 随 <iostream> 一起进库）—— regex_traits 走 ctype
//     facet 做字符分类，不可避免依赖 locale。这补齐了此前缺失的 regex 引擎符号
//     （__match_any_but_newline::__exec 等）。
//   - BpfAtomicLowerPass 降级 static guard 的 load atomic（locale 子系统需要）。
//
// 覆盖：regex_match/regex_search/regex_replace、捕获组、迭代器（regex_iterator /
// regex_token_iterator）、量词/锚点/字符类/反向引用/交替、icase 标志、wregex 宽字符版。
// 全部用断言自检（不依赖 stdout 内容），host 变体用 g++ 编宿主 glibc 作对照基线。

#include <regex>
#include <string>
#include <cstdio>

static int failures = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("FAIL: %s\n", msg);                                         \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

int main() {
    // (1) regex_match：基本完全匹配。
    {
        std::string s = "abc123";
        std::regex re("[a-z]+[0-9]+");
        CHECK(std::regex_match(s, re), "match [a-z]+[0-9]+");
        CHECK(!std::regex_match(std::string("abcXYZ"), re), "match should fail on bad input");
    }

    // (2) 捕获组：smatch[i] 取分组。
    {
        std::string s = "2026-07-07";
        std::regex re("(\\d+)-(\\d+)-(\\d+)");
        std::smatch m;
        CHECK(std::regex_match(s, m, re), "date match");
        CHECK(std::string(m[1]) == "2026", "group1 year");
        CHECK(std::string(m[2]) == "07", "group2 month");
        CHECK(std::string(m[3]) == "07", "group3 day");
        CHECK(m.size() == 4, "match size (full + 3 groups)");
    }

    // (3) regex_search：在串中查找第一个匹配。
    {
        std::string s = "hello 42 world 99 end";
        std::regex re("\\d+");
        std::smatch m;
        CHECK(std::regex_search(s, m, re), "search digits");
        CHECK(std::string(m[0]) == "42", "search first match is 42");
        CHECK(m.position(0) == 6, "search position");
        CHECK(m.length(0) == 2, "search length");
    }

    // (4) sregex_iterator：遍历所有匹配。
    {
        std::string s = "foo1 bar2 baz3";
        std::regex re("[a-z]+(\\d)");
        std::sregex_iterator it(s.begin(), s.end(), re);
        std::sregex_iterator end;
        int count = 0;
        std::string nums;
        for (; it != end; ++it) {
            ++count;
            nums += std::string((*it)[1]);
        }
        CHECK(count == 3, "iterator count=3");
        CHECK(nums == "123", "iterator captured digits");
    }

    // (5) regex_replace：替换。
    {
        std::string s = "hello world";
        std::regex re("world");
        std::string r = std::regex_replace(s, re, std::string("bpfvm"));
        CHECK(r == "hello bpfvm", "replace world->bpfvm");

        // 全局替换所有数字。
        std::string s2 = "a1b2c3";
        std::regex re2("\\d");
        std::string r2 = std::regex_replace(s2, re2, std::string("X"));
        CHECK(r2 == "aXbXcX", "replace all digits");
    }

    // (6) sregex_token_iterator：按分隔符切分（-1 取未匹配部分）。
    {
        std::string s = "a,b,,c";
        std::regex re(",");
        std::sregex_token_iterator it(s.begin(), s.end(), re, -1);
        std::sregex_token_iterator end;
        std::string joined;
        int count = 0;
        std::string last;
        for (; it != end; ++it) {
            joined += std::string(*it) + "|";
            last = std::string(*it);
            ++count;
        }
        // splits: "a","b","","c" -> 4 tokens
        CHECK(count == 4, "token count=4");
        CHECK(last == "c", "token last=c");
        CHECK(joined == "a|b||c|", "token joined");
    }

    // (7) icase 标志（大小写无关）。
    {
        std::string s = "Hello";
        std::regex re("hello", std::regex_constants::icase);
        CHECK(std::regex_match(s, re), "icase match");
        std::regex re2("HELLO", std::regex_constants::icase);
        CHECK(std::regex_match(s, re2), "icase match uppercase pattern");
    }

    // (8) 字符类 \w \s \d 与量词组合。
    {
        std::string s = "Hello, World! 42";
        std::regex re("\\w+");
        std::sregex_iterator it(s.begin(), s.end(), re), end;
        int count = 0;
        for (; it != end; ++it) ++count;
        CHECK(count == 3, "\\w+ count=3 (Hello, World, 42)");
    }

    // (9) 锚点 ^ 和 $。
    {
        std::string s = "foobar";
        CHECK(std::regex_search(s, std::regex("^foo")), "^foo at start");
        CHECK(std::regex_search(s, std::regex("bar$")), "bar$ at end");
        CHECK(!std::regex_search(s, std::regex("^bar")), "^bar not at start");
        CHECK(!std::regex_search(s, std::regex("foo$")), "foo$ not at end");
    }

    // (10) 量词 + * ? {n,m}。
    {
        CHECK(std::regex_match(std::string("aaa"), std::regex("a{2,3}")), "a{2,3}");
        CHECK(std::regex_match(std::string("ac"), std::regex("ab*c")), "ab*c (zero b)");
        CHECK(std::regex_match(std::string("abbbbc"), std::regex("ab*c")), "ab*c (many b)");
        CHECK(std::regex_match(std::string("color"), std::regex("colou?r")), "colou?r");
        CHECK(std::regex_match(std::string("colour"), std::regex("colou?r")), "colou?r with u");
    }

    // (11) 交替 (|)。
    {
        std::regex re("cat|dog|bird");
        CHECK(std::regex_match(std::string("cat"), re), "alternation cat");
        CHECK(std::regex_match(std::string("dog"), re), "alternation dog");
        CHECK(std::regex_match(std::string("bird"), re), "alternation bird");
        CHECK(!std::regex_match(std::string("fish"), re), "alternation no fish");
    }

    // (12) 字符范围 [a-z] [0-9] 与取反 [^]。
    {
        CHECK(std::regex_match(std::string("5"), std::regex("[0-9]")), "[0-9]");
        CHECK(std::regex_match(std::string("m"), std::regex("[a-z]")), "[a-z]");
        CHECK(!std::regex_match(std::string("5"), std::regex("[^0-9]")), "[^0-9] rejects digit");
        CHECK(std::regex_match(std::string("a"), std::regex("[^0-9]")), "[^0-9] accepts letter");
    }

    // (13) 反向引用 (\1)。
    {
        std::regex re("(ab)\\1");
        CHECK(std::regex_match(std::string("abab"), re), "backref (ab)\\1");
        CHECK(!std::regex_match(std::string("abcd"), re), "backref rejects non-repeat");
    }

    // (14) C 字符串重载（const char* 直接匹配）。
    {
        CHECK(std::regex_match("test", std::regex("test")), "cstr match");
        std::cmatch cm;
        CHECK(std::regex_match("abc123", cm, std::regex("([a-z]+)([0-9]+)")), "cstr match with groups");
        CHECK(std::string(cm[1]) == "abc", "cstr group1");
        CHECK(std::string(cm[2]) == "123", "cstr group2");
    }

    // (15) wregex 宽字符版（wchar_t 实例化路径）。
    {
        std::wstring s = L"hello 42 world";
        std::wregex re(L"(\\d+)");
        std::wsmatch m;
        CHECK(std::regex_search(s, m, re), "wregex search");
        CHECK(m[0] == L"42", "wregex matched 42");
        CHECK(std::regex_match(std::wstring(L"abc"), std::wregex(L"[a-z]+")), "wregex match class");
    }

    // (16) empty match / zero-width（regex 引擎边界情况）。
    {
        std::string s = "abc";
        std::regex re("a*");
        std::smatch m;
        // a* 在 "abc" 起始匹配 "a"（贪婪，但非空也算成功）。
        CHECK(std::regex_search(s, m, re), "a* search");
    }

    // (17) regex_error 异常构造（-fno-exceptions 下用 nothrow 路径）。
    //      构造非法正则时，libc++ 在 EH 关闭下不抛异常，而是走 abort/mark 路径。
    //      这里只构造一个合法正则并查询 mark_count / flags，验证 basic_regex 元数据。
    {
        std::regex re("(a)(b)(c)");
        CHECK(re.mark_count() == 3, "mark_count=3");
        std::regex re2("hello");
        CHECK(re2.mark_count() == 0, "mark_count=0 no groups");
    }

    printf("regex: %s\n", failures ? "FAIL" : "all ok");
    return failures == 0 ? 0 : 1;
}
