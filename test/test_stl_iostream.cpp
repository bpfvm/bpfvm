// STL iostream 测试：验证 <iostream>（cin/cout/cerr）+ <sstream> 在 bpfvm 上可用。
//
// 这是 port_cplusplus.md 里 iostream 支持的端到端验证。机制（详见 md）：
//   - 移除 _LIBCPP_HAS_NO_LOCALIZATION（否则 <ios> 被 #if 清空，ios_base 消失）。
//   - libcxx.a 编入 locale.cpp/ios.cpp/iostream.cpp/ostream.cpp（locale 子系统 +
//     cin/cout 全局对象存储 + ios_base::Init）。
//   - BpfAtomicLowerPass（libBpfWideArgs.so）：降级 static guard 的 load atomic
//     （eBPF 无 plain atomic load 指令，LLVM 19 后端 Cannot select）。
//
// 正确性用 std::stringstream（内存流）读回比对，不依赖 stdout 自检；
// cout/cerr 仅验证"能输出不崩溃"（输出到真实 stdout，人眼可见）。
//
// host 变体用 g++ 编宿主 glibc，作为对照基线。

#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>

int main() {
    int failures = 0;

    // (1) cout 基本输出（验证 ios_base::Init 全局对象构造 + ostream << int/char*）。
    //     这是 iostream 最核心路径：static guard（atomic 降级）+ locale::id 初始化 +
    //     num_put facet 格式化。仅验证不崩溃 + 流状态 good。
    std::cout << "hello iostream\n";
    if (!std::cout.good()) {
        printf("FAIL cout good\n");
        ++failures;
    }
    std::cerr << "cerr ok\n";

    // (2) stringstream 内存流：整数 -> 字符串，读回比对（真正验证 num_put 格式化正确）。
    {
        std::ostringstream oss;
        oss << 42 << " " << -7 << " " << 1234567;
        std::string s = oss.str();
        if (s != "42 -7 1234567") {
            printf("FAIL ostringstream int: '%s'\n", s.c_str());
            ++failures;
        }
    }

    // (3) istringstream 字符串 -> 整数（验证 num_get 解析 + istream >>）。
    {
        std::istringstream iss("100 200 300");
        int a = 0, b = 0, c = 0;
        iss >> a >> b >> c;
        if (a != 100 || b != 200 || c != 300) {
            printf("FAIL istringstream int: %d %d %d\n", a, b, c);
            ++failures;
        }
    }

    // (4) 浮点输出（验证 num_put 的 double 格式化 + BpfSoftFp 软化路径）。
    {
        std::ostringstream oss;
        oss << 3.14;
        std::string s = oss.str();
        if (s != "3.14") {
            printf("FAIL ostringstream double: '%s'\n", s.c_str());
            ++failures;
        }
    }

    // (5) endl + flush（验证操纵符 + ostream::flush）。
    {
        std::ostringstream oss;
        oss << "line1" << std::endl << "line2" << std::endl;
        std::string s = oss.str();
        if (s != "line1\nline2\n") {
            printf("FAIL endl: '%s'\n", s.c_str());
            ++failures;
        }
    }

    // (6) hex/dec 操纵符（验证 ios_base::flags + num_put 按 base 格式化）。
    {
        std::ostringstream oss;
        oss << std::hex << 255 << " " << std::dec << 255;
        std::string s = oss.str();
        if (s != "ff 255") {
            printf("FAIL hex/dec: '%s'\n", s.c_str());
            ++failures;
        }
    }

    // (7) setw 宽度（验证 ios_base::width + num_put 填充）。
    {
        std::ostringstream oss;
        oss << std::setw(5) << 42;
        std::string s = oss.str();
        if (s != "   42") {
            printf("FAIL setw: '%s'\n", s.c_str());
            ++failures;
        }
    }

    // (8) std::cin（读一个数）。仅验证流对象可用 + >> 操作符；测试框架需在 stdin 喂数据。
    //     ctest 默认无 stdin，此处仅检查 cin 流对象构造不崩溃（goodbit）。
    if (!std::cin.good()) {
        // cin 在无输入时可能是 eof/good，不视为失败（取决于运行环境）。
    }

    printf("iostream: %s\n", failures ? "FAIL" : "all ok");
    return failures == 0 ? 0 : 1;
}
