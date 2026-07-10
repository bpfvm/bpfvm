// STL 基础测试：验证常用 STL 容器/算法在 bpfvm 上正确工作。
//
// 机制（见 port_cplusplus.md）：
//   - libc++ 头 + BpfLibcallLower pass（memcpy intrinsic 改写）+ libcxx.a
//   - 覆盖 vector/string/map/algorithm/memory/functional/optional
//
// host 变体用 g++ 编宿主 glibc，作为对照基线。

#include <vector>
#include <string>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <set>
#include <algorithm>
#include <memory>
#include <functional>
#include <optional>
#include <variant>
#include <numeric>
#include <cstdio>

// 按值传容器：验证 BpfWideArgs lowerAggregateParams 路径 A（原 stripByval；BPF
// 后端原本拒绝 byval 参数，"pass by value not supported"）。noinline 防 -O1 内联
// 绕过 byval lowering；
// caller 原对象必须不被 callee 修改（真正按值语义）。
__attribute__((noinline)) size_t byval_str_size(std::string s) { return s.size(); }
__attribute__((noinline)) int byval_vec_sum(std::vector<int> v) {
    int sum = 0;
    for (int x : v) sum += x;
    return sum;
}

int main() {
    int failures = 0;

    // (1) vector + algorithm::sort
    std::vector<int> v = {5, 3, 8, 1, 9, 2, 7, 4, 6};
    std::sort(v.begin(), v.end());
    bool sorted_ok = true;
    for (size_t i = 1; i < v.size(); i++)
        if (v[i - 1] > v[i]) { sorted_ok = false; break; }
    int vsum = std::accumulate(v.begin(), v.end(), 0);  // 1+..+9 = 45
    if (!sorted_ok || vsum != 45) {
        printf("FAIL vector/sort: sorted=%d sum=%d\n", (int)sorted_ok, vsum);
        ++failures;
    }

    // (2) string 拼接 + 比较
    std::string s = "hello";
    s += " ";
    s += "world";
    if (s != "hello world" || s.size() != 11) {
        printf("FAIL string: '%s' size=%zu\n", s.c_str(), s.size());
        ++failures;
    }

    // (3) map 插入 + 遍历（有序）
    std::map<std::string, int> m;
    m["one"] = 1;
    m["three"] = 3;
    m["two"] = 2;
    int msum = 0, mcnt = 0;
    for (auto &kv : m) { msum += kv.second; ++mcnt; }
    std::string first_key = m.begin()->first;
    if (mcnt != 3 || msum != 6 || first_key != "one") {
        printf("FAIL map: cnt=%d sum=%d first='%s'\n", mcnt, msum, first_key.c_str());
        ++failures;
    }

    // (4) unordered_map（验证 hash 容器 + ceilf 软化）
    std::unordered_map<int, int> um;
    for (int i = 0; i < 20; i++) um[i] = i * 2;
    if (um.size() != 20 || um[5] != 10) {
        printf("FAIL unordered_map: size=%zu um[5]=%d\n", um.size(), um[5]);
        ++failures;
    }

    // (5) unordered_set
    std::unordered_set<int> us = {10, 20, 30, 40};
    if (us.size() != 4 || !us.count(20)) {
        printf("FAIL unordered_set: size=%zu\n", us.size());
        ++failures;
    }

    // (6) deque（双向 push）
    std::deque<int> dq;
    for (int i = 1; i <= 5; i++) { dq.push_back(i); dq.push_front(-i); }
    if (dq.size() != 10 || dq.front() != -5 || dq.back() != 5) {
        printf("FAIL deque: size=%zu front=%d back=%d\n", dq.size(), dq.front(), dq.back());
        ++failures;
    }

    // (7) set（有序）
    std::set<int> st = {5, 3, 8, 1, 9};
    if (st.size() != 5 || *st.begin() != 1 || *st.rbegin() != 9) {
        printf("FAIL set: size=%zu\n", st.size());
        ++failures;
    }

    // (8) unique_ptr + make_unique
    auto p = std::make_unique<int>(42);
    if (!p || *p != 42) {
        printf("FAIL unique_ptr\n");
        ++failures;
    }

    // (9) optional
    std::optional<int> opt = 100;
    if (!opt || *opt != 100) {
        printf("FAIL optional\n");
        ++failures;
    }

    // (10) variant
    std::variant<int, double> var = 42;
    if (std::get<int>(var) != 42 || var.index() != 0) {
        printf("FAIL variant\n");
        ++failures;
    }

    // (11) function + lambda
    std::function<int(int)> sq = [](int x) { return x * x; };
    if (sq(7) != 49) {
        printf("FAIL function\n");
        ++failures;
    }

    // (12) 按值传容器（BpfWideArgs lowerAggregateParams 路径 A）
    std::string bvs = "hello world";
    std::vector<int> bvv = {1, 2, 3, 4, 5};
    size_t bvsz = byval_str_size(bvs);    // 11
    int bvsum = byval_vec_sum(bvv);       // 15
    if (bvsz != 11 || bvsum != 15 || bvs[0] != 'h' || bvv[0] != 1) {
        printf("FAIL byval: str=%zu vec=%d s0=%c\n", bvsz, bvsum, bvs[0]);
        ++failures;
    }

    printf("stl_basic: vec=%d str='%s' map=%d umap=%zu dq=%zu set=%zu fn=%d byval=%zu/%d\n",
           vsum, s.c_str(), msum, um.size(), dq.size(), st.size(), sq(7), bvsz, bvsum);
    return failures == 0 ? 0 : 1;
}

