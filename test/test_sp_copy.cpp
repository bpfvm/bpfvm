// shared_ptr 按值 copy 传参的引用计数回归测试。
//
// 守护 lowerAggregateParams 路径 B 对非平凡拷贝构造聚合（shared_ptr 16B =
// {ptr,ptr}）的 invisible-reference 改写（见 README.md 函数调用约定突破一节）。改写前的缺陷：
// clang 对 by-value 非平凡聚合生成 [2 x i64] 值参数，pass 在 caller 侧只做按位
// store 到临时 alloca、callee 侧 load 出值——move 构造作用于 load 副本，无法
// 置空 caller 的源临时，caller 析构源时多减一次引用计数 → 计数比实际少 1 →
// caller 持有的 shared_ptr 在 callee 析构副本后变悬空 → 解引用 UAF。
//
// 触发路径（与 bpfvm 自身 PosixSyscall::do_clone 的 make_shared<PosixSyscall>
// 完全同构）：make_shared<Holder>(sp) 内部 placement-new 构造 Holder，构造函数
// Holder(shared_ptr p_) 按值收 p_，体内 move 进成员 p。正确实现下 sp 与 h->p
// 共享同一 control block，引用计数应为 2。
//
// 检测：make_shared<Holder>(sp) 后断言 sp.use_count()==2、对象内容未变；h.reset()
// 后断言 use_count()==1、对象仍存活（UAF 下读到错误值或崩溃）。
#include <memory>
extern "C" int printf(const char *, ...);

struct X {
    int val;
    X(int v) : val(v) {}
};

struct Holder {
    std::shared_ptr<X> p;
    Holder(std::shared_ptr<X> p_) : p(std::move(p_)) {}
};

int main() {
    auto sp = std::make_shared<X>(42);

    // make_shared<Holder>(sp) —— 与 do_clone 的 make_shared<PosixSyscall>(pgrp, ...)
    // 同构：sp 以 lvalue 传入，强制 copy（+1）。
    auto h = std::make_shared<Holder>(sp);

    // 直接在 printf 实参里调 use_count()：避免优化器把 use_count 的 relaxed load
    // CSE 到 make_shared 之前（atomic relaxed load 跨 monotonic atomicrmw 的 CSE
    // 会读到旧值，使检测失效——shared_ptr 行为本身正确，只是检测手段需防 CSE）。
    int val_via_h = h->p->val;
    int val_via_sp = sp->val;
    printf("uc_after=%ld val_h=%d val_sp=%d (expect 2/42/42)\n",
           sp.use_count(), val_via_h, val_via_sp);

    // uc_after==2 验证 copy 构造确实增了计数；val 验证两路径读到同一存活对象。
    if (sp.use_count() != 2) return 2;       // copy 构造漏了 +1（核心 bug）
    if (val_via_h != 42) return 3;           // UAF：h->p 读到错误值
    if (val_via_sp != 42) return 4;          // UAF：sp 已悬空

    // h 离开作用域析构后，引用计数应恢复 1，对象仍存活。
    h.reset();
    int val_final = sp->val;
    printf("uc_final=%ld val_final=%d (expect 1/42)\n", sp.use_count(), val_final);
    if (sp.use_count() != 1) return 5;       // 析构多减了计数
    if (val_final != 42) return 6;           // 对象被提前 free（UAF）

    printf("ok\n");
    return 0;
}
