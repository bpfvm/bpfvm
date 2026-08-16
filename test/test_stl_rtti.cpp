// STL <typeinfo> + dynamic_cast 测试：验证 C++ RTTI 在 bpfvm 上正确工作。
//
// 解锁背景（详见 port_cplusplus.md「RTTI 支持」决策记录）：
//   (1)链接器修 SHT_REL embedded addend bug——typeinfo 第一槽是「vtable+16 指针」，
//     引用 UND 符号 _ZTVN10__cxxabiv1*（定义在 libc++abi），embedded addend=+16 必须
//     读出，否则 typeinfo vtable 指针少 16 -> dynamic_cast/typeid 崩。
//   (2)libcxx.a 编入 libc++abi 的 6 个 typeinfo 源文件（private_typeinfo 等），
//     提供 __cxxabiv1 全部 typeinfo vtable + 76 个基本 typeinfo 对象 + __dynamic_cast
//     全实现 + __cxa_bad_typeid。
// 异常仍禁用（-fno-exceptions），故不测 throw/catch；typeid 与 dynamic_cast 的指针
// 语义不依赖异常（reference dynamic_cast 失败抛 bad_cast 的路径才需要异常，这里不测）。
//
// host 变体用 g++ 编宿主 glibc 作对照基线（同样 -fno-exceptions -frtti）。

#include <typeinfo>
#include <cstdio>

// ---- 测试类型层次 ----
struct Base {
    virtual ~Base() {}
    int x;
};
struct Derived : Base { int y; };            // 单继承 -> __si_class_type_info
struct Unrelated { virtual ~Unrelated() {} };// 无关多态类

struct A { virtual ~A() {} int a; };
struct B { virtual ~B() {} int b; };
struct C : A, B { int c; };                   // 多重继承 -> __vmi_class_type_info
struct D : C { int d; };                       // 深度继承链

struct NonPoly { int z; };                     // 非多态类（无虚函数）

int main() {
    int failures = 0;

    // (1) typeid 基本类型：name() 返回 Itanium mangled 名（首字符是长度）。
    {
        // 不同基本类型的 typeinfo 互不相同；同类型 typeinfo 对象身份相等。
        if (typeid(int) == typeid(double)) {
            printf("FAIL (1a) int==double typeid\n");
            ++failures;
        }
        if (!(typeid(int) == typeid(int))) {
            printf("FAIL (1b) int typeid self-eq\n");
            ++failures;
        }
        // name() 返回非空 mangled 串（int->"i"，double->"d"，const char*->"PKc"）。
        if (typeid(int).name()[0] != 'i') {
            printf("FAIL (1c) int name=%s\n", typeid(int).name());
            ++failures;
        }
        if (typeid(double).name()[0] != 'd') {
            printf("FAIL (1d) double name=%s\n", typeid(double).name());
            ++failures;
        }
    }

    // (2) typeid 多态类型（动态）：通过指针解引用取动态类型 typeinfo。
    {
        Derived d;
        Base* bp = &d;
        const std::type_info& dyn_ti = typeid(*bp);  // 动态：实际是 Derived
        const std::type_info& sta_ti = typeid(Derived); // 静态
        // Itanium ABI 约定同一类型 RTTI 唯一 -> 动态==静态（指针相等）。
        if (&dyn_ti != &sta_ti) {
            printf("FAIL (2) dynamic typeid != static: %s vs %s\n",
                   dyn_ti.name(), sta_ti.name());
            ++failures;
        }
    }

    // (3) hash_code：同类型 hash 相等，基本类型 hash 是 type_name 指针值（unique impl）。
    {
        std::size_t h1 = typeid(int).hash_code();
        std::size_t h2 = typeid(int).hash_code();
        std::size_t h3 = typeid(long).hash_code();
        if (h1 != h2) {
            printf("FAIL (3a) int hash_code inconsistent: %zu vs %zu\n", h1, h2);
            ++failures;
        }
        if (h1 == h3) {
            printf("FAIL (3b) int hash == long hash: %zu\n", h1);
            ++failures;
        }
    }

    // (4) before：定义全序（用于 std::type_index 在有序容器里排序）。
    {
        // before 不要求特定顺序，但必须自反一致：!(a.before(a))。
        const std::type_info& ti = typeid(Base);
        if (ti.before(ti)) {
            printf("FAIL (4) type before itself\n");
            ++failures;
        }
    }

    // (5) dynamic_cast 下行转换（基->派生）：成功返回派生指针。
    {
        Derived d;
        Base* bp = &d;
        Derived* dp = dynamic_cast<Derived*>(bp);
        if (dp != &d) {
            printf("FAIL (5) downcast failed: dp=%p &d=%p\n", (void*)dp, (void*)&d);
            ++failures;
        }
    }

    // (6) dynamic_cast 上行转换（派生->基）：恒成功，返回调整后的基指针。
    {
        Derived d;
        Base* bp = dynamic_cast<Base*>(&d);
        if (bp != static_cast<Base*>(&d)) {
            printf("FAIL (6) upcast\n");
            ++failures;
        }
    }

    // (7) dynamic_cast 空指针：源为 null 时结果恒 null（不解引用）。
    {
        Base* null_bp = nullptr;
        Derived* dp = dynamic_cast<Derived*>(null_bp);
        if (dp != nullptr) {
            printf("FAIL (7) null cast != null: dp=%p\n", (void*)dp);
            ++failures;
        }
    }

    // (8) dynamic_cast 无关类型：源对象不是目标类型，返回 null（不抛异常，因是指针转换）。
    {
        Derived d;
        Base* bp = &d;
        Unrelated* up = dynamic_cast<Unrelated*>(bp);
        if (up != nullptr) {
            printf("FAIL (8) unrelated cast should be null: up=%p\n", (void*)up);
            ++failures;
        }
    }

    // (9) dynamic_cast 多重继承交叉转换：A* <-> B*（通过 C 对象）。
    //     __vmi_class_type_info 路径——搜索多基类偏移表。
    {
        C cobj;
        A* ap = &cobj;
        B* bp = dynamic_cast<B*>(ap);  // 交叉：A 子对象 -> B 子对象
        if (bp == nullptr) {
            printf("FAIL (9a) MI cross-cast null\n");
            ++failures;
        } else if (dynamic_cast<C*>(ap) != &cobj) {
            printf("FAIL (9b) MI downcast through A* != &cobj\n");
            ++failures;
        }
    }

    // (10) dynamic_cast 深度继承链：D 经 C 多重继承到 A。
    {
        D dobj;
        A* ap = &dobj;  // D* -> A*（经 C）
        D* dp = dynamic_cast<D*>(ap);  // 再下行回到 D
        if (dp != &dobj) {
            printf("FAIL (10) deep downcast D->A->D\n");
            ++failures;
        }
    }

    // (11) typeinfo 对象身份：同一多态类型在程序内唯一（Itanium ABI 约定）。
    {
        Derived d1, d2;
        Base *b1 = &d1, *b2 = &d2;
        // 两个不同对象的动态类型都是 Derived -> typeid 应指向同一个 type_info 对象。
        if (&typeid(*b1) != &typeid(*b2)) {
            printf("FAIL (11) typeid identity across objects\n");
            ++failures;
        }
    }

    // (12) 非多态类型的 typeid：编译期确定，无动态查 vtable。
    {
        NonPoly np;
        // typeid(NonPoly) 与 typeid(np)（非多态，取静态类型）应相等。
        if (!(typeid(NonPoly) == typeid(np))) {
            printf("FAIL (12) non-poly typeid\n");
            ++failures;
        }
    }

    // (13) 跨基本类型 before/== 综合检查（回归保护：链接器 addend + typeinfo vtable 解析）。
    {
        bool self_ok = (typeid(int) == typeid(int));
        bool cross_ok = !(typeid(int) == typeid(const char*));
        bool ptr_ok = typeid(const char*).name()[0] == 'P';  // "PKc" -> 'P'(pointer)
        if (!(self_ok && cross_ok && ptr_ok)) {
            printf("FAIL (13) int/ptr rtti: self=%d cross=%d ptr=%d\n",
                   self_ok, cross_ok, ptr_ok);
            ++failures;
        }
    }

    if (failures == 0) {
        printf("OK rtti: all %d checks passed\n", 13);
    } else {
        printf("FAIL rtti: %d checks failed\n", failures);
    }
    return failures != 0;
}
