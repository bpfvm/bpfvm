// Minimal C++ language-feature spike for the BPF VM.
//
// Scope: verifies that core C++ language constructs compile, link, and run
// correctly on bpfvm (both JIT and interpreter). No C++ standard library
// headers are included; I/O and allocation go through musl's C runtime via
// extern "C".
//
// Covered:
//   - template instantiation
//   - class with ctor / methods / inheritance / virtual functions
//   - namespace, constexpr, function overloading, references
//   - auto, lambda with capture
//   - operator new / delete implemented on top of musl malloc / free
//
// Verified limitations (compile-time rejection, observed with clang 19
// `-target bpf -fno-exceptions -fno-rtti`):
//   - `throw` / `try`:
//       error: cannot use 'throw' with exceptions disabled
//       error: cannot use 'try' with exceptions disabled
//   - `dynamic_cast`:
//       error: use of dynamic_cast requires -frtti
//   - `typeid`:
//       error: you need to include <typeinfo> before using the 'typeid' operator
//     (<typeinfo> is part of the C++ runtime, not provided on this target.)
//   These are enforced at compile time, so they fail loud (not silent
//   miscompiles). Revisit when an exception-lowering pass and an RTTI
//   runtime are added.
//
// Constraints (current BPF C++ environment):
//   - No global objects with non-trivial constructors (no .init_array
//     framework yet); all objects are stack/heap allocated inside main.

extern "C" int printf(const char *, ...);
extern "C" void *malloc(unsigned long);
extern "C" void free(void *);

// operator new / delete backed by musl malloc / free.
// The Itanium C++ ABI mangles these to _Znwm / _ZdlPv; providing them here
// means C++ code using `new`/`delete` resolves without a C++ runtime library.
void *operator new(unsigned long n) { return malloc(n); }
void operator delete(void *p) noexcept { free(p); }
void operator delete(void *p, unsigned long) noexcept { free(p); }

// (1) template
template <typename T> struct Box {
    T v;
    T get() const { return v; }
    void set(T x) { v = x; }
};

// (2) class hierarchy with virtual dispatch
struct Base {
    int tag;
    explicit Base(int t) : tag(t) {}
    virtual ~Base() {}
    virtual long id() const { return tag * 10LL; }
};

struct Derived : Base {
    long extra;
    explicit Derived(long e) : Base(7), extra(e) {}
    long id() const override { return tag * 100LL + extra; }
};

// (3) namespace + constexpr + overload
namespace math {
constexpr int factorial(int n) { return n <= 1 ? 1 : n * factorial(n - 1); }
long abs_l(long x) { return x < 0 ? -x : x; }
} // namespace math

// counter to exercise side effects through a reference
static int inc_through_ref(int &r) {
    r += 1;
    return r;
}

int main() {
    int failures = 0;

    // (1) template
    Box<int> b;
    b.set(7);
    if (b.get() != 7) {
        printf("FAIL template: got %d\n", b.get());
        ++failures;
    }

    // (2) virtual dispatch through base pointer, plus heap via new/delete
    Base *p = new Derived(5);
    long vid = p->id(); // expect 7*100 + 5 = 705
    int tag = p->tag;   // expect 7
    delete p;
    if (vid != 705 || tag != 7) {
        printf("FAIL virtual/new: id=%ld tag=%d\n", vid, tag);
        ++failures;
    }

    // (3) constexpr + overload + namespace
    constexpr int f5 = math::factorial(5); // 120
    long a = math::abs_l(-42LL);            // 42
    if (f5 != 120 || a != 42) {
        printf("FAIL constexpr/overload: f5=%d a=%ld\n", f5, a);
        ++failures;
    }

    // (4) references
    int counter = 100;
    int got = inc_through_ref(counter); // 101, counter also 101
    if (got != 101 || counter != 101) {
        printf("FAIL reference: got=%d counter=%d\n", got, counter);
        ++failures;
    }

    // (5) auto + lambda with capture
    int sum = 0;
    auto add = [&](int x) { sum += x; };
    for (int i = 1; i <= 5; ++i)
        add(i);
    if (sum != 15) {
        printf("FAIL lambda: sum=%d\n", sum);
        ++failures;
    }

    // aggregated result; exit 0 only if everything passed
    printf("cpp_lang: template=%d virtual=%ld constexpr=%d ref=%d lambda=%d\n",
           b.get(), vid, f5, counter, sum);
    return failures == 0 ? 0 : 1;
}
