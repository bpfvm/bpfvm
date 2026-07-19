// shared_ptr by-value double-free reproducer for #207686 scope expansion.
#include <memory>
extern "C" int printf(const char *, ...);

struct X {
    int val;
    X(int v) : val(v) {}
    ~X() { printf("~X val=%d\n", val); }
};

std::shared_ptr<X> global;

__attribute__((noinline)) void store_in_global(std::shared_ptr<X> p) {
    printf("store: val=%d use_count=%ld\n", p->val, p.use_count());
    global = std::move(p);
}

int main() {
    auto p = std::make_shared<X>(42);
    store_in_global(std::move(p));
    int v = global->val;
    printf("after store: val=%d\n", v);
    return v == 42 ? 0 : 1;
}
