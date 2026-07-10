// By-value struct parameter spike for the BPF VM.
//
// Scope: verifies that C++ functions taking struct parameters BY VALUE compile,
// link, and run correctly under bpfvm (JIT + interpreter).
//
// Why this needs a dedicated test:
//   The BPF backend rejects `byval` parameters ("pass by value not supported",
//   BPFISelLowering). The BpfWideArgs pass strips the `byval` attribute in the
//   IR (see src/passes/BpfWideArgs.cpp :: lowerAggregateParams, path A — the
//   former stripByval), turning the parameter
//   into a plain ptr — clang has already memcpys the argument into a stack
//   temporary at every call site and passes that pointer. This test guards two
//   invariants that would silently break if the lowering regressed:
//     - the callee reads the correct copy (quad_sum == 10);
//     - a callee mutation must NOT leak back to the caller (qt.a stays 1) —
//       this catches the case where a future optimizer pass elides the per-call
//       memcpy and accidentally passes the caller's original object.
//
// All callees carry __attribute__((noinline)) so -O1 cannot inline them and
// hide a byval-lowering regression (inlining removes the call + byval param).

extern "C" int printf(const char *, ...);

// 32-byte aggregate: forces a byval parameter (no callee-saved register path).
struct Quad { long a, b, c, d; };

// Read the by-value copy.
__attribute__((noinline)) long quad_sum(Quad q) {
    return q.a + q.b + q.c + q.d;
}

// Mutate the by-value copy; the caller's original must be untouched.
__attribute__((noinline)) long quad_mutate(Quad q) {
    q.a = 999;
    q.b = q.b + 1;
    return q.a * 1000 + q.b;
}

// By-value return (sret, already supported) combined with a by-value parameter.
struct Pair { long x; long y; };
__attribute__((noinline)) Pair make_pair(long v) {
    Pair p{v, v + 1};
    return p;
}
__attribute__((noinline)) long take_pair(Pair p) {
    return p.x * p.y;
}

int main() {
    int failures = 0;

    Quad qt{1, 2, 3, 4};
    long qs = quad_sum(qt);        // 1+2+3+4 = 10
    long qm = quad_mutate(qt);     // 999*1000 + (2+1) = 999003
    if (qs != 10 || qm != 999003 || qt.a != 1 || qt.b != 2) {
        printf("FAIL byval quad: qs=%ld qm=%ld qt={%ld,%ld}\n", qs, qm, qt.a, qt.b);
        ++failures;
    }

    Pair p = make_pair(7);         // {7, 8}
    long pp = take_pair(p);        // 7*8 = 56
    if (p.x != 7 || p.y != 8 || pp != 56) {
        printf("FAIL byval pair: p={%ld,%ld} pp=%ld\n", p.x, p.y, pp);
        ++failures;
    }

    printf("cpp_byval: quad_sum=%ld mutate=%ld (qt.a=%ld) pair=%ld\n",
           qs, qm, qt.a, pp);
    return failures == 0 ? 0 : 1;
}
