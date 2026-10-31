/* ffitarget.h - bpfvm target definitions for the BPF ffi.
 *
 * The "calling convention" ffi marshals for is not a hardware ABI but the
 * protocol produced by clang -target bpf + the BpfWideArgs/BpfSoftFp passes:
 *   - one register slot (r1..r5) per C parameter; <=8B aggregates are coerced
 *     into a single integer, >=9B aggregates are passed as pointers
 *   - >5 slots: r1..r4 + r5 = pointer to a packed buffer (offsets are
 *     cumulative allocSize, no alignment padding)
 *   - variadic: named args in r1..rf, r(f+1) = va-pack pointer (f <= 4)
 *   - aggregate returns always go through a hidden sret pointer in r1
 *   - float/double travel as integer bit patterns
 */
#ifndef LIBFFI_TARGET_H
#define LIBFFI_TARGET_H

#ifndef LIBFFI_H
#error "Do not include ffitarget.h directly; include ffi.h instead."
#endif

typedef enum ffi_abi {
    FFI_FIRST_ABI = 0,
    FFI_SYSV,
    FFI_DEFAULT_ABI = FFI_SYSV,
    FFI_LAST_ABI = FFI_DEFAULT_ABI + 1
} ffi_abi;

/* Canonical libffi type codes; _ctypes inspects .type == FFI_TYPE_STRUCT. */
#define FFI_TYPE_VOID       0
#define FFI_TYPE_INT        1
#define FFI_TYPE_FLOAT      2
#define FFI_TYPE_DOUBLE     3
#define FFI_TYPE_LONGDOUBLE 4
#define FFI_TYPE_UINT8      5
#define FFI_TYPE_SINT8      6
#define FFI_TYPE_UINT16     7
#define FFI_TYPE_SINT16     8
#define FFI_TYPE_UINT32     9
#define FFI_TYPE_SINT32     10
#define FFI_TYPE_UINT64     11
#define FFI_TYPE_SINT64     12
#define FFI_TYPE_STRUCT     13
#define FFI_TYPE_POINTER    14
#define FFI_TYPE_COMPLEX    15

/* Closures are emulated with a static thunk pool (see closures.c). */
#define FFI_CLOSURES 1
#define FFI_TRAMPOLINE_SIZE 0
#define FFI_NATIVE_RAW_API 0

#endif
