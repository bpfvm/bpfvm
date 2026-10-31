/* ffi.h - libffi-compatible API for the bpfvm BPF target.
 *
 * Implements the subset _ctypes uses: ffi_prep_cif / ffi_prep_cif_var /
 * ffi_call plus the closure API backed by a static thunk pool. Layout and
 * register rules mirror what the BpfWideArgs pass generates (see
 * ffitarget.h); there is no assembly - dispatch goes through a C helper
 * whose own >5-arg call is packed by the same pass.
 */
#ifndef LIBFFI_H
#define LIBFFI_H

#include <stddef.h>
#include <stdint.h>

#include "ffitarget.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long ffi_arg;
typedef signed long ffi_sarg;

typedef enum ffi_status {
    FFI_OK = 0,
    FFI_BAD_TYPEDEF,
    FFI_BAD_ABI
} ffi_status;

typedef struct _ffi_type {
    size_t size;
    unsigned short alignment;
    unsigned short type;
    struct _ffi_type **elements;
} ffi_type;

extern ffi_type ffi_type_void;
extern ffi_type ffi_type_sint;
extern ffi_type ffi_type_uint;
extern ffi_type ffi_type_schar;
extern ffi_type ffi_type_uchar;
extern ffi_type ffi_type_sshort;
extern ffi_type ffi_type_ushort;
extern ffi_type ffi_type_slong;
extern ffi_type ffi_type_ulong;
extern ffi_type ffi_type_uint8;
extern ffi_type ffi_type_sint8;
extern ffi_type ffi_type_uint16;
extern ffi_type ffi_type_sint16;
extern ffi_type ffi_type_uint32;
extern ffi_type ffi_type_sint32;
extern ffi_type ffi_type_uint64;
extern ffi_type ffi_type_sint64;
extern ffi_type ffi_type_pointer;
extern ffi_type ffi_type_float;
extern ffi_type ffi_type_double;
extern ffi_type ffi_type_longdouble;

/* Public fields match libffi (ctypes embeds ffi_cif by value and links
 * against this header); the trailing fields cache the bpfvm call layout. */
typedef struct {
    ffi_abi abi;
    unsigned nargs;
    ffi_type **arg_types;
    ffi_type *rtype;
    unsigned bytes;      /* total arena bytes (pack buffer + struct copies) */
    unsigned flags;
    unsigned nfixed;     /* 0 = fixed call; >0 = variadic with nfixed named args */
    unsigned nslots;     /* IR-level arg count incl. hidden sret pointer */
    unsigned has_sret;
} ffi_cif;

ffi_status ffi_prep_cif(ffi_cif *cif, ffi_abi abi, unsigned nargs,
                        ffi_type *rtype, ffi_type **atypes);
ffi_status ffi_prep_cif_var(ffi_cif *cif, ffi_abi abi, unsigned nfixedargs,
                            unsigned ntotalargs, ffi_type *rtype,
                            ffi_type **atypes);
void ffi_call(ffi_cif *cif, void (*fn)(void), void *rvalue, void **avalues);

/* Closure API: ffi_closure_alloc returns writable storage and hands back the
 * callable address (a pool thunk) through codeloc. */
typedef struct _ffi_closure {
    char trampoline[8]; /* unused; keeps the canonical field order */
    ffi_cif *cif;
    void (*fun)(ffi_cif *cif, void *ret, void **args, void *user_data);
    void *user_data;
    void *thunk;        /* internal: assigned pool thunk */
} ffi_closure;

void *ffi_closure_alloc(size_t size, void **codeloc);
void ffi_closure_free(void *p);
ffi_status ffi_prep_closure_loc(ffi_closure *closure, ffi_cif *cif,
                                void (*fun)(ffi_cif *, void *, void **, void *),
                                void *user_data, void *codeloc);
/* 废弃接口(_ctypes 回退分支会引用):忽略可执行地址,直接用池内 thunk */
ffi_status ffi_prep_closure(ffi_closure *closure, ffi_cif *cif,
                            void (*fun)(ffi_cif *, void *, void **, void *),
                            void *user_data);

#ifdef __cplusplus
}
#endif

#endif
