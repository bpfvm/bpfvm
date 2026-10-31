/* bpf_ffi_internal.h - ffi.c 与 closures.c 共享的布局辅助。 */
#ifndef BPF_FFI_INTERNAL_H
#define BPF_FFI_INTERNAL_H

#include "ffi.h"

#define BPFFFI_MAX_ARGS 1024

unsigned ffibpf_slot_size(const ffi_type *t);
unsigned ffibpf_va_size(const ffi_type *t);
unsigned ffibpf_round8(unsigned n);
int ffibpf_is_big_struct(const ffi_type *t);

uint64_t bpfffi_closure_dispatch(unsigned idx, uint64_t a0, uint64_t a1,
                                 uint64_t a2, uint64_t a3, uint64_t r5);

#endif
