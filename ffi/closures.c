/* closures.c - ffi_closure emulation via a static signature-agnostic
 * thunk pool.
 *
 * The BpfWideArgs convention gives every compiled function the same
 * register shape (r1..r4 = first four slots, r5 = 5th slot value or pack
 * pointer), so one thunk body typed u64(u64,u64,u64,u64,void*) is callable
 * under any signature. Each thunk forwards its register image plus its own
 * index to bpfffi_closure_dispatch, which reconstructs the argument values
 * from the cif and invokes the closure's fun().
 *
 * Unread registers are ignored; a >5-slot caller passes the pack pointer
 * in r5, which dispatch unpacks via the cif. A struct-returning caller
 * passes the hidden sret pointer in r1 (= a0), which becomes fun()'s
 * return buffer.
 */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "ffi.h"
#include "bpf_ffi_internal.h"

#define BPFFFI_MAX_CLOSURES 256

#define THUNK(n)                                                              \
    static uint64_t __attribute__((used)) bpfffi_thunk_##n(                  \
        uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, void *pack)      \
    {                                                                         \
        return bpfffi_closure_dispatch((n), a0, a1, a2, a3,                  \
                                       (uint64_t)(uintptr_t)pack);           \
    }
#define ADDR(n) bpfffi_thunk_##n,

#include "thunks.inc"

static ffi_closure *bpfffi_pool[BPFFFI_MAX_CLOSURES];
static char bpfffi_used[BPFFFI_MAX_CLOSURES];
static pthread_mutex_t bpfffi_pool_mu = PTHREAD_MUTEX_INITIALIZER;

/* 从 thunk 地址反查池下标;-1 表示不在池中。 */
static int thunk_index(void *thunk)
{
    int i;
    for (i = 0; i < BPFFFI_MAX_CLOSURES; i++)
        if (bpfffi_thunk_tab[i] == thunk)
            return i;
    return -1;
}

static uint64_t load_le(const void *p, unsigned n)
{
    uint64_t v = 0;
    memcpy(&v, p, n);
    return v;
}

/* 间接调用(函数指针)与直接调用同一约定(BpfWideArgs 对两类调用点都把聚合
 * 实参归一化为裸指针):每个参数恰占 1 个槽 —— 标量/<=8B 结构体内嵌,
 * >=9B 结构体是指向调用方临时拷贝的指针。>5 槽时 r5 是 pack 指针,槽 4 起
 * 按累计 allocSize(ffibpf_slot_size)排布;<=5 槽时第 5 槽的值直接在 r5。 */

uint64_t bpfffi_closure_dispatch(unsigned idx, uint64_t a0, uint64_t a1,
                                 uint64_t a2, uint64_t a3, uint64_t r5)
{
    ffi_closure *cl;
    const uint64_t regs[4] = { a0, a1, a2, a3 };
    ffi_cif *cif;
    void *args[BPFFFI_MAX_ARGS];
    uint64_t staging[BPFFFI_MAX_ARGS];
    uint64_t ret8 = 0;
    unsigned i, slot, pack_off = 0, nslots;

    cl = bpfffi_pool[idx];
    if (cl == NULL)
        return 0;
    cif = cl->cif;
    nslots = cif->nslots;   /* 含 sret(结构体返回回调,ctypes 不建,防御保留) */
    slot = cif->has_sret;

    for (i = 0; i < cif->nargs; i++) {
        ffi_type *t = cif->arg_types[i];
        uint64_t v;

        if (nslots > 5 && slot >= 4) {
            v = load_le((char *)(uintptr_t)r5 + pack_off, ffibpf_slot_size(t));
            pack_off += ffibpf_slot_size(t);
        } else if (slot < 4) {
            v = regs[slot];
        } else {
            v = r5;   /* 总槽数恰 5:第 5 槽的值直接在 r5 */
        }
        slot++;
        if (t->type == FFI_TYPE_STRUCT && t->size > 8) {
            args[i] = (void *)(uintptr_t)v;
        } else {
            staging[i] = v;
            args[i] = &staging[i];
        }
    }

    cl->fun(cif,
            cif->has_sret ? (void *)(uintptr_t)a0 : (void *)&ret8,
            args, cl->user_data);

    return cif->has_sret ? 0 : ret8;
}

void *ffi_closure_alloc(size_t size, void **codeloc)
{
    ffi_closure *cl;
    int i;

    if (size < sizeof(ffi_closure))
        return NULL;
    cl = malloc(size);
    if (cl == NULL)
        return NULL;
    memset(cl, 0, size);

    pthread_mutex_lock(&bpfffi_pool_mu);
    for (i = 0; i < BPFFFI_MAX_CLOSURES; i++) {
        if (!bpfffi_used[i]) {
            bpfffi_used[i] = 1;
            break;
        }
    }
    pthread_mutex_unlock(&bpfffi_pool_mu);
    if (i == BPFFFI_MAX_CLOSURES) {
        free(cl);
        return NULL;
    }
    cl->thunk = bpfffi_thunk_tab[i];
    *codeloc = cl->thunk;
    return cl;
}

void ffi_closure_free(void *p)
{
    ffi_closure *cl = p;
    int i;

    if (cl == NULL)
        return;
    pthread_mutex_lock(&bpfffi_pool_mu);
    i = thunk_index(cl->thunk);
    if (i >= 0) {
        if (bpfffi_pool[i] == cl)
            bpfffi_pool[i] = NULL;
        bpfffi_used[i] = 0;
    }
    pthread_mutex_unlock(&bpfffi_pool_mu);
    free(cl);
}

static ffi_status prep_bind(ffi_closure *closure, ffi_cif *cif,
                            void (*fun)(ffi_cif *, void *, void **, void *),
                            void *user_data, void *codeloc)
{
    int i;

    if (cif == NULL || closure == NULL || fun == NULL)
        return FFI_BAD_TYPEDEF;
    if (cif->nfixed)   /* dispatch 按定参槽位还原,不认 va-pack 布局 */
        return FFI_BAD_TYPEDEF;
    if (cif->abi < FFI_FIRST_ABI || cif->abi >= FFI_LAST_ABI)
        return FFI_BAD_ABI;

    i = thunk_index(closure->thunk);
    if (i < 0 || (codeloc != NULL && codeloc != closure->thunk))
        return FFI_BAD_ABI;

    closure->cif = cif;
    closure->fun = fun;
    closure->user_data = user_data;
    pthread_mutex_lock(&bpfffi_pool_mu);
    bpfffi_pool[i] = closure;
    pthread_mutex_unlock(&bpfffi_pool_mu);
    return FFI_OK;
}

ffi_status ffi_prep_closure_loc(ffi_closure *closure, ffi_cif *cif,
                                void (*fun)(ffi_cif *, void *, void **, void *),
                                void *user_data, void *codeloc)
{
    return prep_bind(closure, cif, fun, user_data, codeloc);
}

ffi_status ffi_prep_closure(ffi_closure *closure, ffi_cif *cif,
                            void (*fun)(ffi_cif *, void *, void **, void *),
                            void *user_data)
{
    if (closure != NULL && closure->thunk == NULL) {
        /* 未走 ffi_closure_alloc 的调用方:补分配一个池 thunk */
        pthread_mutex_lock(&bpfffi_pool_mu);
        for (int i = 0; i < BPFFFI_MAX_CLOSURES; i++) {
            if (!bpfffi_used[i]) {
                bpfffi_used[i] = 1;
                closure->thunk = bpfffi_thunk_tab[i];
                break;
            }
        }
        pthread_mutex_unlock(&bpfffi_pool_mu);
    }
    return prep_bind(closure, cif, fun, user_data, NULL);
}
