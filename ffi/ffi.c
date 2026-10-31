/* ffi.c - ffi_call / ffi_prep_cif for the bpfvm BPF target.
 *
 * Register/pack rules replicated from the BpfWideArgs pass (probe-verified):
 *   - every C parameter occupies exactly one slot; <=8B aggregates are
 *     embedded by value, >=9B aggregates are pointers to writable copies
 *   - slots 0..3 -> r1..r4; with <=5 slots the 5th slot value rides r5,
 *     with >5 slots r5 points at a pack buffer holding slots 4.. at
 *     cumulative allocSize byte offsets
 *   - aggregate returns: hidden sret pointer is slot 0
 *   - variadic (nfixed named args, f <= 4): named in r1..rf, r(f+1) points
 *     at a va-pack buffer with the same cumulative layout
 *   - float/double are marshaled as integer bit patterns (little endian)
 *
 * The actual call goes through bpfffi_call5: a 6-arg C helper whose own
 * >5-arg call the pass packs, so its body re-materializes r1..r4 = s0..s3,
 * r5 = s4 and performs the indirect call - the pass does the register
 * marshaling for us.
 */
#include <stdlib.h>
#include <string.h>

#include "ffi.h"
#include "bpf_ffi_internal.h"

ffi_type ffi_type_void = { 0, 0, FFI_TYPE_VOID, NULL };
/* libffi 旧版短名(_ctypes 的 cfield/callproc 按这些名字引用) */
ffi_type ffi_type_sint = { 4, 4, FFI_TYPE_SINT32, NULL };
ffi_type ffi_type_uint = { 4, 4, FFI_TYPE_UINT32, NULL };
ffi_type ffi_type_schar = { 1, 1, FFI_TYPE_SINT8, NULL };
ffi_type ffi_type_uchar = { 1, 1, FFI_TYPE_UINT8, NULL };
ffi_type ffi_type_sshort = { 2, 2, FFI_TYPE_SINT16, NULL };
ffi_type ffi_type_ushort = { 2, 2, FFI_TYPE_UINT16, NULL };
ffi_type ffi_type_slong = { 8, 8, FFI_TYPE_SINT64, NULL };
ffi_type ffi_type_ulong = { 8, 8, FFI_TYPE_UINT64, NULL };
ffi_type ffi_type_uint8 = { 1, 1, FFI_TYPE_UINT8, NULL };
ffi_type ffi_type_sint8 = { 1, 1, FFI_TYPE_SINT8, NULL };
ffi_type ffi_type_uint16 = { 2, 2, FFI_TYPE_UINT16, NULL };
ffi_type ffi_type_sint16 = { 2, 2, FFI_TYPE_SINT16, NULL };
ffi_type ffi_type_uint32 = { 4, 4, FFI_TYPE_UINT32, NULL };
ffi_type ffi_type_sint32 = { 4, 4, FFI_TYPE_SINT32, NULL };
ffi_type ffi_type_sint64 = { 8, 8, FFI_TYPE_SINT64, NULL };
ffi_type ffi_type_uint64 = { 8, 8, FFI_TYPE_UINT64, NULL };
ffi_type ffi_type_pointer = { 8, 8, FFI_TYPE_POINTER, NULL };
ffi_type ffi_type_float = { 4, 4, FFI_TYPE_FLOAT, NULL };
ffi_type ffi_type_double = { 8, 8, FFI_TYPE_DOUBLE, NULL };
ffi_type ffi_type_longdouble = { 8, 8, FFI_TYPE_LONGDOUBLE, NULL };

/* Bytes a parameter occupies in a slot / pack field (scalar = sizeof,
 * <=8B struct embedded = sizeof, >=9B struct = pointer). */
unsigned ffibpf_slot_size(const ffi_type *t)
{
    if (t->type == FFI_TYPE_STRUCT && t->size > 8)
        return 8;
    return t->size;
}

unsigned ffibpf_round8(unsigned n)
{
    return (n + 7u) & ~7u;
}

static int type_valid(const ffi_type *t)
{
    if (t == NULL || t->type == FFI_TYPE_COMPLEX)
        return 0;
    if (t->type != FFI_TYPE_STRUCT && t->size > 8)
        return 0;
    return 1;
}

int ffibpf_is_big_struct(const ffi_type *t)
{
    return t->type == FFI_TYPE_STRUCT && t->size > 8;
}

/* 变参值在 va-pack 中的宽度。callee 的 va_arg 对聚合一律按引用(clang 生成
 * va_arg ap, ptr 再解引用),pack 字段存指针(8B);标量按 sizeof 内嵌。
 * pass 侧 rewriteCallSitePacked 对聚合变参同样存指针、步长 8。 */
unsigned ffibpf_va_size(const ffi_type *t)
{
    if (t->type == FFI_TYPE_STRUCT)
        return 8;
    return t->size;
}

static uint64_t load_le(const void *p, unsigned n)
{
    uint64_t v = 0;
    memcpy(&v, p, n);
    return v;
}

static void store_le(void *p, unsigned n, uint64_t v)
{
    memcpy(p, &v, n);
}

static uint64_t bpfffi_call5(void *fn, uint64_t s0, uint64_t s1, uint64_t s2,
                             uint64_t s3, uint64_t s4)
{
    typedef uint64_t (*f5)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    return ((f5)fn)(s0, s1, s2, s3, s4);
}

static ffi_status prep(ffi_cif *cif, ffi_abi abi, unsigned nargs,
                       unsigned nfixed, ffi_type *rtype, ffi_type **atypes)
{
    unsigned i, copy_bytes = 0, pack_bytes = 0;

    if (abi < FFI_FIRST_ABI || abi >= FFI_LAST_ABI)
        return FFI_BAD_ABI;
    if (rtype == NULL || !type_valid(rtype))
        return FFI_BAD_TYPEDEF;
    if (nargs > BPFFFI_MAX_ARGS)
        return FFI_BAD_TYPEDEF;

    cif->abi = abi;
    cif->nargs = nargs;
    cif->arg_types = atypes;
    cif->rtype = rtype;
    cif->nfixed = nfixed;

    /* 变参去变参化后在具名参数后追加 __va_base;工具链无法 lower
     * 6 参去变参签名,故具名最多 4 个,且 sret 与变参不可组合。 */
    if (nfixed) {
        if (nfixed < 1 || nfixed > 4 || nargs < nfixed)
            return FFI_BAD_TYPEDEF;
        if (rtype->type == FFI_TYPE_STRUCT)
            return FFI_BAD_TYPEDEF;
    }

    for (i = 0; i < nargs; i++) {
        if (!type_valid(atypes[i]))
            return FFI_BAD_TYPEDEF;
        /* 定参区 >=9B 结构体传 arena 指针;变参区一切结构体按引用传 arena 指针 */
        if (atypes[i]->type == FFI_TYPE_STRUCT &&
            (ffibpf_is_big_struct(atypes[i]) || (nfixed && i >= nfixed)))
            copy_bytes += ffibpf_round8(atypes[i]->size);
    }

    cif->has_sret = rtype->type == FFI_TYPE_STRUCT;
    cif->nslots = nargs + cif->has_sret;
    cif->flags = 0;
    if (nfixed) {
        for (i = nfixed; i < nargs; i++)
            pack_bytes += ffibpf_va_size(atypes[i]);
    } else if (cif->nslots > 5) {
        for (i = 4 - cif->has_sret; i < nargs; i++)
            pack_bytes += ffibpf_slot_size(atypes[i]);
    }
    cif->bytes = copy_bytes + pack_bytes;
    return FFI_OK;
}

ffi_status ffi_prep_cif(ffi_cif *cif, ffi_abi abi, unsigned nargs,
                        ffi_type *rtype, ffi_type **atypes)
{
    return prep(cif, abi, nargs, 0, rtype, atypes);
}

ffi_status ffi_prep_cif_var(ffi_cif *cif, ffi_abi abi, unsigned nfixedargs,
                            unsigned ntotalargs, ffi_type *rtype,
                            ffi_type **atypes)
{
    if (nfixedargs < 1)   /* libffi 同样要求至少 1 个具名参数 */
        return FFI_BAD_TYPEDEF;
    return prep(cif, abi, ntotalargs, nfixedargs, rtype, atypes);
}

/* 窄符号整数在寄存器槽必须由调用方符号扩展(BPF 参数降级省略使用点扩展,
 * 调用方传 0xFF 即被当作 +255);pack 区字段恰好 N 字节,被调方 ldxsb 自行
 * 扩展,无需处理。 */
static uint64_t sext_le(const void *p, const ffi_type *t)
{
    uint64_t v = load_le(p, t->size);
    switch (t->type) {
    case FFI_TYPE_INT:
    case FFI_TYPE_SINT8:
    case FFI_TYPE_SINT16:
    case FFI_TYPE_SINT32:
        if (t->size == 1) return (uint64_t)(int64_t)(int8_t)v;
        if (t->size == 2) return (uint64_t)(int64_t)(int16_t)v;
        if (t->size == 4) return (uint64_t)(int64_t)(int32_t)v;
        return v;
    default:
        return v;
    }
}

/* 参数 i 的 slot 值;>=9B 结构体先拷入 arena 可写区再传指针。 */
static uint64_t arg_slot(const ffi_cif *cif, void **avalues, char *arena,
                         unsigned *copy_off, unsigned i)
{
    ffi_type *t = cif->arg_types[i];
    if (ffibpf_is_big_struct(t)) {
        char *dst = arena + *copy_off;
        memcpy(dst, avalues[i], t->size);
        *copy_off += ffibpf_round8(t->size);
        return (uint64_t)(uintptr_t)dst;
    }
    return sext_le(avalues[i], t);
}

void ffi_call(ffi_cif *cif, void (*fn)(void), void *rvalue, void **avalues)
{
    uint64_t s[5] = { 0, 0, 0, 0, 0 };
    unsigned copy_bytes = 0, copy_off = 0, pack_off = 0, i;
    char *arena, *pack;
    uint64_t ret;

    /* 与 prep 的 copy_bytes 记账一致:定参区 >=9B 结构体 + 变参区一切结构体。
     * 记账规则若改动须同步 prep;更稳妥是把 copy_bytes 存进 cif(如恒 0 的
     * flags 字段)消除这份重复。 */
    for (i = 0; i < cif->nargs; i++)
        if (cif->arg_types[i]->type == FFI_TYPE_STRUCT &&
            (ffibpf_is_big_struct(cif->arg_types[i]) ||
             (cif->nfixed && i >= cif->nfixed)))
            copy_bytes += ffibpf_round8(cif->arg_types[i]->size);
    arena = cif->bytes ? malloc(cif->bytes) : NULL;
    pack = arena ? arena + copy_bytes : NULL;

    if (cif->nfixed) {
        for (i = 0; i < cif->nfixed; i++)
            s[i] = arg_slot(cif, avalues, arena, &copy_off, i);
        /* 变参值按 va 约定:结构体按引用存 arena 拷贝指针,标量按 sizeof 内嵌 */
        for (i = cif->nfixed; i < cif->nargs; i++) {
            ffi_type *t = cif->arg_types[i];
            if (t->type == FFI_TYPE_STRUCT) {
                char *dst = arena + copy_off;
                memcpy(dst, avalues[i], t->size);
                copy_off += ffibpf_round8(t->size);
                store_le(pack + pack_off, 8, (uint64_t)(uintptr_t)dst);
            } else {
                store_le(pack + pack_off, t->size, sext_le(avalues[i], t));
            }
            pack_off += ffibpf_va_size(t);
        }
        s[cif->nfixed] = (uint64_t)(uintptr_t)pack;
    } else {
        if (cif->has_sret)
            s[0] = (uint64_t)(uintptr_t)rvalue;
        if (cif->nslots > 5) {
            for (i = 0; i < 4 - cif->has_sret; i++)
                s[i + cif->has_sret] =
                    arg_slot(cif, avalues, arena, &copy_off, i);
            for (i = 4 - cif->has_sret; i < cif->nargs; i++) {
                store_le(pack + pack_off, ffibpf_slot_size(cif->arg_types[i]),
                         arg_slot(cif, avalues, arena, &copy_off, i));
                pack_off += ffibpf_slot_size(cif->arg_types[i]);
            }
            s[4] = (uint64_t)(uintptr_t)pack;
        } else {
            for (i = 0; i < cif->nargs; i++)
                s[i + cif->has_sret] =
                    arg_slot(cif, avalues, arena, &copy_off, i);
        }
    }

    ret = bpfffi_call5((void *)(uintptr_t)fn, s[0], s[1], s[2], s[3], s[4]);
    if (cif->rtype->type != FFI_TYPE_VOID &&
        cif->rtype->type != FFI_TYPE_STRUCT)
        *(uint64_t *)rvalue = ret;
    free(arena);
}
