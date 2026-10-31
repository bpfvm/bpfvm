#!/usr/bin/env python3
"""生成 thunks.inc:签名无关 thunk 池(THUNK(n) 展开 + 地址表)。
数量必须与 closures.c 的 BPFFFI_MAX_CLOSURES 一致。"""
N = 256
print('/* 自动生成:签名无关 thunk 池与地址表,数量与 closures.c 的')
print(' * BPFFFI_MAX_CLOSURES 一致。重新生成(在仓库根的 ffi/ 目录):')
print(' *   python3 gen_thunks.py > thunks.inc */')
print()
for i in range(N):
    print(f'THUNK({i})')
print()
print('static void *const bpfffi_thunk_tab[BPFFFI_MAX_CLOSURES] = {')
for i in range(N):
    print(f'ADDR({i})')
print('};')
