#!/bin/bash
# 构建 busybox for BPF。
# 策略：让 kbuild 只编译出各子目录的 built-in.o / lib.a（make busybox-all），
# 链接绕过 scripts/trylink（它对 -Wl,--sort-section 等 bpfvm-ld 不认的选项做探针会失败），
# 改用 bpfvm-ld 手动链接。
#
# 默认动态链接（与 build_root.sh 的 dash/sbase 一致）：
#   生成 PIE ET_DYN，libc.so 作为 DT_NEEDED 依赖，多个 BPF 程序共享同一份 libc.so。
#   运行：./build/bpfvm -- busybox/busybox.linked [applet ...]
# 静态链接：LINK_MODE=static ./scripts/build_busybox.sh
#   生成自包含 ET_EXEC（体积大，无运行时依赖）。
set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

# busybox 某些 applet 区分 linux，需要 __linux__ 宏（COMMON_CFLAGS 默认不带）。
COMMON_CFLAGS="${COMMON_CFLAGS} -D__linux__"
BB_DIR="${ROOT_DIR}/busybox"
make_ld_wrapper

configure() {
    echo "=== Configuring busybox ==="
    cd "${BB_DIR}"
    # 重新生成默认 config
    make HOSTCC=gcc defconfig >/dev/null 2>&1

    # 关掉不可用的 applet：网络栈、磁盘/文件系统管理、需要网络的服务端、
    # 需要 tty/getty 的 loginutils、需要浮点 long double 的（暂禁）。
    # sed 把 "=y" 行改成 "# CONFIG_xxx is not set" 不行——olddefconfig 会用 # is not set 形式。
    # 直接把值改 n，再跑 olddefconfig。
    local disable=(
        # 关掉编译失败的 applet（基于 defconfig -k 全量编译实测，非想当然）。
        # 分类：A=依赖内核UAPI头  B=VLA  C=浮点libcall  D=指针/int转换  E=synccall运行时nr
        # 共享 libbb 失败点（hash_md5_sha/xconnect/capability/loop）用 feature config
        # 或 include/{asm,linux}/ stub 头解决，不禁 applet 本体。
        # === A. 依赖内核 UAPI 头（linux/*.h asm/*.h mtd/*.h）===
        CONFIG_KBD_MODE CONFIG_OPENVT CONFIG_SHOWKEY CONFIG_LOADFONT CONFIG_SETFONT CONFIG_DEALLOCVT
        CONFIG_BEEP CONFIG_CONSPY CONFIG_FBSPLASH CONFIG_HDPARM
        CONFIG_I2CGET CONFIG_I2CSET CONFIG_I2CDUMP CONFIG_I2CDETECT CONFIG_I2CTRANSFER
        CONFIG_NANDWRITE CONFIG_NANDDUMP CONFIG_PARTPROBE CONFIG_RAIDAUTORUN CONFIG_SEEDRNG
        CONFIG_UBIRENAME CONFIG_UBIATTACH CONFIG_UBIDETACH CONFIG_UBIMKVOL
        CONFIG_UBIRMVOL CONFIG_UBIRSVOL CONFIG_UBIUPDATEVOL CONFIG_WATCHDOG
        CONFIG_ACPID CONFIG_BLKDISCARD CONFIG_BLOCKDEV CONFIG_FSFREEZE CONFIG_FSTRIM
        CONFIG_MDEV CONFIG_FEATURE_MDEV_CONFIG CONFIG_MKFS_VFAT CONFIG_MKFS_EXT2 CONFIG_MKE2FS
        CONFIG_SETPRIV CONFIG_UEVENT CONFIG_SWITCH_ROOT
        CONFIG_BRCTL CONFIG_ETHER_WAKE CONFIG_IFENSLAVE CONFIG_IFPLUGD
        CONFIG_NAMEIF CONFIG_NBDCLIENT CONFIG_TUNCTL CONFIG_ZCIP
        CONFIG_UDHCPC CONFIG_UDHCPC6
        CONFIG_IP CONFIG_FEATURE_IP CONFIG_FEATURE_IP_ADDRESS CONFIG_FEATURE_IP_LINK
        CONFIG_FEATURE_IP_ROUTE CONFIG_FEATURE_IP_TUNNEL CONFIG_FEATURE_IP_RULE
        CONFIG_FEATURE_IP_SHORT_FORMS CONFIG_IPADDR CONFIG_IPLINK CONFIG_IPROUTE
        CONFIG_IPTUNNEL CONFIG_IPRULE CONFIG_IPNEIGH CONFIG_FEATURE_IP_RARE_PROTOCOLS
        CONFIG_TC CONFIG_SLATTACH
        CONFIG_IONICE                             # include <asm/unistd.h> 取 __NR_ioprio_*，BPF 无此 UAPI/VM 实现（A 类）
        # === feature config（解决共享 libbb 失败，保留 applet 本体）===
        CONFIG_SHA1_HWACCEL CONFIG_SHA256_HWACCEL
        CONFIG_RUN_INIT CONFIG_FEATURE_SETPRIV_CAPABILITIES
        CONFIG_FEATURE_IFCONFIG_SLIP
        CONFIG_VLOCK                             # 缺 vlock_main（依赖 crypt/tty）
        CONFIG_MKDOSFS                           # 同 mkfs_vfat，缺 linux/hdreg.h
        # loop：libbb/loop.c 缺 linux/loop.h/posix_types.h，提供 set_loop 等给
        # losetup/mount。BPF 无 loop 设备，禁 LOSETUP + FEATURE_MOUNT_LOOP 让 loop.c 不参与
        CONFIG_LOSETUP CONFIG_FEATURE_MOUNT_LOOP
    )
    local cfg
    for cfg in "${disable[@]}"; do
        sed -i "s|^${cfg}=y|# ${cfg} is not set|" .config
    done

    # 显式启用的 config：defconfig 默认关、但 BPF/VM 环境需要的。
    local enable=(
        CONFIG_FEATURE_SH_STANDALONE
        CONFIG_FEATURE_SH_NOFORK
    )
    for cfg in "${enable[@]}"; do
        sed -i "s|^# ${cfg} is not set|${cfg}=y|" .config
        sed -i "s|^${cfg}=.*|${cfg}=y|" .config
    done

    # olddefconfig 同步依赖关系
    make HOSTCC=gcc CC="${CLANG_WRAPPER}" olddefconfig >/dev/null 2>&1 || true
    # 清理上次构建的陈旧 .o（config 改变后，被禁 applet 的 .o 仍会残留并参与链接）
    make clean >/dev/null 2>&1 || true
    echo "=== Config 关键项检查 ==="
    command grep -E 'CONFIG_(SH_IS_ASH|ASH|HUSH|CAT|LS|ECHO|TRUE|FALSE|SLEEP|DATE|ID|UNAME|STATIC|TC|INET|HTTPD|MOUNT|LOGIN|SU|DPKG|FEATURE_SH_STANDALONE|FEATURE_SH_NOFORK)=y' .config || true
}

build() {
    echo "=== Building busybox (编译各 built-in.o) ==="
    cd "${BB_DIR}"
    # make busybox_unstripped 会先把所有 $(busybox-all) 的 built-in.o/lib.a 编出来，
    # 最后才走 trylink。trylink 对 bpfvm-ld 不兼容会失败，但此时 .o 都已生成。
    # 这里允许失败，后面手动链接。
    make -k -j4 \
         HOSTCC=gcc \
         CC="${CLANG_WRAPPER}" \
         ARCH=bpf \
         CROSS_COMPILE= \
         KBUILD_VERBOSE=0 \
         CFLAGS="${COMMON_CFLAGS}" \
         LDFLAGS="-target bpf -nostdlib -L${ROOT_DIR}/root/lib" \
         busybox_unstripped || true
    local rc=${PIPESTATUS[0]}
    echo "=== make 退出码 ${rc}（链接阶段失败是预期的，检查 .o 产物）==="
    ls -la busybox_unstripped 2>/dev/null || echo "(无 busybox_unstripped，需要手动链接)"
}

# 收集所有真实 .o 文件到全局数组 OBJS。
# kbuild 的 built-in.o 是用 `ld -r` 合并的，但 bpfvm-ld 不支持 -r，
# 因此这些 built-in.o 是空的 ar 归档。改为直接收集所有真实 .o 文件
# （排除 built-in.o/lib.a 这些中间聚合产物），一次性交给 bpfvm-ld 链接。
collect_objs() {
    OBJS=()
    while IFS= read -r f; do
        OBJS+=("$f")
    done < <(find . -name '*.o' \
                -not -name 'built-in.o' \
                -not -path './.git/*' \
                -not -path './scripts/*' 2>/dev/null | sort)
    echo "收集到 ${#OBJS[@]} 个 .o 文件"
}

# 动态链接：与 build_root.sh 的 dash 一致，生成 PIE ET_DYN，libc.so 作为 DT_NEEDED 依赖。
# 运行时 bpfvm 从 root/lib/（或 LD_LIBRARY_PATH）解析 libc.so；多个动态可执行文件共享
# 同一份 libc.so，整体体积比静态链接小（busybox 自身不含 musl 代码）。
link_dyn() {
    echo "=== 手动链接 busybox (动态，bpfvm-ld) ==="
    cd "${BB_DIR}"
    collect_objs
    "${BPFVM_LD}" -L "${ROOT_DIR}/root/lib" -l c "${OBJS[@]}" -o busybox.linked
    local rc=${PIPESTATUS[0]}
    echo "=== 链接退出码 ${rc} ==="
    if [ -f busybox.linked ]; then
        file busybox.linked
        ls -la busybox.linked
    fi
}

# 静态链接：把 libc.a 整体并入 busybox，生成自包含的 ET_EXEC。体积大但无运行时依赖。
link_static() {
    echo "=== 手动链接 busybox (静态，bpfvm-ld) ==="
    cd "${BB_DIR}"
    collect_objs
    "${BPFVM_LD}" -static  "${OBJS[@]}" "${ROOT_DIR}/root/lib/libc.a" -o busybox.out
    local rc=${PIPESTATUS[0]}
    echo "=== 链接退出码 ${rc} ==="
    if [ -f busybox.out ]; then
        file busybox.out
        ls -la busybox.out
    fi
}

LINK_MODE="${LINK_MODE:-dyn}"
configure

# === 移植补丁：ash Ctrl+C 退出 bug（LLVM BPF 后端 miscompile workaround）===
# 给 popstackmark 加 noinline 阻断内联，绕过后端 bug。根因/机制/upstream issue
# 详见 AGENTS.md §5 "Known LLVM BPF backend bugs"。
# 幂等：已是 noinline 则跳过（perl s/// 不匹配已改过的行）。
if ! perl -0777 -ne 'exit 0 if /static void __attribute__\(\(noinline\)\)\npopstackmark/; exit 1' "${BB_DIR}/shell/ash.c"; then
    echo "=== Patching ash.c: popstackmark -> noinline (Ctrl+C bug fix) ==="
    perl -0777 -i -pe 's/^static void\n(popstackmark\(struct stackmark)/static void __attribute__((noinline))\n$1/m' "${BB_DIR}/shell/ash.c"
fi

build
if [ "${LINK_MODE}" = "static" ]; then
    link_static
else
    link_dyn
fi
