#!/bin/bash
# 构建 busybox for BPF。
# make busybox_unstripped 编译所有 built-in.o/lib.a 后走 scripts/trylink 最终链接。
# bpfvm-ld 已兼容 trylink（忽略 --start-group/--sort-*、吞掉 -Map 等带参选项、
# 按内容分发输入、支持 -r），且 libm.a 等子库软链接到 libc.a（-lm 即 -lc），
# trylink 直接产出最终二进制。
#
# 动态（默认）：PIE ET_DYN，libc.so 作为 DT_NEEDED 依赖。
#   运行：./build/bpfvm -- busybox/busybox.linked [applet ...]
# 静态：LINK_MODE=static ./scripts/build_busybox.sh，产出自包含 ET_EXEC。
set -e
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

# busybox 某些 applet 区分 linux，需要 __linux__ 宏（COMMON_CFLAGS 默认不带）。
COMMON_CFLAGS="${COMMON_CFLAGS} -D__linux__"
BB_DIR="${ROOT_DIR}/busybox"
make_ld_wrapper

# 屏蔽系统 bpf-gcc，让 clang fallback 到 host gcc：
# bpf-gcc 的 *link spec 不透传 -static 给 ld（upstream binutils-bpf 缺陷），静态模式下产出
# 会是 PIE 而非 ET_EXEC。在 wrapper 目录放 bpf-gcc → host gcc 软链并前置到 PATH，clang 查
# bpf-gcc 时优先命中它（host gcc 正确透传 -static）。系统 bpf-gcc 不动，仅影响本构建。
if [ -n "${LD_WRAPPER_DIR}" ] && [ -x /usr/bin/gcc ]; then
    ln -sf /usr/bin/gcc "${LD_WRAPPER_DIR}/bpf-gcc"
    cat > "${LD_WRAPPER_DIR}/clang" <<EOF
#!/bin/bash
export COMPILER_PATH="${LD_WRAPPER_DIR}"
export PATH="${LD_WRAPPER_DIR}:\${PATH}"
exec "$(command -v clang)" "\$@"
EOF
    chmod +x "${LD_WRAPPER_DIR}/clang"
    CLANG_WRAPPER="${LD_WRAPPER_DIR}/clang"
fi

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
    # 静态模式开启 CONFIG_STATIC（影响 trylink 的 --gc-sections 决策）。
    [ "${LINK_MODE}" = "static" ] && enable+=(CONFIG_STATIC)
    for cfg in "${enable[@]}"; do
        sed -i "s|^# ${cfg} is not set|${cfg}=y|" .config
        sed -i "s|^${cfg}=.*|${cfg}=y|" .config
    done
    [ "${LINK_MODE}" != "static" ] && sed -i "s|^CONFIG_STATIC=y|# CONFIG_STATIC is not set|" .config

    # olddefconfig 同步依赖关系
    make HOSTCC=gcc CC="${CLANG_WRAPPER}" olddefconfig >/dev/null 2>&1 || true
    # 清理上次构建的陈旧 .o（config 改变后，被禁 applet 的 .o 仍会残留并参与链接）
    make clean >/dev/null 2>&1 || true
    echo "=== Config 关键项检查 ==="
    command grep -E 'CONFIG_(SH_IS_ASH|ASH|HUSH|CAT|LS|ECHO|TRUE|FALSE|SLEEP|DATE|ID|UNAME|STATIC|TC|INET|HTTPD|MOUNT|LOGIN|SU|DPKG|FEATURE_SH_STANDALONE|FEATURE_SH_NOFORK)=y' .config || true
}

build() {
    echo "=== Building busybox ==="
    cd "${BB_DIR}"
    # trylink 直接产出最终二进制（动态 PIE / 静态 ET_EXEC，见顶部说明）。
    local ldflags="-target bpf -nostdlib -L${ROOT_DIR}/root/lib"
    [ "${LINK_MODE}" = "static" ] && ldflags="${ldflags} -static"
    make -j4 \
         HOSTCC=gcc \
         CC="${CLANG_WRAPPER}" \
         ARCH=bpf \
         CROSS_COMPILE= \
         KBUILD_VERBOSE=0 \
         CFLAGS="${COMMON_CFLAGS}" \
         LDFLAGS="${ldflags}" \
         busybox_unstripped
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

# trylink 产出即最终二进制，mv为约定文件名（动态 busybox.linked / 静态 busybox.out）。
cd "${BB_DIR}"
OUT=$([ "${LINK_MODE}" = "static" ] && echo busybox.out || echo busybox.linked)
mv busybox_unstripped "${OUT}"
file "${OUT}"
ls -la "${OUT}"
