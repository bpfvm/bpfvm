# bpfvm - 用户态 BPF 虚拟机

`bpfvm` 是一个基于 C++20 实现的 BPF (eBPF) 虚拟机，旨在在用户态加载并运行 BPF ELF 二进制文件。

与内核中的 BPF 运行时不同，本项目致力于提供一个类似 POSIX 的运行环境，通过集成 [PDCLib](https://uclibc.org/pdclib/) (Public Domain C Library) 和模拟常见的系统调用 (syscalls)，使得标准的 C 语言程序（如 `dash` shell 和 `sbase` 工具集）能够通过交叉编译运行在此虚拟机上。

## 核心特性

*   **ELF 加载器**: 解析并加载标准 BPF ELF 可执行文件（支持静态链接与动态链接 PIE）。
*   **JIT 加速**: 混合解释器/JIT 执行模型，热函数编译为 x86_64 / AArch64 原生代码，配合软件 TLB 加速地址翻译。
*   **指令集支持**: 实现核心 eBPF 指令集解释执行。
*   **浮点支持**: 通过 `BpfSoftFp` LLVM pass 提供 `float`/`double` 支持（算术、类型转换、比较）。
*   **系统调用模拟**: 通过可插拔的 `SyscallHandler` 接口实现了 `open`, `read`, `write`, `fork`, `execve` 等核心 POSIX 系统调用，支持文件系统操作和进程控制。
*   **标准库支持**: 深度集成了 `PDCLib`，为 BPF 程序提供标准 C 库支持 (stdio, stdlib, string 等)。
*   **信号支持**: 支持信号处理（`SIGKILL`/`SIGSTOP`/`SIGCONT` 等），使用无锁队列实现信号传递，支持信号打断系统调用。
*   **内存安全**: 提供内存越界检查机制。
*   **实际应用支持**: 能够运行 `dash` (Debian Almquist Shell) 和 `sbase` (coreutils) 等复杂程序。
*   **Demo Rootfs**: 提供脚本一键构建 `dash + sbase` 的最小 rootfs，并安装到 `root/`。

## 构建指南

### 依赖项

构建本项目需要以下工具和库：

*   **C++ 编译器**: 支持 C++20 标准 (推荐 Clang 或 GCC)。
*   **CMake**: 3.16 或更高版本。
*   **libelf**: 用于 ELF 文件解析 (`libelf-dev` 或 `elfutils-libelf-devel`)。
*   **BPF 工具链**: `clang >= 19` 编译 Guest 程序，`bpfvm-ld`（本项目自带）链接。无需 `binutils-bpf`。

### 编译虚拟机

```bash
# 配置并构建
cmake -S . -B build
cmake --build build

# 构建产物：
#   build/bpfvm / bpfvm-ld / bpfvm_test —— 虚拟机、链接器、单元测试
#   build/libBpfWideArgs.so / libBpfSoftFp.so —— LLVM pass 插件（Guest 编译用，
#     需 LLVM 开发头；缺失时跳过，不影响 VM 本体）
```

### 编译 PDCLib (Guest 标准库)

在编译任何 BPF Guest 程序之前，需要先构建针对 BPF 目标的 PDCLib：

```bash
cd pdclib
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=bpf-toolchain.cmake
cmake --build build
cmake --install build --prefix build/install
cd ..
```
*注意：项目根目录下的 `libc` 是指向 `pdclib/build/install` 的符号链接，安装完成后即可通过 `-Ilibc/include` 使用。*

## 运行与测试

### 运行 BPF 程序

使用编译好的虚拟机加载 ELF 文件：

```bash
./build/bpfvm <path-to-elf-file>
```

### 运行单元测试

VM 自身的指令集单元测试：

```bash
./build/bpfvm_test
```

### 构建 Demo Rootfs (dash + sbase)

一键构建 `dash` 和 `sbase`，并将产物安装到 `root/bin`：

```bash
./build_root.sh
# 运行 dash（示例）
./build/bpfvm root/bin/dash
```

### 运行集成测试

编译并运行 `test/` 目录下的简单 BPF 测试用例：

```bash
make -C test
```

## 项目结构

```
├── src/
│   ├── main.cpp              # VM 入口，命令行解析
│   ├── insn.h / insn.cpp     # VM 核心：指令定义、解释执行循环、浮点原语 do_softfp
│   ├── posix_syscall.h/cpp   # POSIX 系统调用实现 (PosixSyscall)
│   ├── empty_syscall.h       # 空系统调用桩 (EmptySyscall, 用于测试)
│   ├── elf_loader.h/cpp      # BPF ELF 加载与库搜索
│   ├── elf_linker.h/cpp      # 离线 BPF 链接器核心（静态/共享/动态三种模式）
│   ├── ld_main.cpp           # bpfvm-ld CLI
│   ├── jit/                  # JIT 子系统（编译器 + 各架构发射器）
│   │   ├── jit.h, jit_base_emitter.h     # JIT 共享结构与发射基类
│   │   ├── jit_compiler.h/cpp    # 架构无关的 JIT 编译器模板
│   │   ├── x86_emitter.h/cpp     # x86_64 JIT 代码发射
│   │   └── aarch64_emitter.h/cpp # AArch64 JIT 代码发射
│   ├── passes/               # LLVM pass 插件（编译为 build/lib*.so，由 clang -fpass-plugin= 加载）
│   │   ├── BpfWideArgs.cpp   #   突破 5 参数限制 + 返回结构体 + 变参函数
│   │   └── BpfSoftFp.cpp     #   把浮点 IR 改写为软浮点 call（启用 float/double）
│   └── insn_test.cpp         # 指令集单元测试
├── include/              # BPF Guest 程序使用的头文件（syscall ID、POSIX 类型、浮点 call 编号）
├── cmake/                # CMake 辅助脚本（CTest 集成等）
├── pdclib/               # PDCLib 标准 C 库 (子模块)
├── dash/                 # dash shell (子模块)
├── sbase/                # sbase coreutils
├── test/                 # BPF 集成测试用例
└── root/                 # Demo rootfs 输出目录
```

VM 架构采用可插拔的 `SyscallHandler` 接口，将指令执行 (`insn.cpp`) 与系统调用处理 (`posix_syscall.cpp`) 解耦。`PosixSyscall` 提供完整的 POSIX 系统调用模拟，`EmptySyscall` 则作为测试用的空实现。

## 架构限制与开发指南

由于 BPF 架构的特殊性，为本虚拟机开发 C 程序时需注意以下限制：

1.  **浮点运算**: BPF 硬件本身无浮点单元。本项目通过 `BpfSoftFp` LLVM pass 插件（编译时自动注入）提供 `float`/`double` 支持，可直接使用，无需手动改写。
2.  **参数与返回值限制**: 原生 BPF 调用约定最多 **5 个参数**，且无法返回结构体。本项目自带 `BpfWideArgs` LLVM pass 插件，编译时自动解决这两个限制。
3.  **变长参数 (Varargs)**: BPF 后端拒绝任何变参函数。`BpfWideArgs` pass 同样自动解决，可直接使用 `...` 函数及 `va_start`/`va_arg`。

> 三类限制的细节与历史实现方案见 [`AGENTS.md`](AGENTS.md) 的 "BPF Architecture Constraints & Developer Guide" 一节。

## 工具链

本项目自带 BPF 链接器 `bpfvm-ld`（`src/ld_main.cpp`），完全替代 `binutils-bpf` `bpf-ld`。

```bash
# 编译（clang 直接，无 wrapper）
clang -target bpf -mcpu=v4 -O1 -nostdinc -fno-builtin \
      -isystem libc/include -isystem include -g \
      foo.c -c -o foo.o

# 链接（三种模式）
bpfvm-ld -static foo.o -l:libpdclib.a -o foo.linked        # 静态：自包含 ET_EXEC
bpfvm-ld --shared --soname libc.so libpdclib.a -o libc.so  # 共享库：PIE .so
bpfvm-ld foo.o -l libc.so -o foo.linked                    # 动态（默认）：PIE + DT_NEEDED

# 运行
bpfvm foo.linked    # 或 foo.dyn
```

`bpfvm-ld` 兼容 clang/gcc 风格命令行（接受 `-target`、`-Wl,...`、`-isystem` 等），可作为 autoconf 项目的 `CCLD`。


## 许可证

[待补充，如 MIT / GPL]
