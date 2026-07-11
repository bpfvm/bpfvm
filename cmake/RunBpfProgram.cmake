# 每个用例内部串行跑 4 个变体：静态/动态 × JIT 开/关。
# 不同用例之间由 ctest -j 并发。同用例的 4 变体串行，不冲突文件。
#
# 参数：BPFVM / NAME / WORKDIR / ROOT（可选）
#   ROOT 非空 → chroot 模式：每个变体建临时 rootfs，prog 以 guest 路径（/<name>.<suffix>）
#   启动（bpfvm --root <rootfs>）。root/lib 一并拷入（动态变体的 PT_INTERP 解析）。
#   host 变体跳过（chroot 无宿主对照意义）。隔离正确性由 guest 程序自身断言

if(NOT DEFINED BPFVM)
    message(FATAL_ERROR "BPFVM is required")
endif()
if(NOT DEFINED NAME)
    message(FATAL_ERROR "NAME is required")
endif()
if(NOT DEFINED WORKDIR)
    set(WORKDIR "${CMAKE_CURRENT_LIST_DIR}/..")
endif()

# label|program_suffix|BPF_TEST_VARIANT|JIT_ENABLE|JIT_THRESHOLD  ("-" 占位空值)
# 前 4 个走 bpfvm（静态/动态 × JIT/解释器）。
# JIT 变体设 JIT_THRESHOLD=1：每个 pc 命中一次即编译，最大化 JIT 覆盖（暴露冷代码
# 路径里的 JIT 缺陷，而非只在热点循环上验证）。
# 第 5 个 host 变体直接运行宿主 gcc 原生二进制（test/Makefile 的 *.host），
# 作为 BPF/musl/bpfvm 实现的对照基线：同一测试逻辑在标准 glibc 下也应通过。
set(variants
    "static_jit|out|-|-|1"
    "dynamic_jit|linked|linked|-|1"
    "static_interp|out|-|0|-"
    "dynamic_interp|linked|linked|0|-"
    "host|host|host|-|-"
)

# chroot 模式下需要 root/lib（libc.so = ld-bpf.so，供动态变体 PT_INTERP 解析）。
if(DEFINED ROOT AND NOT ROOT STREQUAL "")
    set(ROOT_LIB "${WORKDIR}/root/lib")
endif()

foreach(v ${variants})
    string(REPLACE "|" ";" fields ${v})
    list(GET fields 0 label)
    list(GET fields 1 suffix)
    list(GET fields 2 variant_env)
    list(GET fields 3 jit_env)
    list(GET fields 4 threshold_env)

    # chroot 模式跳过 host 变体（chroot 无宿主对照意义）。
    if(DEFINED ROOT AND label STREQUAL "host")
        continue()
    endif()

    set(prog "${WORKDIR}/test/${NAME}.${suffix}")

    if(variant_env STREQUAL "-")
        unset(ENV{BPF_TEST_VARIANT})
    else()
        set(ENV{BPF_TEST_VARIANT} "${variant_env}")
    endif()
    if(jit_env STREQUAL "-")
        unset(ENV{JIT_ENABLE})
    else()
        set(ENV{JIT_ENABLE} "${jit_env}")
    endif()
    if(threshold_env STREQUAL "-")
        unset(ENV{JIT_THRESHOLD})
    else()
        set(ENV{JIT_THRESHOLD} "${threshold_env}")
    endif()
    # 运行时库搜索路径（bpfvm 自身与 guest ldso 都用 LD_LIBRARY_PATH 搜库）：
    #   - root/lib：libc.so/libcxx.so（build_root.sh 复制到此，供 rootfs 与 ctest 共用）。
    #   - test：测试用 .so（如 GOT 的 libgot.so，构建产物落在 test/ 下）。
    set(ENV{LD_LIBRARY_PATH} "${WORKDIR}/root/lib:${WORKDIR}/test")

    if(label STREQUAL "host")
        # host 变体：直接运行宿主二进制，不经过 bpfvm。
        # 用 /bin/sh -c "umask 0022 && exec ..." 包装，对齐 bpfvm 启动时设置的 umask
        # （宿主 shell umask 可能不是 0022，如 0002，会导致 test_umask 误判失败）。
        execute_process(
            COMMAND /bin/sh -c "umask 0022 && exec \"$0\" \"$@\"" "${prog}"
            WORKING_DIRECTORY "${WORKDIR}"
            INPUT_FILE /dev/null
            RESULT_VARIABLE result
            OUTPUT_VARIABLE stdout
            ERROR_VARIABLE stderr
        )
    elseif(DEFINED ROOT)
        # chroot 变体：建临时 rootfs（CMAKE_PID+label 唯一，ctest 并发/同用例多变体不冲突），
        # 拷入 prog（guest 路径 = /<name>.<suffix>）与 root/lib，--root 启动。
        set(rootfs "${WORKDIR}/build/rootfs_${NAME}_${CMAKE_PID}_${label}")
        file(REMOVE_RECURSE "${rootfs}")
        file(MAKE_DIRECTORY "${rootfs}")
        file(COPY "${prog}" DESTINATION "${rootfs}")
        file(COPY "${ROOT_LIB}" DESTINATION "${rootfs}")
        execute_process(
            COMMAND "${BPFVM}" "--root" "${rootfs}" "/${NAME}.${suffix}"
            WORKING_DIRECTORY "${WORKDIR}"
            INPUT_FILE /dev/null
            RESULT_VARIABLE result
            OUTPUT_VARIABLE stdout
            ERROR_VARIABLE stderr
        )
    else()
        execute_process(
            COMMAND "${BPFVM}" "${prog}"
            WORKING_DIRECTORY "${WORKDIR}"
            INPUT_FILE /dev/null
            RESULT_VARIABLE result
            OUTPUT_VARIABLE stdout
            ERROR_VARIABLE stderr
        )
    endif()

    if(NOT result EQUAL 0)
        message("Variant '${label}' (${prog}) failed with exit ${result}:")
        message("stdout:\n${stdout}")
        message("stderr:\n${stderr}")
        message(FATAL_ERROR "${NAME} variant '${label}' exited with ${result}, expected 0")
    endif()

    # chroot 模式：清理临时 rootfs
    if(DEFINED ROOT)
        file(REMOVE_RECURSE "${rootfs}")
    endif()
endforeach()
