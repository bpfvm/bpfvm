# 每个用例内部串行跑 4 个变体：静态/动态 × JIT 开/关。
# 不同用例之间由 ctest -j 并发。同用例的 4 变体串行，不冲突文件。
#
# 参数：BPFVM / NAME / WORKDIR

if(NOT DEFINED BPFVM)
    message(FATAL_ERROR "BPFVM is required")
endif()
if(NOT DEFINED NAME)
    message(FATAL_ERROR "NAME is required")
endif()
if(NOT DEFINED WORKDIR)
    set(WORKDIR "${CMAKE_CURRENT_LIST_DIR}/..")
endif()

# label|program_suffix|BPF_TEST_VARIANT|JIT_ENABLE  ("-" 占位空值)
set(variants
    "static_jit|out|-|-"
    "dynamic_jit|linked|linked|-"
    "static_interp|out|-|0"
    "dynamic_interp|linked|linked|0"
)

foreach(v ${variants})
    string(REPLACE "|" ";" fields ${v})
    list(GET fields 0 label)
    list(GET fields 1 suffix)
    list(GET fields 2 variant_env)
    list(GET fields 3 jit_env)

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
    # test/ 下可能含测试用 .so（如 GOT 的 testgot.so），加入库搜索路径
    set(ENV{BPF_LIB_PATH} "${WORKDIR}/test")

    execute_process(
        COMMAND "${BPFVM}" "${prog}"
        WORKING_DIRECTORY "${WORKDIR}"
        INPUT_FILE /dev/null
        RESULT_VARIABLE result
        OUTPUT_VARIABLE stdout
        ERROR_VARIABLE stderr
    )

    if(NOT result EQUAL 0)
        message("Variant '${label}' (${prog}) failed with exit ${result}:")
        message("stdout:\n${stdout}")
        message("stderr:\n${stderr}")
        message(FATAL_ERROR "${NAME} variant '${label}' exited with ${result}, expected 0")
    endif()
endforeach()
