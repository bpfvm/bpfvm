cmake_minimum_required(VERSION 3.25)
project(bpfvm)

include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBELF REQUIRED libelf)

#SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
#SET(BUILD_SHARED_LIBRARIES OFF)
#SET(CMAKE_EXE_LINKER_FLAGS "-static")

add_compile_options(-Wall -Wextra -fPIC -fno-omit-frame-pointer)

include_directories(${LIBELF_INCLUDE_DIRS})
link_directories(${LIBELF_LIBRARY_DIRS})

add_subdirectory(src)

# src/CMakeLists.txt 与 src/posix/CMakeLists.txt 各自 PARENT_SCOPE 导出本目录维护的
# 源文件列表（相对 ${CMAKE_SOURCE_DIR} 的相对路径）。这里转发给 nesting 子项目，
# 这样新增/删除 .cpp 仍只改对应目录的 CMakeLists.txt 一处，nesting 自动跟着变。
# ExternalProject 用 ";"作为 list 分隔符，会拆 -D 的值，所以先换成 "|"（LIST_SEPARATOR
# 在子项目侧会自动还原回 ";"）。
string(REPLACE ";" "|" _lib_sources_arg    "${BPFVM_LIB_SOURCES}")
string(REPLACE ";" "|" _main_source_arg    "${BPFVM_MAIN_SOURCE}")
string(REPLACE ";" "|" _posix_sources_arg  "${BPFVM_POSIX_SOURCES}")

# ---------------------------------------------------------------------------
# bpfvm.bpf：把 bpfvm 自身 C++ 源码交叉编译成 BPF ELF（BPF-on-BPF 三层嵌套中间层）。
# 用 toolchain file + ExternalProject_Add 把 nesting/
# 当独立交叉编译子项目（nesting/CMakeLists.txt 是普通 CMake；源列表只在那里写一次，
# 加 .cpp 只改一处）。toolchain file（cmake/bpfvm-bpf-toolchain.cmake）集中所有 BPF 编译/
# 链接配置。
#
# configure 期检测依赖（clang++ + libc++ 头 + root/lib 动态库）。工作流：
#   1. 首次 cmake+make 建 host 工具链（bpfvm/bpfvm-ld/4 个 pass .so）
#   2. ./scripts/build_root.sh 产出 root/lib/{libc.so,libcxx.so}
#   3. 重新 cmake+make → 自动构建 build/bpfvm.bpf
# 依赖缺失则跳过（不报错）。
option(BPFVM_BUILD_BPF "Build bpfvm.bpf (BPF-on-BPF self-host) when deps are met" ON)
if(BPFVM_BUILD_BPF)
    find_program(BPFVM_CLANGXX_BIN clang++)
    find_program(BPFVM_CLANG_BIN  clang)
    set(_bpf_on ON)
    set(_bpf_reason "")

    if(NOT BPFVM_CLANGXX_BIN)
        set(_bpf_on OFF)
        set(_bpf_reason "clang++ not in PATH")
    elseif(NOT BPFVM_CLANG_BIN)
        set(_bpf_on OFF)
        set(_bpf_reason "clang not in PATH")
    endif()

    # libc++ 头 + clang resource include（与 scripts/build_libcxx.sh 同逻辑：
    # clang resource dir 上溯三级 + include/c++/v1；找不到再扫 /usr/lib/llvm-*）。
    if(_bpf_on)
        execute_process(COMMAND ${BPFVM_CLANGXX_BIN} -print-resource-dir
                        OUTPUT_VARIABLE _bpf_clang_res OUTPUT_STRIP_TRAILING_WHITESPACE)
        get_filename_component(_bpf_llvm_root "${_bpf_clang_res}/../../.." ABSOLUTE)
        set(_bpf_libcxx_inc "${_bpf_llvm_root}/include/c++/v1")
        if(NOT EXISTS "${_bpf_libcxx_inc}/vector")
            file(GLOB _bpf_cand LIST_DIRECTORIES true "/usr/lib/llvm-*/include/c++/v1")
            list(SORT _bpf_cand)
            list(REVERSE _bpf_cand)
            foreach(_p IN LISTS _bpf_cand)
                if(EXISTS "${_p}/vector")
                    set(_bpf_libcxx_inc "${_p}")
                    break()
                endif()
            endforeach()
            if(NOT EXISTS "${_bpf_libcxx_inc}/vector")
                set(_bpf_on OFF)
                set(_bpf_reason "libc++ headers (include/c++/v1) not found")
            endif()
        endif()
    endif()

    # root/lib 动态库（由 scripts/build_root.sh 产出，不在 CMake 内构建）。
    if(_bpf_on)
        foreach(_lib root/lib/libc.so root/lib/libcxx.so)
            if(NOT EXISTS "${CMAKE_SOURCE_DIR}/${_lib}")
                set(_bpf_on OFF)
                set(_bpf_reason "missing ${_lib} (run ./scripts/build_root.sh first)")
                break()
            endif()
        endforeach()
    endif()

    if(_bpf_on)
        include(ExternalProject)
        ExternalProject_Add(bpfvm_bpf
            # 子项目本身默认就是 ALL，会随 make all 自动构建。
            SOURCE_DIR       ${CMAKE_SOURCE_DIR}/nesting
            BINARY_DIR       ${CMAKE_BINARY_DIR}/bpfvm_bpf
            CMAKE_GENERATOR  ${CMAKE_GENERATOR}
            CMAKE_ARGS
                -DCMAKE_TOOLCHAIN_FILE=${CMAKE_SOURCE_DIR}/cmake/bpfvm-bpf-toolchain.cmake
                -DCMAKE_BUILD_TYPE=Release
                # 子项目和 toolchain 需要的路径变量（生成器表达式在 build 期展开，
                # 拿到本次构建的真实产物路径，不依赖 build/ 硬编码）。
                -DBPFVM_ROOT=${CMAKE_SOURCE_DIR}
                -DBPFVM_CLANG=${BPFVM_CLANG_BIN}
                -DBPFVM_CLANGXX=${BPFVM_CLANGXX_BIN}
                -DBPFVM_LIBCXX_INC=${_bpf_libcxx_inc}
                -DBPFVM_CLANG_RES_INC=${_bpf_clang_res}/include
                -DBPFVM_BPFVM_LD=$<TARGET_FILE:bpfvm-ld>
                -DBPFVM_PASS_WIDEARGS=$<TARGET_FILE:BpfWideArgs>
                -DBPFVM_PASS_SOFTFP=$<TARGET_FILE:BpfSoftFp>
                -DBPFVM_PASS_LIBCALLLOWER=$<TARGET_FILE:BpfLibcallLower>
                -DBPFVM_PASS_EMUTLS=$<TARGET_FILE:BpfEmutls>
                # 源文件列表由 src/CMakeLists.txt 与 src/posix/CMakeLists.txt 导出
                # （相对 ${CMAKE_SOURCE_DIR} 的相对路径，子项目里拼上 ${BPFVM_ROOT}/ 前缀）。
                # 走 ExternalProject 的 LIST_SEPARATOR：值里 ";" 换成 "|" 传入，子项目
                # 收到的变量里 "|" 会被还原回 ";"，可直接当 CMake list 用。
                -DBPFVM_LIB_SOURCES=${_lib_sources_arg}
                -DBPFVM_MAIN_SOURCE=${_main_source_arg}
                -DBPFVM_POSIX_SOURCES=${_posix_sources_arg}
            LIST_SEPARATOR "|"
            BUILD_BYPRODUCTS ${CMAKE_BINARY_DIR}/bpfvm_bpf/bpfvm.bpf
            # BUILD_ALWAYS 1：每次 make 都重跑子项目的 build step（子构建内部 make 自己
            # 做增量判断，touch 源文件只重编对应 .o + 重链）。不加这个的话 ExternalProject
            # 用 stamp 判断，不会感知 SOURCE_DIR 里源文件的变化。
            BUILD_ALWAYS     1
            # 先编 host 工具链（bpfvm-ld + 4 个 pass .so）再 configure 子项目。
            DEPENDS          bpfvm-ld BpfWideArgs BpfSoftFp BpfLibcallLower BpfEmutls
            # 子项目产物拷到顶层 build/bpfvm.bpf。
            INSTALL_COMMAND  ${CMAKE_COMMAND} -E copy
                             ${CMAKE_BINARY_DIR}/bpfvm_bpf/bpfvm.bpf
                             ${CMAKE_BINARY_DIR}/bpfvm.bpf)
        message(STATUS "bpfvm_bpf: enabled  -> ${CMAKE_BINARY_DIR}/bpfvm.bpf (libc++ headers: ${_bpf_libcxx_inc})")
    else()
        message(STATUS "bpfvm_bpf: disabled (${_bpf_reason})")
    endif()
endif()

if(BUILD_TESTING)
    add_test(NAME unit_tests COMMAND bpfvm_test)

    add_test(
        NAME bpf_programs_build
        COMMAND ${CMAKE_MAKE_PROGRAM} -C ${CMAKE_SOURCE_DIR}/test
    )
    set_tests_properties(bpf_programs_build PROPERTIES
        FIXTURES_SETUP bpf_programs_built
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )

    # 每个用例一个 ctest 条目，内部串行跑 4 变体（静态/动态 × JIT 开/关）。
    # 不同用例之间由 ctest -j 并发；同用例变体串行，不冲突文件。
    # ROOT 参数非空时走 chroot 模式（建临时 rootfs + --root 启动 + marker 落位校验）。
    function(add_bpf_program_test name)
        set(extra_args)
        if(name IN_LIST BPF_ROOT_TESTS)
            list(APPEND extra_args -DROOT=1)
        endif()
        add_test(NAME ${name}
            COMMAND ${CMAKE_COMMAND}
                -DBPFVM=$<TARGET_FILE:bpfvm>
                -DNAME=${name}
                -DWORKDIR=${CMAKE_SOURCE_DIR}
                ${extra_args}
                -P ${CMAKE_SOURCE_DIR}/cmake/RunBpfProgram.cmake)
        set_tests_properties(${name} PROPERTIES
            FIXTURES_REQUIRED bpf_programs_built
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            TIMEOUT 300
        )
    endfunction()

    file(GLOB TEST_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_SOURCE_DIR}/test/test_*.c"
        "${CMAKE_SOURCE_DIR}/test/test_*.cpp")

    # 不自动注册为独立测试的辅助程序（被其他测试调用）。
    set(BPF_TEST_HELPERS
        test_arg
        test_cloexec_child
    )

    # 辅助程序里需要 --root chroot 隔离跑的：用标准 runner 的 ROOT 模式注册
    # （建临时 rootfs + --root 启动 + 校验写操作落在 rootfs 内）。
    set(BPF_ROOT_TESTS
        test_root
    )

    foreach(test_source IN LISTS TEST_SOURCES)
        get_filename_component(test_name "${test_source}" NAME_WE)

        # ROOT 测试虽在 helpers，但单独注册（带 ROOT=1）。
        if(test_name IN_LIST BPF_TEST_HELPERS)
            continue()
        endif()

        add_bpf_program_test(${test_name})
    endforeach()
endif()
