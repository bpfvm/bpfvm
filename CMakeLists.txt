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
