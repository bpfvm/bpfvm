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
add_executable(bpfvm main.cpp insn.cpp posix_syscall.cpp)
target_link_libraries(bpfvm ${LIBELF_LIBRARIES})


add_executable(bpfvm_test insn.cpp posix_syscall.cpp insn_test.cpp)
target_link_libraries(bpfvm_test ${LIBELF_LIBRARIES})

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

    function(add_bpf_program_test name expected_exit)
        add_test(
            NAME ${name}
            COMMAND ${CMAKE_COMMAND}
                -DBPFVM=$<TARGET_FILE:bpfvm>
                -DPROGRAM=${CMAKE_SOURCE_DIR}/test/${name}.out
                -DEXPECTED_EXIT=${expected_exit}
                -DWORKDIR=${CMAKE_SOURCE_DIR}
                -P ${CMAKE_SOURCE_DIR}/cmake/RunBpfProgram.cmake
        )
        set_tests_properties(${name} PROPERTIES
            FIXTURES_REQUIRED bpf_programs_built
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        )
    endfunction()

    file(GLOB TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/test/test_*.c")

    set(BPF_TEST_HELPERS
        test_arg
        test_cloexec_child
    )

    foreach(test_source IN LISTS TEST_SOURCES)
        get_filename_component(test_name "${test_source}" NAME_WE)

        if(test_name IN_LIST BPF_TEST_HELPERS)
            continue()
        endif()

        set(expected_exit 0)
        add_bpf_program_test(${test_name} ${expected_exit})
    endforeach()
endif()
