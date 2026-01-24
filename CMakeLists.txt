cmake_minimum_required(VERSION 3.25)
project(bpfvm)

set(CMAKE_CXX_STANDARD 20)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBELF REQUIRED libelf)

#SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
#SET(BUILD_SHARED_LIBRARIES OFF)
#SET(CMAKE_EXE_LINKER_FLAGS "-static")

include_directories(${LIBELF_INCLUDE_DIRS})
link_directories(${LIBELF_LIBRARY_DIRS})
add_executable(bpfvm main.cpp insn.cpp)
target_link_libraries(bpfvm ${LIBELF_LIBRARIES})


add_executable(bpfvm_test insn.cpp insn_test.cpp)
target_link_libraries(bpfvm_test ${LIBELF_LIBRARIES})
