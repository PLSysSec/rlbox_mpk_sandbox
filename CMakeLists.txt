cmake_minimum_required(VERSION 3.13)

project(rlbox_mpk
        VERSION 0.1
        DESCRIPTION "RLBox integration with MPK")

# Project Settings ###################

# set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
SET(ASM_OPTIONS "-x assembler-with-cpp")
enable_language(C CXX ASM)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")

option(DEV "Use settings suitable for dev contributions to rlbox" OFF)

file(GLOB_RECURSE
     ALL_CXX_SOURCE_FILES
     ${CMAKE_SOURCE_DIR}/include/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/include/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/include/*.cc
     ${CMAKE_SOURCE_DIR}/include/*.hh
     ${CMAKE_SOURCE_DIR}/include/*.ii
     ${CMAKE_SOURCE_DIR}/include/*.[CHI]
     ${CMAKE_SOURCE_DIR}/test/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/test/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/test/*.cc
     ${CMAKE_SOURCE_DIR}/test/*.hh
     ${CMAKE_SOURCE_DIR}/test/*.ii
     ${CMAKE_SOURCE_DIR}/test/*.[CHI]
     ${CMAKE_SOURCE_DIR}/c_src/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/c_src/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/c_src/*.cc
     ${CMAKE_SOURCE_DIR}/c_src/*.hh
     ${CMAKE_SOURCE_DIR}/c_src/*.ii
     ${CMAKE_SOURCE_DIR}/c_src/*.[CHI])

# Dev Tools ###################

if(DEV)
  if(MSVC)
    add_compile_options(/W4) # warnings
    add_compile_options(/WX) # warnings as errors
  else()
    add_compile_options(-Wall -Wextra -pedantic) # warnings
    add_compile_options(-Werror) # warnings as errors
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
  endif()

  find_program(CLANG_TIDY "clang-tidy")
  if(CLANG_TIDY)
    # Config in .clang-tidy
    set(CMAKE_CXX_CLANG_TIDY clang-tidy)
  endif()

  find_program(CLANG_FORMAT "clang-format")
  if(CLANG_FORMAT)
    # Config in .clang-format
    add_custom_target(format-source
                      COMMAND clang-format
                              -i
                              -style=file
                              ${ALL_CXX_SOURCE_FILES})
  endif()

endif()

# Dependencies ###################

include(FetchContent)

FetchContent_Declare(
  rlbox
  GIT_REPOSITORY https://github.com/PLSysSec/rlbox_api_cpp17.git
  GIT_TAG origin/gettimeofday)
FetchContent_GetProperties(rlbox)
if(NOT rlbox_POPULATED)
  FetchContent_Populate(rlbox)
endif()

FetchContent_Declare(catch2
                     GIT_REPOSITORY https://github.com/catchorg/Catch2.git
                     GIT_TAG v2.9.1)
FetchContent_GetProperties(catch2)
if(NOT catch2_POPULATED)
  FetchContent_Populate(catch2)
endif()

add_subdirectory("${catch2_SOURCE_DIR}")
list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/contrib")

set (zerocost_heavy_trampoline_SOURCE_DIR "${CMAKE_SOURCE_DIR}/../zerocost_heavy_trampoline")

# Lib ###################

add_library(rlbox_glue_lib_static STATIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib/libtest.c)
target_include_directories(rlbox_glue_lib_static
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib)

add_library(rlbox_glue_lib_shared SHARED ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib/libtest.c)
target_include_directories(rlbox_glue_lib_shared
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib)

add_library(rlbox_glue_lib_static_32 STATIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib/libtest.c)
target_include_directories(rlbox_glue_lib_static
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib)
target_compile_options(rlbox_glue_lib_static_32 PUBLIC "-m32")
target_link_options(rlbox_glue_lib_static_32 PUBLIC "-m32")

add_library(rlbox_glue_lib_shared_32 SHARED ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib/libtest.c)
target_include_directories(rlbox_glue_lib_shared
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib)
target_compile_options(rlbox_glue_lib_shared_32 PUBLIC "-m32")
target_link_options(rlbox_glue_lib_shared_32 PUBLIC "-m32")

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(DYLIB_EXT "dylib")
else()
  set(DYLIB_EXT "so")
endif()
set(GLUE_LIB_SO "${CMAKE_BINARY_DIR}/librlbox_glue_lib_shared.${DYLIB_EXT}")
set(GLUE_LIB_SO_32 "${CMAKE_BINARY_DIR}/librlbox_glue_lib_shared_32.${DYLIB_EXT}")

# Tests ###################

find_package(Threads REQUIRED)

include(CTest)
include(Catch)

add_executable(test_rlbox_glue test/test_mpk_sandbox_glue_main.cpp
                               test/test_mpk_sandbox_glue.cpp
                               ${zerocost_heavy_trampoline_SOURCE_DIR}/c_src/trampoline_src.cpp
                               ${zerocost_heavy_trampoline_SOURCE_DIR}/c_src/trampoline_asm_64.S
                               )
target_include_directories(test_rlbox_glue PUBLIC include)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/include)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib)
target_include_directories(test_rlbox_glue
                           PUBLIC ${zerocost_heavy_trampoline_SOURCE_DIR}/include)
target_compile_definitions(test_rlbox_glue PUBLIC
                           GLUE_LIB_PATH="${GLUE_LIB_SO}")

add_dependencies(test_rlbox_glue rlbox_glue_lib_shared)

target_link_libraries(test_rlbox_glue
                      Catch2::Catch2
                      ${CMAKE_THREAD_LIBS_INIT}
                      ${CMAKE_DL_LIBS}
                      )

if(UNIX AND NOT (${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  target_link_libraries(test_rlbox_glue rt)
endif()

catch_discover_tests(test_rlbox_glue)

####################################

add_executable(test_rlbox_glue_32 test/test_mpk_sandbox_glue_main.cpp
                               test/test_mpk_sandbox_glue.cpp
                               ${zerocost_heavy_trampoline_SOURCE_DIR}/c_src/trampoline_src.cpp
                               ${zerocost_heavy_trampoline_SOURCE_DIR}/c_src/trampoline_asm_32.S
                               )
target_compile_options(test_rlbox_glue_32 PUBLIC "-m32")
target_link_options(test_rlbox_glue_32 PUBLIC "-m32")
target_include_directories(test_rlbox_glue_32 PUBLIC include)
target_include_directories(test_rlbox_glue_32
                           PUBLIC ${rlbox_SOURCE_DIR}/code/include)
target_include_directories(test_rlbox_glue_32
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue)
target_include_directories(test_rlbox_glue_32
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib)
target_include_directories(test_rlbox_glue_32
                           PUBLIC ${zerocost_heavy_trampoline_SOURCE_DIR}/include)
target_compile_definitions(test_rlbox_glue_32 PUBLIC
                           GLUE_LIB_PATH="${GLUE_LIB_SO_32}")

add_dependencies(test_rlbox_glue_32 rlbox_glue_lib_shared_32)

target_link_libraries(test_rlbox_glue_32
                      Catch2::Catch2
                      ${CMAKE_THREAD_LIBS_INIT}
                      ${CMAKE_DL_LIBS}
                      )

if(UNIX AND NOT (${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  target_link_libraries(test_rlbox_glue_32 rt)
endif()

catch_discover_tests(test_rlbox_glue_32)

# Shortcuts ###################

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} -V)
add_dependencies(check test_rlbox_glue test_rlbox_glue_32)

