cmake_minimum_required(VERSION 3.15)

project(xorstr LANGUAGES CXX)

add_library(xorstr INTERFACE)
target_include_directories(xorstr INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(xorstr INTERFACE cxx_std_17)

option(XORSTR_BUILD_TESTS "Build xorstr tests" ON)

if(XORSTR_BUILD_TESTS)
    enable_testing()

    add_executable(xorstr_smoke tests/smoke.cpp)
    target_link_libraries(xorstr_smoke PRIVATE xorstr)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64|i.86|x86")
        if(MSVC)
            target_compile_options(xorstr_smoke PRIVATE /arch:AVX2)
        else()
            target_compile_options(xorstr_smoke PRIVATE -mavx2)
        endif()
    endif()

    add_test(NAME xorstr_smoke COMMAND xorstr_smoke)

    add_executable(xorstr_smoke_noavx tests/smoke.cpp)
    target_link_libraries(xorstr_smoke_noavx PRIVATE xorstr)
    target_compile_definitions(xorstr_smoke_noavx PRIVATE JM_XORSTR_DISABLE_AVX_INTRINSICS)

    add_test(NAME xorstr_smoke_noavx COMMAND xorstr_smoke_noavx)
endif()
