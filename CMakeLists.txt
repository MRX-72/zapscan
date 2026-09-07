cmake_minimum_required(VERSION 3.16)

project(zapscan VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(ZAPSCAN_BUILD_TESTS "Build the test suite" ON)
option(ZAPSCAN_ENABLE_SANITIZERS "Enable ASan/UBSan in Debug builds" OFF)

if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_library(zapscan_core
    src/target.cpp
    src/scanner.cpp
    src/report.cpp
)
target_include_directories(zapscan_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(zapscan_core PUBLIC cxx_std_17)

add_executable(zapscan
    src/main.cpp
)
target_link_libraries(zapscan PRIVATE zapscan_core)

if(ZAPSCAN_ENABLE_SANITIZERS AND NOT MSVC)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

install(TARGETS zapscan RUNTIME DESTINATION bin)
install(DIRECTORY include/zapscan DESTINATION include)

if(ZAPSCAN_BUILD_TESTS)
    enable_testing()
    add_executable(zapscan_tests
        tests/test_main.cpp
        tests/test_target.cpp
        tests/test_scanner.cpp
        tests/test_report.cpp
    )
    target_link_libraries(zapscan_tests PRIVATE zapscan_core)
    add_test(NAME zapscan_tests COMMAND zapscan_tests)
endif()