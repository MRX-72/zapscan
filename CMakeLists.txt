cmake_minimum_required(VERSION 3.10)
project(Zapscan VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add compiler warnings for better code quality
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Check for Nmap (Runtime dependency, but good to warn)
find_program(NMAP_EXECUTABLE nmap)
if(NOT NMAP_EXECUTABLE)
    message(WARNING "Nmap not found! Zapscan requires Nmap to function correctly.")
endif()

add_executable(zap Zapscan.cpp)

# Optimization for release builds
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

install(TARGETS zap DESTINATION bin)
