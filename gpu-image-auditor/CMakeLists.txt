cmake_minimum_required(VERSION 3.16)

project(gpu-image-auditor
    VERSION 0.1
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(gpu-image-auditor
    src/main.cpp
    src/checks.cpp
)

target_include_directories(gpu-image-auditor
    PRIVATE
        src
)