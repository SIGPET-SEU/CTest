cmake_minimum_required(VERSION 3.28)
project(Libgcrypt C)

set(CMAKE_C_STANDARD 11)

# Add this for direct references to header files
# e.g., #include "ws_regex.h"
include_directories("${PROJECT_SOURCE_DIR}/src")

add_subdirectory("${PROJECT_SOURCE_DIR}/tests")
add_subdirectory("${PROJECT_SOURCE_DIR}/src")