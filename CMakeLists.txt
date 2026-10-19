cmake_minimum_required(VERSION 3.16)
project(lab_netstack_premium LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build the bundled libpcap as a shared library, with its own C compiler flags.
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(BUILD_SHARED_LIBS ON)
add_subdirectory(dependencies/libpcap-1.10.7 EXCLUDE_FROM_ALL)

add_library(netstack STATIC
    src/device.cpp
    src/packetio.cpp
)
target_include_directories(netstack PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(netstack PUBLIC pcap)
# Keep the exact language flag required by this project's conventions.
target_compile_options(netstack PUBLIC -std=c++2a)
target_compile_options(netstack PRIVATE -Wall -Wextra -Wpedantic)

add_executable(lab1_demo src/lab1_demo.cpp)
target_link_libraries(lab1_demo PRIVATE netstack)
target_compile_options(lab1_demo PRIVATE -Wall -Wextra -Wpedantic)
