cmake_minimum_required(VERSION 3.16)
project(lab2_netstack LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Use the installed libpcap development package; do not submit third-party code.
find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)
if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "Install libpcap-dev, or set PCAP_INCLUDE_DIR and PCAP_LIBRARY")
endif()

add_library(netstack STATIC
    src/device.cpp
    src/packetio.cpp
    src/ip.cpp
    src/routing.cpp
    src/arp.cpp
    src/link_state.cpp
    src/netstack.cpp
)
target_include_directories(netstack PUBLIC src "${PCAP_INCLUDE_DIR}")
target_link_libraries(netstack PUBLIC "${PCAP_LIBRARY}")
target_compile_options(netstack PUBLIC -std=c++2a)
target_compile_options(netstack PRIVATE -Wall -Wextra -Wpedantic)

add_executable(lab2_demo src/lab2_demo.cpp)
target_link_libraries(lab2_demo PRIVATE netstack)
target_compile_options(lab2_demo PRIVATE -Wall -Wextra -Wpedantic)
