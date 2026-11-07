cmake_minimum_required(VERSION 3.16)
project(lab3_netstack LANGUAGES C CXX)

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
    src/ipfrag.cpp
    src/routing.cpp
    src/arp.cpp
    src/link_state.cpp
    src/egress.cpp
    src/tcp.cpp
    src/socket.cpp
    src/netstack.cpp
)
target_include_directories(netstack PUBLIC src "${PCAP_INCLUDE_DIR}")
target_link_libraries(netstack PUBLIC "${PCAP_LIBRARY}")
target_compile_options(netstack PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++2a>)
target_compile_options(netstack PRIVATE -Wall -Wextra -Wpedantic)

add_executable(lab3_router src/lab3_router.cpp)
target_link_libraries(lab3_router PRIVATE netstack)
target_compile_options(lab3_router PRIVATE -Wall -Wextra -Wpedantic)

set(NETSTACK_WRAP_OPTIONS
    -Wl,--wrap=socket
    -Wl,--wrap=bind
    -Wl,--wrap=listen
    -Wl,--wrap=connect
    -Wl,--wrap=accept
    -Wl,--wrap=read
    -Wl,--wrap=write
    -Wl,--wrap=close
    -Wl,--wrap=getaddrinfo
    -Wl,--wrap=send
    -Wl,--wrap=recv
    -Wl,--wrap=sendto
    -Wl,--wrap=recvfrom
)

add_executable(tcp_tool src/evaluate/tcp_tool.cpp)
target_link_libraries(tcp_tool PRIVATE netstack)
target_link_options(tcp_tool PRIVATE ${NETSTACK_WRAP_OPTIONS})
target_compile_options(tcp_tool PRIVATE -Wall -Wextra -Wpedantic)

add_executable(ip_tool src/evaluate/ip_tool.cpp)
target_link_libraries(ip_tool PRIVATE netstack)
target_compile_options(ip_tool PRIVATE -Wall -Wextra -Wpedantic)

add_executable(http_origin src/evaluate/http_origin.cpp)
target_link_libraries(http_origin PRIVATE netstack)
target_link_options(http_origin PRIVATE ${NETSTACK_WRAP_OPTIONS})
target_compile_options(http_origin PRIVATE -Wall -Wextra -Wpedantic)

add_executable(http_proxy src/http_proxy.cpp)
target_link_libraries(http_proxy PRIVATE netstack)
target_link_options(http_proxy PRIVATE ${NETSTACK_WRAP_OPTIONS})
target_compile_options(http_proxy PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()
add_executable(unit_tests src/evaluate/unit_tests.cpp)
target_link_libraries(unit_tests PRIVATE netstack)
target_link_options(unit_tests PRIVATE ${NETSTACK_WRAP_OPTIONS})
target_compile_options(unit_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME unit_tests COMMAND unit_tests)
