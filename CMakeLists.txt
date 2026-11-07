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
    src/ip.cpp
    src/routing.cpp
    src/arp.cpp
    src/link_state.cpp
    src/tcp.cpp
    src/socket.cpp
    src/netstack.cpp
)
target_include_directories(netstack PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(netstack PUBLIC pcap)
# Keep the exact language flag required by this project's conventions, but do
# not pass a C++ flag to the C checkpoint sources.
target_compile_options(netstack PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++2a>)
target_compile_options(netstack PRIVATE -Wall -Wextra -Wpedantic)

add_executable(lab1_demo src/lab1_demo.cpp)
target_link_libraries(lab1_demo PRIVATE netstack)
target_compile_options(lab1_demo PRIVATE -Wall -Wextra -Wpedantic)

add_executable(lab2_demo src/lab2_demo.cpp)
target_link_libraries(lab2_demo PRIVATE netstack)
target_compile_options(lab2_demo PRIVATE -Wall -Wextra -Wpedantic)

add_executable(lab3_router src/lab3_router.cpp)
target_link_libraries(lab3_router PRIVATE netstack)
target_compile_options(lab3_router PRIVATE -Wall -Wextra -Wpedantic)

# The checkpoint sources must stay untouched. They are linked with the
# user-space stack through the linker's --wrap mechanism.
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

foreach(checkpoint echo_client echo_server perf_client perf_server)
    add_executable(${checkpoint}
        checkpoints/${checkpoint}.c
        checkpoints/unp.c
    )
    target_link_libraries(${checkpoint} PRIVATE netstack)
    target_link_options(${checkpoint} PRIVATE ${NETSTACK_WRAP_OPTIONS})
endforeach()
