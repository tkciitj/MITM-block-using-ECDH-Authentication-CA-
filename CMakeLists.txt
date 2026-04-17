cmake_minimum_required(VERSION 3.15)
project(ECDH_MITM VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(OpenSSL REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/src)

# ── Data directory ─────────────────────────────────────────────────────────────
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/data)

# ── Shared core library ────────────────────────────────────────────────────────
add_library(ecdh_core STATIC
    src/crypto/ecc_math.cpp
    src/crypto/ecdh_core.cpp
    src/crypto/aes_gcm.cpp
    src/crypto/cert_auth.cpp
    src/protocol/tcp_channel.cpp
    src/protocol/handshake.cpp
    src/protocol/messenger.cpp
    src/ui/terminal.cpp
)

target_link_libraries(ecdh_core OpenSSL::Crypto OpenSSL::SSL)

if(WIN32)
    target_link_libraries(ecdh_core ws2_32 crypt32)
endif()

if(THREADS_PREFER_PTHREAD_FLAG)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

find_package(Threads REQUIRED)
target_link_libraries(ecdh_core Threads::Threads)

# ── Three executables ──────────────────────────────────────────────────────────
foreach(target alice bob oscar)
    add_executable(${target} src/${target}.cpp)
    target_link_libraries(${target} ecdh_core OpenSSL::Crypto OpenSSL::SSL Threads::Threads)
    if(WIN32)
        target_link_libraries(${target} ws2_32 crypt32)
    endif()
endforeach()

if(MSVC)
    target_compile_options(ecdh_core PRIVATE /W3)
else()
    target_compile_options(ecdh_core PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

# DATA_DIR points to <project root>/data/ so cert files persist across builds
set(DATA_DIR_PATH "${CMAKE_SOURCE_DIR}/data")
target_compile_definitions(ecdh_core PUBLIC DATA_DIR="${DATA_DIR_PATH}")
target_compile_definitions(alice     PUBLIC DATA_DIR="${DATA_DIR_PATH}")
target_compile_definitions(bob       PUBLIC DATA_DIR="${DATA_DIR_PATH}")
target_compile_definitions(oscar     PUBLIC DATA_DIR="${DATA_DIR_PATH}")

message(STATUS "")
message(STATUS "╔══════════════════════════════════════════╗")
message(STATUS "║  ECDH-MITM Demo — Build Configured       ║")
message(STATUS "╠══════════════════════════════════════════╣")
message(STATUS "║  OpenSSL version : ${OPENSSL_VERSION}")
message(STATUS "║  Output dir      : ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "║  Data dir        : ${DATA_DIR_PATH}")
message(STATUS "╚══════════════════════════════════════════╝")
message(STATUS "")
message(STATUS "  Run: cmake --build build && cd build && bash ../scripts/demo.sh")
message(STATUS "")
