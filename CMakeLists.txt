cmake_minimum_required(VERSION 3.7)
project(daggercoin) 
enable_language(C ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-std=gnu11 -O3 -g -Wall -Wmissing-prototypes -Wno-unused-result")

add_subdirectory(test)

set(OPENSSL_ROOT_DIR "/opt/openssl/")
find_package(OpenSSL REQUIRED)

include_directories(
   ${OPENSSL_INCLUDE_DIR}
)

set(DAGGER_SOURCES
    cheatcoin/address.c
    cheatcoin/block.c
    cheatcoin/crypt.c
    cheatcoin/hash.c
    cheatcoin/log.c
    cheatcoin/main.c
    cheatcoin/memory.c
    cheatcoin/netdb.c
    cheatcoin/pool.c
    cheatcoin/sha256.c
    cheatcoin/storage.c
    cheatcoin/sync.c
    cheatcoin/transport.c
    cheatcoin/wallet.c
    dnet/dnet_crypt.c
    dnet/dnet_database.c
    dnet/dnet_main.c
    dnet/dnet_threads.c
    dnet/dnet_connection.c
    dnet/dnet_stream.c
    dnet/dnet_packet.c
    dnet/dnet_command.c
    dnet/dnet_log.c
    dnet/dnet_files.c
    dnet/dnet_tap.c
    dus/programs/dfstools/source/dfslib/dfslib_crypt.c
    dus/programs/dfstools/source/dfslib/dfslib_random.c
    dus/programs/dfstools/source/dfslib/dfslib_string.c
    dus/programs/dfstools/source/lib/dfsrsa.c
    dus/programs/dar/source/lib/crc_c.c
)

set(DAGGER_HEADERS
    cheatcoin/address.h
    cheatcoin/block.h
    cheatcoin/crypt.h
    cheatcoin/hash.h
    cheatcoin/log.h
    cheatcoin/main.h
    cheatcoin/memory.h
    cheatcoin/netdb.h
    cheatcoin/pool.h
    cheatcoin/sha256.h
    cheatcoin/state.h
    cheatcoin/storage.h
    cheatcoin/sync.h
    cheatcoin/transport.h
    cheatcoin/wallet.h
    dnet/dnet_crypt.h
    dnet/dnet_database.h
    dnet/dnet_history.h
    dnet/dnet_threads.h
    dnet/dnet_connection.h
    dnet/dnet_stream.h
    dnet/dnet_packet.h
    dnet/dnet_command.h
    dnet/dnet_log.h
    dnet/dnet_files.h
    dnet/dnet_tap.h
    dnet/dthread.h
    dus/programs/dfstools/source/dfslib/dfslib_crypt.h
    dus/programs/dfstools/source/dfslib/dfslib_random.h
    dus/programs/dfstools/source/dfslib/dfslib_string.h
    dus/programs/dfstools/source/dfslib/dfslib_types.h
    dus/programs/dfstools/source/include/dfsrsa.h
    dus/programs/dar/source/include/crc.h
    ldus/source/include/ldus/atomic.h
    ldus/source/include/ldus/list.h
    ldus/source/include/ldus/rbtree.h
)

set(SHA256_LINUX_ASM_SOURCES
    cheatcoin/sha256-mb-x86_64.s
    cheatcoin/x86_64cpuid.s
)

set(SHA256_MAC_ASM_SOURCES
    cheatcoin/sha256-mb-x86_64-mac.s
    cheatcoin/x86_64cpuid-mac.s
)

OPTION(DEBUG
    "Build the project using debugging code"
    OFF)
if(DEBUG)
    MESSAGE("Adding Debug flag...")
    SET(CMAKE_BUILD_TYPE Debug)
    MESSAGE("Build type is " ${CMAKE_BUILD_TYPE})
else()
    add_definitions(-DNDEBUG)
endif(DEBUG)

add_definitions(-DDFSTOOLS)
add_definitions(-DCHEATCOIN)
add_definitions(-DSHA256_USE_OPENSSL_TXFM)
add_definitions(-DSHA256_OPENSSL_MBLOCK)

if(APPLE)
add_executable(
   ${PROJECT_NAME}
   ${DAGGER_HEADERS}
   ${DAGGER_SOURCES}
   ${SHA256_MAC_ASM_SOURCES}
)
else(UNIX)
add_executable(
   ${PROJECT_NAME}
   ${DAGGER_HEADERS}
   ${DAGGER_SOURCES}
   ${SHA256_LINUX_ASM_SOURCES}
)
endif()

target_link_libraries(${PROJECT_NAME} m pthread crypto ssl) 

add_executable(
   cgi_stats
   cheatcoin/statsdaemon.c
)
add_executable(
   cgi_block
   cheatcoin/block.cgi.c
)
