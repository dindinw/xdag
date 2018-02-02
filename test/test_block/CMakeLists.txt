enable_language(C ASM)

find_package(OpenSSL REQUIRED)

include_directories(
        ${OPENSSL_INCLUDE_DIR}
)

if(APPLE)
set(ASM_FILES
    ../../cheatcoin/sha256-mb-x86_64-mac.s
    ../../cheatcoin/x86_64cpuid-mac.s)
else(UNIX)
set(ASM_FILES
    ../../cheatcoin/sha256-mb-x86_64.s
    ../../cheatcoin/x86_64cpuid.s)
endif()
MESSAGE("ASM ${ASM_FILES}")
set(SOURCES
    ../../cheatcoin/log.c
    ../../cheatcoin/log.h
    ../../cheatcoin/hash.c
    ../../cheatcoin/hash.h
    ../../cheatcoin/sha256.c
    ../../cheatcoin/sha256.h
    ${ASM_FILES}
    test_block.c
)
add_executable(test_block ${SOURCES})
target_link_libraries(test_block pthread crypto ssl)

