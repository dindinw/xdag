enable_language(C ASM)

set(TEST_ADDR_FILES
    ../../cheatcoin/address.c
    ../../cheatcoin/address.h
    ../../cheatcoin/log.c
    ../../cheatcoin/log.h
    test_address.c
)

add_definitions(-DNDEBUG)
add_executable(test_address ${TEST_ADDR_FILES})

