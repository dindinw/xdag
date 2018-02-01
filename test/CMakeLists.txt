
set(SOURCES
    ../cheatcoin/address.c
    ../cheatcoin/log.c
    test_address.c
)
set(HEADERS
    ../cheatcoin/address.h
    ../cheatcoin/log.h
)
#add_definitions(-DNDEBUG)
add_executable(test_address ${HEADERS} ${SOURCES})
