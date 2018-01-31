
set(SOURCES
	../cheatcoin/address.c
	test_address.c
)
set(HEADERS 
	../cheatcoin/address.h
)

add_executable(test_address ${HEADERS} ${SOURCES})
