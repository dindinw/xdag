#include "../cheatcoin/address.h"
#include "../cheatcoin/pool.h"
#include "../cheatcoin/log.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *g_progname;

extern void test_cheatcoin_address2hash(const char *address, cheatcoin_hash_t hash);

int main (int argc, char **argv)
{
    int n = 0;
    cheatcoin_address_init();

    // test address2hash
    cheatcoin_hash_t hash;
    test_cheatcoin_address2hash(FUND_ADDRESS,hash);
    printf("hash_llu=%llu\n",(long long )*hash);
    printf("%s\n",cheatcoin_hash2address(hash));
    test_cheatcoin_address2hash("3Bh+hU9SCFEgTpFPiS2mOfHT2IfYAwOj",hash);
    printf("%s\n",cheatcoin_hash2address(hash));
    test_cheatcoin_address2hash("egdowWJppa6uCci2Q1/PGeFWNRGu3sel",hash);
    printf("%s\n",cheatcoin_hash2address(hash));

    // test hash2address
    //24b63f11ca11f18714a6e431578773c82b5432457c9b824fae32299eff20fb19
    //f79807a264f57f42a5c7deae113556e119cf5f43b6c809aeaea56962c168077a
    //egdowWJppa6uCci2Q1/PGeFWNRGu3sel
    //c9dfe305f4c3a4cb16227769150a6eaac6fc9624e190201ead801c86f4aa8fd9


    // test debug log
    g_progname = strdup(argv[0]);
    cheatcoin_set_log_level(9);

    cheatcoin_mess("meg...");
    cheatcoin_info("info...");
    cheatcoin_debug("debug...");
    return (n == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

void test_cheatcoin_address2hash(const char *address, cheatcoin_hash_t h){
    cheatcoin_address2hash(address,h);
    printf("%016llx%016llx%016llx%016llx\n",
           (unsigned long long)h[3], (unsigned long long)h[2], (unsigned long long)h[1], (unsigned long long)h[0]);
}
