#include "../../cheatcoin/log.h"
#include "../../cheatcoin/hash.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <pthread.h>

#define CHEATCOIN_MAIN_ERA	0x16940000000ll

#define bufsize (0x100000 / sizeof(struct cheatcoin_block))

#define SLASH "/"
#define STORAGE_DIR0			"storage%s"
#define STORAGE_DIR0_ARGS(t)	("")
#define STORAGE_DIR1			STORAGE_DIR0 SLASH "%02x"
#define STORAGE_DIR1_ARGS(t)	STORAGE_DIR0_ARGS(t), (int)((t) >> 40)
#define STORAGE_DIR2			STORAGE_DIR1 SLASH "%02x"
#define STORAGE_DIR2_ARGS(t)	STORAGE_DIR1_ARGS(t), (int)((t) >> 32) & 0xff
#define STORAGE_DIR3			STORAGE_DIR2 SLASH "%02x"
#define STORAGE_DIR3_ARGS(t)	STORAGE_DIR2_ARGS(t), (int)((t) >> 24) & 0xff
#define STORAGE_FILE			STORAGE_DIR3 SLASH "%02x.dat"
#define STORAGE_FILE_ARGS(t)	STORAGE_DIR3_ARGS(t), (int)((t) >> 16) & 0xff
#define SUMS_FILE				"sums.dat"

#define cheatcoin_type(b, n) ((b)->field[0].type >> ((n) << 2) & 0xf)

static pthread_mutex_t storage_mutex = PTHREAD_MUTEX_INITIALIZER;

enum cheatcoin_field_type {
    CHEATCOIN_FIELD_NONCE,
    CHEATCOIN_FIELD_HEAD,
    CHEATCOIN_FIELD_IN,
    CHEATCOIN_FIELD_OUT,
    CHEATCOIN_FIELD_SIGN_IN,
    CHEATCOIN_FIELD_SIGN_OUT,
    CHEATCOIN_FIELD_PUBLIC_KEY_0,
    CHEATCOIN_FIELD_PUBLIC_KEY_1,
};

struct cheatcoin_storage_sum {
    uint64_t sum;
    uint64_t size;
};

char *g_progname;

typedef uint64_t cheatcoin_time_t;
typedef uint64_t cheatcoin_amount_t;
typedef uint64_t cheatcoin_hash_t[4];
typedef uint64_t cheatcoin_hashlow_t[3];
#define CHEATCOIN_BLOCK_FIELDS 16

struct cheatcoin_field {
    union {
        struct {
            union {
                struct {
                    uint64_t transport_header;
                    uint64_t type;
                    cheatcoin_time_t time;
                };
                cheatcoin_hashlow_t hash;
            };
            union {
                cheatcoin_amount_t amount;
                cheatcoin_time_t end_time;
            };
        };
        cheatcoin_hash_t data;
    };
};

struct cheatcoin_block {
    struct cheatcoin_field field[CHEATCOIN_BLOCK_FIELDS];
};

cheatcoin_time_t st = CHEATCOIN_MAIN_ERA;
cheatcoin_time_t et ;




static int sort_callback(const void *l, const void *r) {
    struct cheatcoin_block **L = (struct cheatcoin_block **)l, **R = (struct cheatcoin_block **)r;
    if ((*L)->field[0].time < (*R)->field[0].time) return -1;
    if ((*L)->field[0].time > (*R)->field[0].time) return 1;
    return 0;
}

static uint64_t get_timestamp(void) {
    struct timeval tp;
    gettimeofday(&tp, 0);
    return (uint64_t)(unsigned long)tp.tv_sec << 10 | ((tp.tv_usec << 10) / 1000000);
}

static int correct_storage_sum(const char *path, int pos, const struct cheatcoin_storage_sum *sum, int add) {
    struct cheatcoin_storage_sum sums[256];
    FILE *f = fopen(path, "r+b");
    if (f) {
        if (fread(sums, sizeof(struct cheatcoin_storage_sum), 256, f) != 256)
        { fclose(f); cheatcoin_err("Storag: sums file %s corrupted", path); return -1; }
        rewind(f);
    } else {
        f = fopen(path, "wb");
        if (!f) { cheatcoin_err("Storag: can't create file %s", path); return -1; }
        memset(sums, 0, sizeof(sums));
    }
    if (!add) {
        if (sums[pos].size == sum->size && sums[pos].sum == sum->sum) { fclose(f); return 0; }
        if (sums[pos].size || sums[pos].sum) {
            sums[pos].size = sums[pos].sum = 0;
            cheatcoin_err("Storag: corrupted, sums file %s, pos %x", path, pos);
        }
    }
    sums[pos].size += sum->size;
    sums[pos].sum  += sum->sum;
    if (fwrite(sums, sizeof(struct cheatcoin_storage_sum), 256, f) != 256)
    { fclose(f); cheatcoin_err("Storag: can't write file %s", path); return -1; }
    fclose(f);
    return 1;
}
static int correct_storage_sums(cheatcoin_time_t t, const struct cheatcoin_storage_sum *sum, int add) {
    char path[256];
    int res;
    sprintf(path, STORAGE_DIR3 SLASH SUMS_FILE, STORAGE_DIR3_ARGS(t));
    res = correct_storage_sum(path, (t >> 16) & 0xff, sum, add);
    if (res <= 0) return res;
    sprintf(path, STORAGE_DIR2 SLASH SUMS_FILE, STORAGE_DIR2_ARGS(t));
    res = correct_storage_sum(path, (t >> 24) & 0xff, sum, 1);
    if (res <= 0) return res;
    sprintf(path, STORAGE_DIR1 SLASH SUMS_FILE, STORAGE_DIR1_ARGS(t));
    res = correct_storage_sum(path, (t >> 32) & 0xff, sum, 1);
    if (res <= 0) return res;
    sprintf(path, STORAGE_DIR0 SLASH SUMS_FILE, STORAGE_DIR0_ARGS(t));
    res = correct_storage_sum(path, (t >> 40) & 0xff, sum, 1);
    if (res <= 0) return res;
    return 0;
}

uint64_t cheatcoin_load_blocks(cheatcoin_time_t start_time, cheatcoin_time_t end_time, void *data, void *(*callback)(void *, void *)) {
    struct cheatcoin_block buf[bufsize], *pbuf[bufsize];
    struct cheatcoin_storage_sum s;
    char path[256];
    struct stat st;
    FILE *f;
    uint64_t sum = 0, pos = 0, pos0, mask;
    int64_t i, j, k, todo;
    s.size = s.sum = 0;
    while (start_time < end_time) {
        sprintf(path, STORAGE_FILE, STORAGE_FILE_ARGS(start_time));
        pthread_mutex_lock(&storage_mutex);
        //printf("st=%lld,ed=%lld,path=%s\n",start_time,end_time,path);
        f = fopen(path, "rb");
        if (f) {
            printf("=======================================================================================\n");
            printf(">>> open file : %s\n",path);
            if (fseek(f, pos, SEEK_SET) < 0) todo = 0;
            else todo = fread(buf, sizeof(struct cheatcoin_block), bufsize, f);
            fclose(f);
        } else todo = 0;
        pthread_mutex_unlock(&storage_mutex);
        pos0 = pos;
        for (i = k = 0; i < todo; ++i, pos += sizeof(struct cheatcoin_block)) {
            if (buf[i].field[0].time >= start_time && buf[i].field[0].time < end_time) {
                s.size += sizeof(struct cheatcoin_block);
                for (j = 0; j < sizeof(struct cheatcoin_block) / sizeof(uint64_t); ++j)
                    s.sum += ((uint64_t *)(buf + i))[j];
                pbuf[k++] = buf + i;
            }
            printf("load : %s \n",path);
        }
        if (k) qsort(pbuf, k, sizeof(struct cheatcoin_block *), sort_callback);
        for (i = 0; i < k; ++i) {
            pbuf[i]->field[0].transport_header = pos0 + ((uint8_t *)pbuf[i] - (uint8_t *)buf);
            printf("callback -> %d -> %d -> %d\n",i,pbuf[i],data);
            if (callback(pbuf[i], data)) return sum;
            sum++;
        }
        if (todo != bufsize) {
            if (f) {
                int res;
                pthread_mutex_lock(&storage_mutex);
                res = correct_storage_sums(start_time, &s, 0);
                pthread_mutex_unlock(&storage_mutex);
                if (res) break;
                s.size = s.sum = 0;
                mask = (1l << 16) - 1;
            }
            else if (sprintf(path, STORAGE_DIR3, STORAGE_DIR3_ARGS(start_time)), !stat(path, &st)) mask = (1l << 16) - 1;
            else if (sprintf(path, STORAGE_DIR2, STORAGE_DIR2_ARGS(start_time)), !stat(path, &st)) mask = (1l << 24) - 1;
            else if (sprintf(path, STORAGE_DIR1, STORAGE_DIR1_ARGS(start_time)), !stat(path, &st)) mask = (1ll << 32) - 1;
            else mask = (1ll << 40) - 1;
            start_time |= mask;
            start_time++;
            pos = 0;
        }
    }
    return sum;
}

static void printf_type(int type){
    char type_name[256];
    switch(type){
        case CHEATCOIN_FIELD_NONCE:         sprintf(type_name, "CHEATCOIN_FIELD_NONCE");        break;
        case CHEATCOIN_FIELD_HEAD:          sprintf(type_name, "CHEATCOIN_FIELD_HEAD");         break;
        case CHEATCOIN_FIELD_IN:            sprintf(type_name, "CHEATCOIN_FIELD_IN" ) ;         break;
        case CHEATCOIN_FIELD_OUT:           sprintf(type_name, "CHEATCOIN_FIELD_OUT");          break;
        case CHEATCOIN_FIELD_SIGN_IN:       sprintf(type_name, "CHEATCOIN_FIELD_SIGN_IN");      break;
        case CHEATCOIN_FIELD_SIGN_OUT:      sprintf(type_name, "CHEATCOIN_FIELD_SIGN_OUT");     break;
        case CHEATCOIN_FIELD_PUBLIC_KEY_0:  sprintf(type_name, "CHEATCOIN_FIELD_PUBLIC_KEY_0"); break;
        case CHEATCOIN_FIELD_PUBLIC_KEY_1:  sprintf(type_name, "CHEATCOIN_FIELD_PUBLIC_KEY_1"); break;
        default:sprintf(type_name, "UNKNOWN");
    }
    printf("type (%d) = %s \n",type,type_name);
}


void showbits(unsigned int x)
{
    int i;
    for(i=(sizeof(int)*8)-1; i>=0; i--) {
        (x & (1u << i)) ? putchar('1') : putchar('0');
        if (i % 8 == 0) putchar(',');
    }
    printf("\n");
}

void print_hash(cheatcoin_hash_t hash){
    printf("%016llx%016llx%016llx%016llx\n",
           (unsigned long long)hash[3], (unsigned long long)hash[2], (unsigned long long)hash[1], (unsigned long long)hash[0]);
}

static const uint8_t bits2mime[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static uint8_t mime2bits[256];

/* инициализировать модуль адресов */
int cheatcoin_address_init(void) {
    int i;
    memset(mime2bits, 0xFF, 256);
    for (i = 0; i < 64; ++i) mime2bits[bits2mime[i]] = i;
    return 0;
}

/* преобразовать хеш в адрес */
const char *cheatcoin_hash2address(const cheatcoin_hash_t hash) {
	static char bufs[4][33];
	static int k = 0;
	char *buf = &bufs[k++ & 3][0], *ptr = buf;
	int i, c, d;
	const uint8_t *fld = (const uint8_t *)hash;   // 8 bits point
        printf("0,hash=%16u,%16u,%16u,%16u,         hash=",hash[3],hash[2],hash[1],hash[0]);
        showbits(hash[3]);showbits(hash[2]);showbits(hash[1]);showbits(hash[0]);
        printf("0, fld            =%16u,          fld=",*fld);showbits(*fld);
	for (i = c = d = 0; i < 32; ++i) {
        printf("1,   c            =%16u,            c=",c);showbits(c);
        printf("1,   d            =%16u,            d=",d);showbits(d);
        printf("1, fld            =%16u,          fld=",*fld);showbits(*fld);
		if (d < 6) d += 8, c <<= 8, c |= *fld++;
		printf("2,   c            =%16u,            c=",c);showbits(c);
        printf("2,   d            =%16u,            d=",d);showbits(d);
        printf("2, fld            =%16u,          fld=",*fld);showbits(*fld);
        int d_6 = d - 6;
        printf("3, d_6            =%16u,          d_6=",d_6);showbits(d_6);
        int c_shift_d_6 = c >> d_6 ;
        printf("3, c_shift_d_6    =%16u,  c_shift_d_6=",c_shift_d_6);showbits(c_shift_d_6);
        int c_shift_d6_3f = c_shift_d_6 & 0x3F;
        printf("3, c_shift_d6_3f  =%16u,c_shift_d6_3f=",c_shift_d6_3f);showbits(c_shift_d6_3f);


        int token= (c >> (d -= 6) & 0x3F);
        printf("3,   c            =%16u,            c=",c);showbits(c);
        printf("3,   d            =%16u,            d=",d);showbits(d);
        printf("3, fld            =%16u,          fld=",*fld);showbits(*fld);
		printf("token=%u -> bits2mime[%u]= %c,  token=",token, token,bits2mime[token]);showbits(token);
		//*ptr++ = bits2mime[c >> (d -= 6) & 0x3F];
		*ptr++ = bits2mime[token];
		//printf("hash=%llu,i=%d,c=%d,d=%d,k=%d,buf=%s,fld=%d,ptr=%s\n",hash,i,c,d,k,buf,*fld,*ptr);
	}
	*ptr = 0;
	return buf;
}

int cheatcoin_address2hash(const char *address, cheatcoin_hash_t hash) {
    uint8_t *fld = (uint8_t *)hash;
    int i, c, d, e, n;
    for (e = n = i = 0; i < 32; ++i) {
        do {
            if (!(c = (uint8_t)*address++)) return -1;
            d = mime2bits[c];
        } while (d & 0xC0);
        e <<= 6, e |= d, n += 6;
        if (n >= 8) {
            *fld++ = e >> (n -= 8);
        }
    }
    for (i = 0; i < 8; ++i) *fld++ = 0;
    return 0;
}

static void *print_block_callback(void *block, void *data) {

    struct cheatcoin_block *b = (struct cheatcoin_block *) block;

    cheatcoin_time_t *t = (cheatcoin_time_t *) data;

    uint64_t theader = b->field[0].transport_header;

    cheatcoin_hash_t hash;
    cheatcoin_hash(b, sizeof(struct cheatcoin_block), hash);
    printf_type(cheatcoin_type(b, 0));

    printf(" field 0 type: %llx\n", b->field[0].type);
    showbits(b->field[0].type);
    // #define cheatcoin_type(b, n) ((b)->field[0].type >> ((n) << 2) & 0xf)
    int i = 0;
    int nsignin = 0, nsignout = 0, signinmask = 0, signoutmask = 0;
    int inmask = 0, outmask = 0;
    //int type = 0;
    for (i = 1; i < CHEATCOIN_BLOCK_FIELDS; ++i) {
        /*
        printf("i                                    = ");
        showbits(i);
        printf("i<<2                                 = ");
        showbits(i<<2);
        printf("b->field[0].type                     = ");
        showbits(b->field[0].type);
        printf("b->field[0].type >> ((i) << 2)       = ");
        showbits(b->field[0].type >> ((i) << 2));
        printf("b->field[0].type >> ((i) << 2) & 0xf = ");
        showbits(b->field[0].type >> ((i) << 2) & 0xf);
        */
        int type = cheatcoin_type(b,i);
        printf_type(type);
        switch((type = cheatcoin_type(b,i))){
            case CHEATCOIN_FIELD_NONCE:			break;
            case CHEATCOIN_FIELD_IN:			inmask  |= 1 << i; break;
            case CHEATCOIN_FIELD_OUT:			outmask |= 1 << i; break;
            case CHEATCOIN_FIELD_SIGN_IN:		if (++nsignin  & 1) signinmask  |= 1 << i; break;
            case CHEATCOIN_FIELD_SIGN_OUT:		if (++nsignout & 1) signoutmask |= 1 << i; break;
        }
    }
    printf("inmask      =");showbits(inmask);
    printf("outmask     =");showbits(outmask);
    printf("signinmask  =");showbits(signinmask);
    printf("signoutmask =");showbits(signoutmask);


    print_hash(hash);
    cheatcoin_hash_t hash2;
    cheatcoin_address2hash("egdowWJppa6uCci2Q1/PGeFWNRGu3sel",hash2);
    print_hash(hash2);

    if (memcmp(hash, hash2, sizeof(cheatcoin_hashlow_t) ) == 0 ){
        printf("hashlow eq! \n");
    }
    printf("%s\n",cheatcoin_hash2address(hash));
    printf("%s\n",cheatcoin_hash2address(hash2));
    struct tm tm;
    char tbuf[64];
    localtime_r(&b->field[0].time, &tm);
    strftime(tbuf, 64, "%Y-%m-%d %H:%M:%S", &tm);



    printf("      time: %s\n", tbuf);
    printf(" timestamp: %llx\n", (unsigned long long)b->field[0].time);
    printf("    amount: %u\n", b->field[0].amount);
    printf("    data: %d\n", b->field[0].data);


    printf("test %d %d\n",b,data);
    return 1; //return 1 -> only print the first one, stop
    //return 0;
}


int main (int argc, char **argv)
{
    int n = 0;
    cheatcoin_address_init();
    // test debug log
    char *ptr;
    g_progname = strdup(argv[0]);
    while ((ptr = strchr(g_progname, '/')) || (ptr = strchr(g_progname, '\\'))) g_progname = ptr + 1;
    cheatcoin_set_log_level(9);
    cheatcoin_mess("meg...");
    cheatcoin_info("info...");
    cheatcoin_debug("debug...");

    et=get_timestamp();
    cheatcoin_load_blocks(st, et, &st, print_block_callback);
    return (n == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}







