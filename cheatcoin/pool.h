/* пул и майнер, T13.744-T13.836 $DVS:time$ */

#ifndef CHEATCOIN_POOL_H
#define CHEATCOIN_POOL_H

#include <stdio.h>
#include "block.h"
#include "hash.h"

#define CHEATCOIN_POOL_N_CONFIRMATIONS	16

struct cheatcoin_pool_task {
	struct cheatcoin_field task[2], lastfield, minhash, nonce;
	cheatcoin_time_t main_time;
	void *ctx0, *ctx;
};

#define N_MINERS		4096
#define START_N_MINERS	256
#define START_N_MINERS_IP 8
#define MINERS_PWD		"minersgonnamine"
#define SECTOR0_BASE	0x1947f3acu
#define SECTOR0_OFFSET	0x82e9d1b5u
#define HEADER_WORD		0x3fca9e2bu
#define DATA_SIZE		(sizeof(struct cheatcoin_field) / sizeof(uint32_t))
#define SEND_PERIOD		10 /* период в секундах, с которым майнер посылает пулу результаты */
#define FUND_ADDRESS	"FQglVQtb60vQv2DOWEUL7yh3smtj7g1s" /* адрес фонда сообщества */

enum miner_state {
	MINER_BLOCK		= 1,
	MINER_ARCHIVE	= 2,
	MINER_FREE		= 4,
	MINER_BALANCE	= 8,
	MINER_ADDRESS	= 0x10,
};

struct miner {
	double maxdiff[CHEATCOIN_POOL_N_CONFIRMATIONS];
	struct cheatcoin_field id;
	uint32_t data[DATA_SIZE];
	double prev_diff;
	cheatcoin_time_t main_time;
	uint64_t nfield_in;
	uint64_t nfield_out;
	uint64_t ntask;
	struct cheatcoin_block *block;
	uint32_t ip;
	uint32_t prev_diff_count;
	uint16_t port;
	uint16_t state;
	uint8_t data_size;
	uint8_t block_size;
};

/* инициализация пула (pool_on = 1) или подключение майнера к пулу (pool_on = 0; pool_arg - параметры пула ip:port[:CFG];
   miner_addr - адрес майнера, если он указан явно */
extern int cheatcoin_pool_start(int pool_on, const char *pool_arg, const char *miner_address);

/* изменяет число потоков майнинга */
extern int cheatcoin_mining_start(int n_mining_threads);

/* получает параметры пула в виде строки, 0 - если пул отключен */
extern char *cheatcoin_pool_get_config(char *buf);

/* устанавливает параметры пула */
extern int cheatcoin_pool_set_config(const char *str);

/* послать блок в сеть через пул */
extern int cheatcoin_send_block_via_pool(struct cheatcoin_block *b);

/* вывести в файл список майнеров */
extern int cheatcoin_print_miners(FILE *out);

extern struct cheatcoin_pool_task g_cheatcoin_pool_task[2];
extern uint64_t g_cheatcoin_pool_ntask;
extern cheatcoin_hash_t g_cheatcoin_mined_hashes[CHEATCOIN_POOL_N_CONFIRMATIONS],
						g_cheatcoin_mined_nonce[CHEATCOIN_POOL_N_CONFIRMATIONS];
/* число собственных потоков майнинга */
extern int g_cheatcoin_mining_threads;
/* указатель на мьютекс, блокирующий оптимальную шару */
extern void *g_ptr_share_mutex;

#endif
