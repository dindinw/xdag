/* логирование, T13.670-T13.811 $DVS:time$ */

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/time.h>
#include "system.h"
#include "log.h"
#include "main.h"

#define CHEATCOIN_LOG_FILE "%s.log"

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int log_level = CHEATCOIN_INFO;

int cheatcoin_log(int level, const char *format, ...) {
	static const char lvl[] = "NONEFATACRITINTEERROWARNMESSINFODBUGTRAC";
	char tbuf[64], buf[64];
	struct tm tm;
	va_list arg;
	struct timeval tv;
	FILE *f;
	int done;
	time_t t;

	if (level < 0 || level > CHEATCOIN_TRACE) level = CHEATCOIN_INTERNAL;
	if (level > log_level) return 0;
	gettimeofday(&tv, 0);
	t = tv.tv_sec;
	localtime_r(&t, &tm);
	strftime(tbuf, 64, "%Y-%m-%d %H:%M:%S", &tm);
	pthread_mutex_lock(&log_mutex);
	sprintf(buf, CHEATCOIN_LOG_FILE, g_progname);
	f = fopen(buf, "a");
	if (!f) { done = -1; goto end; }
	fprintf(f, "%s.%03d [%012llx:%.4s]  ", tbuf, (int)(tv.tv_usec / 1000), (long long)pthread_self_ptr(), lvl + 4 * level);

	va_start(arg, format);
	done = vfprintf(f, format, arg);
	va_end(arg);

	fprintf(f, "\n");
	fclose(f);
end:
	pthread_mutex_unlock(&log_mutex);

    return done;
}

extern char *cheatcoin_log_array(const void *arr, unsigned size) {
	static int k = 0;
	static char buf[4][0x1000];
	char *res = &buf[k++ & 3][0];
	unsigned i;
	for (i = 0; i < size; ++i) sprintf(res + 3 * i - !!i, "%s%02x", (i ? ":" : ""), ((uint8_t *)arr)[i]);
	return res;
}

/* устанавливает максимальный уровень ошибки для вывода в лог, возвращает прежний уровень (0 - ничего не выводить, 9 - всё) */
extern int cheatcoin_set_log_level(int level) {
	int level0 = log_level;
	if (level >= 0 && level <= CHEATCOIN_TRACE) log_level = level;
	return level0;
}


#if !defined(_WIN32) && !defined(_WIN64)
#define __USE_GNU
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <execinfo.h>

#ifdef linux
#include <ucontext.h>

#define RIP_sig(context)     ((context)->uc_mcontext.gregs[REG_RIP])
#define EFL_sig(context)     ((context)->uc_mcontext.gregs[REG_EFL])
#define ERR_sig(context)     ((context)->uc_mcontext.gregs[REG_ERR])
#define TRAP_sig(context)    ((context)->uc_mcontext.gregs[REG_TRAPNO])
#define CR2_sig(context) ((char *)context->uc_mcontext.gregs[REG_CR2])

#define RAX_sig(context)     ((context)->uc_mcontext.gregs[REG_RAX])
#define RBX_sig(context)     ((context)->uc_mcontext.gregs[REG_RBX])
#define RCX_sig(context)     ((context)->uc_mcontext.gregs[REG_RCX])
#define RDX_sig(context)     ((context)->uc_mcontext.gregs[REG_RDX])
#define RSI_sig(context)     ((context)->uc_mcontext.gregs[REG_RSI])
#define RDI_sig(context)     ((context)->uc_mcontext.gregs[REG_RDI])
#define RBP_sig(context)     ((context)->uc_mcontext.gregs[REG_RBP])


#define R8_sig(context)      ((context)->uc_mcontext.gregs[REG_R8])
#define R9_sig(context)      ((context)->uc_mcontext.gregs[REG_R9])
#define R10_sig(context)     ((context)->uc_mcontext.gregs[REG_R10])
#define R11_sig(context)     ((context)->uc_mcontext.gregs[REG_R11])
#define R12_sig(context)     ((context)->uc_mcontext.gregs[REG_R12])
#define R13_sig(context)     ((context)->uc_mcontext.gregs[REG_R13])
#define R14_sig(context)     ((context)->uc_mcontext.gregs[REG_R14])
#define R15_sig(context)     ((context)->uc_mcontext.gregs[REG_R15])


#elif __APPLE__
# include <sys/ucontext.h>
#define RIP_sig(context)     (*((unsigned long*)&(context)->uc_mcontext->__ss.__rip))
#define RSP_sig(context)     (*((unsigned long*)&(context)->uc_mcontext->__ss.__rsp))
#define TRAP_sig(context)    ((context)->uc_mcontext->__es.__trapno)
#define ERR_sig(context)     ((context)->uc_mcontext->__es.__err)
#define EFL_sig(context)     ((context)->uc_mcontext->__ss.__rflags)
#define CR2_sig(context)     ((char *) info->si_addr)


#define RAX_sig(context)     ((context)->uc_mcontext->__ss.__rax)
#define RBX_sig(context)     ((context)->uc_mcontext->__ss.__rbx)
#define RCX_sig(context)     ((context)->uc_mcontext->__ss.__rcx)
#define RDX_sig(context)     ((context)->uc_mcontext->__ss.__rdx)
#define RSI_sig(context)     ((context)->uc_mcontext->__ss.__rsi)
#define RDI_sig(context)     ((context)->uc_mcontext->__ss.__rdi)
#define RBP_sig(context)     ((context)->uc_mcontext->__ss.__rbp)
#define R8_sig(context)      ((context)->uc_mcontext->__ss.__r8)
#define R9_sig(context)      ((context)->uc_mcontext->__ss.__r9)
#define R10_sig(context)     ((context)->uc_mcontext->__ss.__r10)
#define R11_sig(context)     ((context)->uc_mcontext->__ss.__r11)
#define R12_sig(context)     ((context)->uc_mcontext->__ss.__r12)
#define R13_sig(context)     ((context)->uc_mcontext->__ss.__r13)
#define R14_sig(context)     ((context)->uc_mcontext->__ss.__r14)
#define R15_sig(context)     ((context)->uc_mcontext->__ss.__r15)

#endif



#define REG_(name) sprintf(buf + strlen(buf), #name "=%llx, ",(unsigned long long)name##_sig(uc))

//#define REG_(name) sprintf(buf + strlen(buf), #name "=%llx, ", (unsigned long long)uc->uc_mcontext.gregs[REG_##name])

static void sigCatch(int signum, siginfo_t *info, void *context) {
	static void *callstack[100];
	int frames, i;
	char **strs;
	cheatcoin_fatal("Signal %d delivered", signum);
#ifdef __x86_64__
	{
	static char buf[0x100]; *buf = 0;
	ucontext_t *uc = (ucontext_t *)context;
	REG_(RIP); REG_(EFL); REG_(ERR); REG_(CR2);
	cheatcoin_fatal("%s", buf); *buf = 0;
	REG_(RAX); REG_(RBX); REG_(RCX); REG_(RDX); REG_(RSI); REG_(RDI); REG_(RBP); REG_(RSP);
	cheatcoin_fatal("%s", buf); *buf = 0;
	REG_(R8); REG_(R9); REG_(R10); REG_(R11); REG_(R12); REG_(R13); REG_(R14); REG_(R15);
	cheatcoin_fatal("%s", buf);
	}
#endif
	frames = backtrace(callstack, 100);
	strs = backtrace_symbols(callstack, frames);
	for (i = 0; i < frames; ++i)
		cheatcoin_fatal("%s", strs[i]);
	signal(signum, SIG_DFL);
	kill(getpid(), signum);
	exit(-1);
}

int cheatcoin_log_init(void) {
	int i;
	struct sigaction sa;
	sa.sa_sigaction = sigCatch;
	sigemptyset (&sa.sa_mask);
	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	for (i = 1; i < 32; ++i) {
		if (i != SIGURG && i != SIGCHLD && i != SIGCONT && i != SIGPIPE) {
			sigaction(i, &sa, 0);
		}
	}
	return 0;
}

#else

int cheatcoin_log_init(void) { return 0; }

#endif
