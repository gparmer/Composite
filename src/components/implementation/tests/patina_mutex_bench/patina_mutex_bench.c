/*
 * Copyright 2020, Bite Ye, Runyu Pan and Gabriel Parmer, GWU, gparmer@gwu.edu.
 *
 * This uses a two clause BSD License.
 */

#include <llprint.h>
#include <sched.h>
#include <cos_time.h>
#include <patina.h>
#include <perfdata.h>

#define COLD_CACHE
#ifdef COLD_CACHE
#define cache_flush() __cache_flush()
#define COLD_OFFSET 1
#define COLD_INDEX 0
#else
#define cache_flush()
#define COLD_OFFSET 0
#define COLD_INDEX -1
#endif

#define CACHE_SIZE 512 * 1024
#define CACHE_LINE_SIZE 32

#undef LOCK_TRACE_DEBUG
#ifdef LOCK_TRACE_DEBUG
#define debug(format, ...) printc(format, ##__VA_ARGS__)
#else
#define debug(format, ...)
#endif

/* One low-priority thread and one high-priority thread contends on the lock */
#ifdef COLD_CACHE
#define ITERATION 10 * 10
#define SLEEP_TIME 100 * 1000
#else
#define ITERATION 10 * 1000
#define SLEEP_TIME 1000
#endif

/* #define PRINT_ALL */

patina_mutex_t mid;
thdid_t        lock_hi = 0, lock_lo = 0;
volatile int   flag = 0;

volatile cycles_t start;
volatile cycles_t end;

struct perfdata perf;
cycles_t        result[ITERATION] = {
  0,
};

volatile char pool[CACHE_SIZE * 4] = {
  0,
};

void
__cache_flush()
{
	int agg = 1;
	for (int i = 0; i < CACHE_SIZE * 4; i += CACHE_LINE_SIZE) {
		pool[i] += agg;
		agg = pool[i];
	}
}

/***
 * The high priority thread periodically challenges the lock while the low priority thread keeps spinning.
 * When the low-priority thread detects that the flag is changed, it knows that the lock is challenged.
 * Execution: hi take -> lo release -> hi release, there is 1 contended take, 1 release, and 2 ctxsws.
 */
void
lock_hi_thd(void *d)
{
	/* Never stops running; low priority controls how many iters to run. */
	while (1) {
		debug("h1,");
		sched_thd_block(0);
		sched_thd_block_timeout(0, time_now() + time_usec2cyc(SLEEP_TIME));

		debug("h2,");
		cache_flush();
		flag  = 1;
		start = time_now();
		patina_mutex_lock(mid);
		patina_mutex_unlock(mid);

		end = time_now();
		debug("h3,");
	}
}

void
lock_lo_thd(void *d)
{
	int i;

	for (i = 0; i < ITERATION + COLD_OFFSET; i++) {
		debug("l1,");
		sched_thd_wakeup(lock_hi);

		debug("l2,");
		flag = 0;
		patina_mutex_lock(mid);

		debug("l3,");
		while (flag != 1) {}
		patina_mutex_unlock(mid);

		if (i != COLD_INDEX) { perfdata_add(&perf, end - start); }
		debug("l4,");
	}

#ifdef PRINT_ALL
	perfdata_raw(&perf);
#endif
	perfdata_calc(&perf);
	perfdata_print(&perf);

	while (1);
}

void
test_lock(void)
{
	int i;

	sched_param_t sps[] = {SCHED_PARAM_CONS(SCHEDP_PRIO, 4), SCHED_PARAM_CONS(SCHEDP_PRIO, 6)};

	mid = patina_mutex_create(0);

	/* Uncontended lock taking/releasing */
	perfdata_init(&perf, "Uncontended lock - take+release", result, ITERATION);
	for (i = 0; i < ITERATION + COLD_OFFSET; i++) {
		cache_flush();
		start = time_now();

		patina_mutex_lock(mid);
		patina_mutex_unlock(mid);

		end = time_now();
		if (i != COLD_INDEX) { perfdata_add(&perf, end - start); }
	}
#ifdef PRINT_ALL
	perfdata_raw(&perf);
#endif
	perfdata_calc(&perf);
	perfdata_print(&perf);

	perfdata_init(&perf, "Contended lock - take+release", result, ITERATION);

	printc("Create threads:\n");

	lock_lo = sched_thd_create(lock_lo_thd, NULL);
	printc("\tcreating lo thread %ld at prio %d\n", lock_lo, sps[1]);
	sched_thd_param_set(lock_lo, sps[1]);

	lock_hi = sched_thd_create(lock_hi_thd, NULL);
	printc("\tcreating hi thread %ld at prio %d\n", lock_hi, sps[0]);
	sched_thd_param_set(lock_hi, sps[0]);
}

void
cos_init(void)
{
	printc("Benchmark for the crt_lock (w/sched interface).\n");
}

int
main(void)
{
	sched_thd_block_timeout(0, time_now() + time_usec2cyc(1000 * 1000));

	test_lock();

	printc("Running benchmark, exiting main thread...\n");

	return 0;
}
