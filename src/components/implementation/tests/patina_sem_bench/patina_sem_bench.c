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

#undef SEM_TRACE_DEBUG
#ifdef SEM_TRACE_DEBUG
#define debug(format, ...) printc(format, ##__VA_ARGS__)
#else
#define debug(format, ...)
#endif

/* One low-priority thread and one high-priority thread contends on the semaphore */
#define ITERATION 10 * 1000
/* #define PRINT_ALL */

patina_sem_t sid;
thdid_t      sem_hi = 0, sem_lo = 0;
volatile int flag = 0;

volatile cycles_t start;
volatile cycles_t end;

struct perfdata perf;
cycles_t        result[ITERATION] = {
  0,
};

/***
 * The high priority thread periodically challenges the sem while the low priority thread keeps spinning.
 * When the low-priority thread detects that the flag is changed, it knows that the sem is challenged.
 * Execution: hi take -> lo release -> hi release, there is 1 contended take, 1 give, and 2 ctxsws.
 */
void
sem_hi_thd(void *d)
{
	/* Never stops running; low priority controls how many iters to run. */
	while (1) {
		debug("h1");
		sched_thd_block(0);
		sched_thd_block_timeout(0, time_now() + time_usec2cyc(1000));

		debug("h2");
		flag  = 1;
		start = time_now();

		patina_sem_take(sid);
		patina_sem_give(sid);

		end = time_now();
		debug("h3");
	}
}

void
sem_lo_thd(void *d)
{
	int i;

	for (i = 0; i < ITERATION; i++) {
		debug("l1");
		sched_thd_wakeup(sem_hi);

		debug("l2");
		flag = 0;
		patina_sem_take(sid);

		debug("l3");
		while (flag != 1) {}

		patina_sem_give(sid);

		perfdata_add(&perf, end - start);
		debug("l4");
	}

#ifdef PRINT_ALL
	perfdata_all(&perf);
#endif
	perfdata_calc(&perf);
	perfdata_print(&perf);

	while (1);
}

void
test_sem(void)
{
	int      i;
	cycles_t start, end;

	sched_param_t sps[] = {SCHED_PARAM_CONS(SCHEDP_PRIO, 4), SCHED_PARAM_CONS(SCHEDP_PRIO, 6)};

	sid = patina_sem_create(1, 0);

	/* Uncontended semaphore taking/releasing */
	perfdata_init(&perf, "Uncontended semaphore - take+give", result, ITERATION);
	for (i = 0; i < ITERATION; i++) {
		start = time_now();

		patina_sem_take(sid);
		patina_sem_give(sid);

		end = time_now();
		perfdata_add(&perf, end - start);
	}
#ifdef PRINT_ALL
	perfdata_raw(&perf);
#endif
	perfdata_calc(&perf);
	perfdata_print(&perf);

	perfdata_init(&perf, "Contended semaphore - take+give", result, ITERATION);

	printc("Create threads:\n");

	sem_lo = sched_thd_create(sem_lo_thd, NULL);
	printc("\tcreating lo thread %ld at prio %d\n", sem_lo, sps[1]);
	sched_thd_param_set(sem_lo, sps[1]);

	sem_hi = sched_thd_create(sem_hi_thd, NULL);
	printc("\tcreating hi thread %ld at prio %d\n", sem_hi, sps[0]);
	sched_thd_param_set(sem_hi, sps[0]);
}

void
cos_init(void)
{
	printc("Benchmark for the crt_sem (w/sched interface).\n");
}

int
main(void)
{
	sched_thd_block_timeout(0, time_now() + time_usec2cyc(1000 * 1000));

	test_sem();

	printc("Running benchmark, exiting main thread...\n");

	return 0;
}
