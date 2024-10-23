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

#undef EVENT_TRACE_DEBUG
#ifdef EVENT_TRACE_DEBUG
#define debug(format, ...) printc(format, ##__VA_ARGS__)
#else
#define debug(format, ...)
#endif

#define ITERATION 10 * 1000
/* #define PRINT_ALL */

patina_sem_t   sid;
patina_event_t evt;
evt_res_id_t   rid;

thdid_t      evt_hi = 0, evt_lo = 0;
volatile int flag = 0;

volatile cycles_t start;
volatile cycles_t end;

struct perfdata perf;
cycles_t        result[ITERATION] = {
  0,
};

void
evt_hi_thd(void *d)
{
	int i;

	for (i = 0; i < ITERATION; i++) {
		debug("h1");
		patina_event_wait(&evt, NULL, 0);
		end = time_now();

		debug("h2");
		perfdata_add(&perf, end - start);

		debug("h3");
		patina_sem_give(sid);
	}

#ifdef PRINT_ALL
	perfdata_raw(&perf);
#endif
	perfdata_calc(&perf);
	perfdata_print(&perf);

	while (1);
}

void
evt_lo_thd(void *d)
{
	while (1) {
		debug("l1");
		start = time_now();
		patina_event_debug_trigger(rid);

		debug("l2");
		patina_sem_take(sid);
	}
}

void
test_evt(void)
{
	int      i;
	int      first = 0;
	cycles_t start, end;

	sched_param_t sps[] = {SCHED_PARAM_CONS(SCHEDP_PRIO, 4), SCHED_PARAM_CONS(SCHEDP_PRIO, 6)};

	sid = patina_sem_create(0, 0);
	patina_event_create(&evt, 1);
	rid = patina_event_debug_fake_add(&evt);

	perfdata_init(&perf, "Event latency - total", result, ITERATION);

	printc("Create threads:\n");

	evt_lo = sched_thd_create(evt_lo_thd, NULL);
	printc("\tcreating lo thread %ld at prio %d\n", evt_lo, sps[0]);
	sched_thd_param_set(evt_lo, sps[1]);

	evt_hi = sched_thd_create(evt_hi_thd, NULL);
	printc("\tcreating hi thread %ld at prio %d\n", evt_hi, sps[0]);
	sched_thd_param_set(evt_hi, sps[0]);
}

void
cos_init(void)
{
	printc("Benchmark for the event (w/sched interface).\n");
}

int
main(void)
{
	sched_thd_block_timeout(0, time_now() + time_usec2cyc(1000 * 1000));

	test_evt();

	printc("Running benchmark, exiting main thread...\n");

	return 0;
}
