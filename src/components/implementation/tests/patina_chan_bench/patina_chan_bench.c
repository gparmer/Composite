/*
 * Copyright 2020, Bite Ye, Runyu Pan and Gabriel Parmer, GWU, gparmer@gwu.edu.
 *
 * This uses a two clause BSD License.
 */

#include <llprint.h>
#include <sched.h>

#include <patina.h>
#include <perfdata.h>
#include <cos_time.h>

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

#undef PATINA_CHAN_TRACE_DEBUG
#ifdef PATINA_CHAN_TRACE_DEBUG
#define debug(format, ...) printc(format, ##__VA_ARGS__)
#else
#define debug(format, ...)
#endif

/* One low-priority thread and one high-priority thread contends on the lock */
#ifdef COLD_CACHE
#define ITERATION 10 * 10
#else
#define ITERATION 10 * 1000
#endif
#undef PRINT_ALL

/* Two options are available: Sender at low/high prio, data words 4 */
#define DATA_WORDS 2

thdid_t chan_reader = 0, chan_writer = 0;

typedef unsigned int cycles_32_t;

volatile cycles_32_t tmp[DATA_WORDS] = {
  0,
};
volatile cycles_32_t ts1[DATA_WORDS] = {
  0,
};
volatile cycles_32_t ts2[DATA_WORDS] = {
  0,
};
volatile cycles_32_t ts3[DATA_WORDS] = {
  0,
};

struct perfdata perf1, perf2, perf3;
cycles_t        result1[ITERATION] = {
  0,
};
cycles_t result2[ITERATION] = {
  0,
};
cycles_t result3[ITERATION] = {
  0,
};

patina_chan_t   cid;
patina_chan_t   cid2;
patina_chan_r_t rid;
patina_chan_r_t rid2;
patina_chan_s_t sid;
patina_chan_s_t sid2;

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
 * The two threads reciprocally sends and receives.
 */
void
chan_reader_thd(void *d)
{
	/* Never stops running; writer controls how many iters to run. */
	while (1) {
		debug("r1,");
		patina_channel_recv(rid, (void *)tmp, 0, 0);
		debug("tsr1: %d,", tmp[0]);
		debug("r2,");
		tmp[0] = time_now();
		debug("tsr2: %d,", tmp[0]);
		debug("r3,");
		patina_channel_send(sid2, (void *)tmp, 0, 0);
		debug("r4,");
	}
}

void
chan_writer_thd(void *d)
{
	int i;

	for (int i = 0; i < ITERATION + COLD_OFFSET; i++) {
		debug("w1,");
		cache_flush();
		ts1[0] = time_now();
		debug("ts1: %d,", ts1[0]);
		debug("w2,");
		patina_channel_send(sid, (void *)ts1, 0, 0);
		debug("w3,");
		patina_channel_recv(rid2, (void *)ts2, 0, 0);
		debug("ts2: %d,", ts2[0]);
		debug("w4,");
		ts3[0] = time_now();
		debug("w5,");

		if (ts2[0] > ts1[0] && ts3[0] > ts2[0] && i != COLD_INDEX) {
			perfdata_add(&perf1, ts2[0] - ts1[0]);
			perfdata_add(&perf2, ts3[0] - ts2[0]);
			perfdata_add(&perf3, ts3[0] - ts1[0]);
		}
	}

#ifdef PRINT_ALL
	perfdata_raw(&perf1);
	perfdata_raw(&perf2);
	perfdata_raw(&perf3);
#endif
	perfdata_calc(&perf1);
	perfdata_calc(&perf2);
	perfdata_calc(&perf3);

	perfdata_print(&perf1);
	perfdata_print(&perf2);
	perfdata_print(&perf3);

	while (1);
}

void
test_chan(void)
{
	int      i;
	cycles_t begin, end;

	sched_param_t sps[] = {SCHED_PARAM_CONS(SCHEDP_PRIO, 4), SCHED_PARAM_CONS(SCHEDP_PRIO, 6)};

	/* Uncontended lock taking/releasing */
	perfdata_init(&perf1, "Uncontended channel - selfloop", result1, ITERATION);
	for (i = 0; i < ITERATION; i++) {
		begin = time_now();

		debug("send\n");
		patina_channel_send(sid, (void *)tmp, 1, 0);
		debug("recv\n");
		patina_channel_recv(rid, (void *)tmp, 1, 0);

		end = time_now();
		perfdata_add(&perf1, end - begin);
	}
#ifdef PRINT_ALL
	perfdata_raw(&perf1);
#endif
	perfdata_calc(&perf1);
	perfdata_print(&perf1);

	perfdata_init(&perf1, "Contended channel - reader high use this", result1, ITERATION);
	perfdata_init(&perf2, "Contended channel - writer high use this", result2, ITERATION);
	perfdata_init(&perf3, "Contended channel - roundtrip", result3, ITERATION);

	printc("Create threads:\n");

	chan_reader = sched_thd_create(chan_reader_thd, NULL);
	printc("\tcreating reader thread %ld at prio %d\n", chan_reader, sps[1]);
	sched_thd_param_set(chan_reader, sps[0]);

	chan_writer = sched_thd_create(chan_writer_thd, NULL);
	printc("\tcreating writer thread %ld at prio %d\n", chan_writer, sps[0]);
	sched_thd_param_set(chan_writer, sps[1]);
}

void
cos_init(void)
{
	printc("Benchmark for the patina chan (w/sched interface).\n");
}

int
main(void)
{
	sched_thd_block_timeout(0, time_now() + time_usec2cyc(1000 * 1000));

	printc("Initializing channel\n");

	cid  = patina_channel_create(sizeof(cycles_32_t), DATA_WORDS, 0, CHAN_DEFAULT);
	cid2 = patina_channel_create(sizeof(cycles_32_t), DATA_WORDS, 0, CHAN_DEFAULT);

	printc("Initializing end points\n");

	sid  = patina_channel_get_send(cid);
	rid  = patina_channel_get_recv(cid);
	sid2 = patina_channel_get_send(cid2);
	rid2 = patina_channel_get_recv(cid2);

	test_chan();

	printc("Running benchmark, exiting main thread...\n");

	return 0;
}
