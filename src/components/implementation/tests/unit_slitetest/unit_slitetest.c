/*
 * Copyright 2018, Phani Gadepalli and Gabriel Parmer, GWU, gparmer@gwu.edu.
 *
 * This uses a two clause BSD License.
 */

#include <llprint.h>
#include <res_spec.h>
#include <sched.h>
#include <cos_time.h>
#include <perfdata.h>

#define SL_FPRR_NPRIOS 32

#define LOWEST_PRIORITY (SL_FPRR_NPRIOS - 1)

#define LOW_PRIORITY (LOWEST_PRIORITY - 1)
#define HIGH_PRIORITY (LOWEST_PRIORITY - 10)

#define TEST_RCV_CORE 0
#define TEST_SND_CORE 1

#define TEST_ITERS 1000000

static volatile int test_done = 0;
static volatile thdid_t thd[2] = { 0 };
static volatile thdid_t spin_thd[2] = { 0 };

static volatile unsigned long long total_rcvd[NUM_CPU] = { 0 };
static volatile unsigned long long total_sent[NUM_CPU] = { 0 };

static volatile cycles_t global_time[2] = { 0 };
static volatile cycles_t time = 0;

static struct perfdata pd;

#define ARRAY_SIZE 10000
static cycles_t results[ARRAY_SIZE];

static void
rcv_spiner()
{
	int i = 0;
	while (!spin_thd[1]) ;
	while (i < TEST_ITERS) {
		//printc("*************spiner1**************: %ld\n\n", spin_thd[0]);
		printc("%ld\n", spin_thd[0]);
		i++;
		sched_thd_yield_to(spin_thd[1]);
	}
	printc("SUCCESS\n");
	test_done = 1;
	SPIN();
	assert(0);
	return;
}

static void
rcv_spiner2()
{
	int i = 0;
	while (!spin_thd[0]) ;
	while (!test_done) {
		//printc("*************spiner2**************: %ld\n\n", spin_thd[1]);
		printc("%ld", spin_thd[1]);
		sched_thd_yield_to(spin_thd[0]);
	}
	SPIN();
	assert(0);
	return;
}

void
test_ipi_switch(void)
{

	if (cos_cpuid() == TEST_RCV_CORE) {
		printc("test ipi switch\n");
		spin_thd[0] = sched_thd_create(rcv_spiner, NULL);
		sched_thd_param_set(spin_thd[0], sched_param_pack(SCHEDP_PRIO, HIGH_PRIORITY));

		spin_thd[1] = sched_thd_create(rcv_spiner2, NULL);
		sched_thd_param_set(spin_thd[1], sched_param_pack(SCHEDP_PRIO, HIGH_PRIORITY));

		sched_thd_yield_to(spin_thd[0]);
		//sched_thd_yield_to(thd[cos_cpuid()]);
	} else {
		//thd[cos_cpuid()] = sched_thd_create(test_snd_fn, NULL);
		//sched_thd_param_set(thd[cos_cpuid()], sched_param_pack(SCHEDP_PRIO, HIGH_PRIORITY));
	}
	SPIN();
	assert(0);
}

void
parallel_main(coreid_t cid, int init_core, int ncores)
{
	int i = 0;

	test_ipi_switch();
	SPIN();
	return;
}