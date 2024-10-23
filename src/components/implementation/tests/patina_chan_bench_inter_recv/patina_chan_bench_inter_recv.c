/*
 * Copyright 2020, Bite Ye, Runyu Pan and Gabriel Parmer, GWU, gparmer@gwu.edu.
 *
 * This uses a two clause BSD License.
 */

#include <cos_component.h>
#include <llprint.h>
#include <cos_time.h>
#include <patina.h>
#include <ps.h>
#include <perfdata.h>

#undef CHAN_TRACE_DEBUG
#ifdef CHAN_TRACE_DEBUG
#define debug(format, ...) printc(format, ##__VA_ARGS__)
#else
#define debug(format, ...)
#endif

patina_chan_s_t sid;
patina_chan_r_t rid;
patina_event_t  evt;

/* Keep these settings below consistent with the sender side */
#undef USE_EVTMGR

#define TEST_CHAN_ITEM_SZ sizeof(u32_t)
#define TEST_CHAN_NSLOTS 2
#define TEST_CHAN_SEND_ID 3
#define TEST_CHAN_RECV_ID 4
#define TEST_CHAN_PRIO_SELF 4

typedef unsigned int cycles_32_t;

int
main(void)
{
	cycles_t    wakeup;
	cycles_32_t tmp;
#ifdef USE_EVTMGR
	evt_res_id_t   evt_id;
	evt_res_data_t evtdata;
	evt_res_type_t evtsrc;
#endif

	printc("Component chan receiver: executing main.\n");

	/* See if event manager is in use. If yes, log the receiver channel into it */
#ifdef USE_EVTMGR
	patina_event_create(&evt, 1);
	patina_event_add(&evt, rid, 0);
	printc("Receiver side event created.\n");
#endif

	/*
	 * This sleep in both hi and lo comps lets the benchmark run
	 * more predictably on HW and on Qemu.
	 *
	 * Likely because this helps the priority change in cos_init take effect!
	 * Or because this lets the initialization of both ends of channels complete before tests start!
	 */
	wakeup = time_now() + time_usec2cyc(1000 * 1000);
	sched_thd_block_timeout(0, wakeup);

	/* Never stops running; sender controls how many iters to run. */
	while (1) {
		debug("r1,");
#ifdef USE_EVTMGR
		/* Receive from the events then the channel */
		while (patina_channel_recv(rid, &tmp, 1, CHAN_NONBLOCKING) == CHAN_TRY_AGAIN)
			patina_event_wait(&evt, NULL, 0);
#else
		patina_channel_recv(rid, &tmp, 1, 0);
#endif
		debug("tsr1: %d,", tmp);
		debug("r2,");
		tmp = time_now();
		debug("tsr2: %d,", tmp);
		debug("r3,");
		patina_channel_send(sid, &tmp, 1, 0);
		debug("r4,");
	}
}


/* We initialize channel and threads before executing main - here the scheduler doesn't even work so we guarantee good
 * init */
void
cos_init(void)
{
	printc("Component chan receiver initializing:\n\tCreate channel %d\n", TEST_CHAN_SEND_ID);
	sid = patina_channel_retrieve_send(TEST_CHAN_ITEM_SZ, TEST_CHAN_NSLOTS, TEST_CHAN_SEND_ID);

	printc("\tCreate channel %d\n", TEST_CHAN_RECV_ID);
	rid = patina_channel_retrieve_recv(TEST_CHAN_ITEM_SZ, TEST_CHAN_NSLOTS, TEST_CHAN_RECV_ID);

	printc("\tPriority %d for self!\n", TEST_CHAN_PRIO_SELF);
	if (sched_thd_param_set(cos_thdid(), sched_param_pack(SCHEDP_PRIO, TEST_CHAN_PRIO_SELF))) {
		printc("sched_thd_param_set failed.\n");
		assert(0);
	}
}
