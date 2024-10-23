/**
 * Redistribution of this file is permitted under the BSD two clause license.
 *
 * Copyright 2020, The George Washington University
 * Author: Bite Ye, bitye@gwu.edu
 */

#include <cos_time.h>
#include <llprint.h>
#include <patina_timer.h>
#include <patina_types.h>
#include <static_slab.h>

/**
 * This is a wrapper of patina's native tmr lib.
 * For detail API usage guide, please check source codes
 * under 'src/components/lib/tmr/'
 */

SS_STATIC_SLAB(patina_tmr, struct patina_tmr, PATINA_MAX_NUM_TIMER);

/**
 * Get current time (in sec + usec format)
 *
 * Arguments:
 * - @result: time struct (see 'patina_timer.h')
 *
 * @return void
 */
void
patina_time_current(struct time *result)
{
	assert(result);

	u64_t time_now = time_now_usec();

	result->sec  = time_now / (1000 * 1000);
	result->usec = time_now % (1000 * 1000);

	return;
}

/**
 * Create a time struct
 *
 * Arguments:
 * - @a: time struct
 * - @sec: seconds
 * - @usec: micro seconds
 *
 * @return void
 */
void
patina_time_create(struct time *a, u64_t sec, u32_t usec)
{
	assert(a);

	a->sec  = sec;
	a->usec = usec;
}

/**
 * Add some time to a time struct
 *
 * Arguments:
 * - @a: the target time struct
 * - @b: how many time client wants to add
 *
 * @return always success
 */
int
patina_time_add(struct time *a, struct time *b)
{
	assert(a && b);
	assert(!(a->sec + b->sec < a->sec || a->usec + b->usec < a->usec));

	a->sec = a->sec + b->sec;
	a->usec  = a->usec + b->usec;

	return 0;
}

/**
 * Subtract some time from a time struct
 *
 * Arguments:
 * - @a: the target time struct
 * - @b: how many time client wants to subtract
 *
 * @return always success
 */
int
patina_time_sub(struct time *a, struct time *b)
{
	assert(a && b);
	assert(!(a->sec - b->sec > a->sec || a->usec - b->usec > a->usec));

	a->sec = a->sec - b->sec;
	a->usec  = a->usec - b->usec;

	return 0;
}

/* CURRENTLY NOT SUPORTTED! */
u32_t
patina_timer_precision()
{
	assert(0);

	return 0;
}

/**
 * Create a timer
 *
 * @return return id of the timer
 */
patina_timer_t
patina_timer_create()
{
	struct patina_tmr *t = ss_patina_tmr_alloc();
	assert(t);

	t->eid = NULL;

	patina_timer_t tid = (patina_timer_t)t | PATINA_T_TIMER;

	return tid;
}

/**
 * Start a timer (one-shot)
 *
 * Arguments:
 * - @tid: id of the timer
 * - @time: delay time
 *
 * @return always success
 */
int
patina_timer_start(patina_timer_t tid, struct time *time)
{
	assert(tid && time);
	struct patina_tmr *t = (struct patina_tmr *)(tid & PATINA_T_MASK);

	assert(!tmr_init(&t->tmr, (time->sec * 1000 * 1000) + time->usec - time_now_usec(), TMR_ONESHOT));

	if (t->eid) {
		evt_res_id_t id = evt_add((struct evt *)t->eid, 0, 0);
		tmr_evt_associate(&t->tmr, id);
	}

	assert(!tmr_start(&t->tmr));

	return 0;
}

/**
 * Start a timer (periodic)
 *
 * Arguments:
 * - @tid: id of the timer
 * - @offset: offset time to the first trigger
 * - @period: period of the timer
 *
 * @return always success
 */
int
patina_timer_periodic(patina_timer_t tid, struct time *offset, struct time *period)
{
	struct patina_tmr *t = (struct patina_tmr *)(tid & PATINA_T_MASK);

	assert(!tmr_init(&t->tmr, (period->sec * 1000 * 1000) + period->usec, TMR_PERIODIC));

	if (t->eid) {
		evt_res_id_t id = evt_add((struct evt *)t->eid, 0, 0);
		tmr_evt_associate(&t->tmr, id);
	}

	assert(!tmr_start(&t->tmr));

	return 0;
}


/**
 * Cancel a timer
 *
 * Arguments:
 * - @tid: id of the timer
 *
 * @return return 'tmr_stop's return
 */
int
patina_timer_cancel(patina_timer_t tid)
{
	return tmr_stop(&(((struct patina_tmr *)(tid & PATINA_T_MASK))->tmr));
}

/* CURRENTLY NOT SUPPORTED! */
int
patina_timer_free(patina_timer_t tid)
{
	assert(0);

	return 0;
}
