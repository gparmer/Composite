/**
 * Redistribution of this file is permitted under the BSD two clause license.
 *
 * Copyright 2020, The George Washington University
 * Author: Bite Ye, bitye@gwu.edu
 */

#include <llprint.h>
#include <patina_evt.h>
#include <patina_timer.h>
#include <patina_types.h>
#include <string.h>

/**
 * This is a wrapper of patina's native evt interface.
 * For detail API usage guide, please check source codes
 * under 'src/components/interface/evt.h'
 */

/**
 * Create a event
 *
 * Arguments:
 * - @eid: id of the event (a struct, see 'patina_evt.h')
 * - @n_sources: number of sources can be hold in this event
 *
 * @return id of the event
 */
int
patina_event_create(patina_event_t *eid, uint32_t n_sources)
{
	assert(eid && n_sources);

	return evt_init((struct evt *)eid, n_sources);
}


/**
 * Add a source to a event
 *
 * Currently we don't support any flags
 *
 * Arguments:
 * - @eid: id of the event
 * - @src: id of the source
 * - @flags: no effect
 *
 * @return always return 0 for timer and return corresponding native APIs' returns for others
 */
int
patina_event_add(patina_event_t *eid, size_t src, size_t flags)
{
	assert(eid && src);

	evt_res_id_t id;

	if (!eid || !src) { return -1; }

	id = evt_add((struct evt *)eid, 0, 0);
	assert(id);

	if ((src & (~PATINA_T_MASK)) == PATINA_T_TIMER) {
		((struct patina_tmr *)(src & PATINA_T_MASK))->eid = eid;
		return 0;
	}

	if ((src & (~PATINA_T_MASK)) == PATINA_T_CHAN) {
		return chan_evt_associate((struct chan *)(src & PATINA_T_MASK), id);
	}

	if ((src & (~PATINA_T_MASK)) == PATINA_T_CHAN_R) {
		return chan_rcv_evt_associate((struct chan_rcv *)(src & PATINA_T_MASK), id);
	}

	if ((src & (~PATINA_T_MASK)) == PATINA_T_CHAN_S) {
		return chan_snd_evt_associate((struct chan_snd *)(src & PATINA_T_MASK), id);
	}

	assert(0);
}

/**
 * Remove a source from a event
 *
 * Arguments:
 * - @eid: id of the event
 * - @src: id of the source
 * - @flags: no effect
 *
 * @return return native APIs' returns
 */
int
patina_event_remove(patina_event_t *eid, size_t src, size_t flags)
{
	assert(eid && src);

	evt_res_id_t id = 0;

	if (!eid || !src) { return -1; }

	if ((src & (~PATINA_T_MASK)) == PATINA_T_TIMER) {
		id = tmr_evt_associated((struct tmr *)(src & PATINA_T_MASK));
		tmr_evt_disassociate((struct tmr *)(src & PATINA_T_MASK));
	}

	if ((src & (~PATINA_T_MASK)) == PATINA_T_CHAN) {
		id = chan_evt_associated((struct chan *)(src & PATINA_T_MASK));
		chan_evt_disassociate((struct chan *)(src & PATINA_T_MASK));
	}

	if ((src & (~PATINA_T_MASK)) == PATINA_T_CHAN_R) {
		id = chan_rcv_evt_associated((struct chan_rcv *)(src & PATINA_T_MASK));
		chan_rcv_evt_disassociate((struct chan_rcv *)(src & PATINA_T_MASK));
	}

	if ((src & (~PATINA_T_MASK)) == PATINA_T_CHAN_S) {
		id = chan_snd_evt_associated((struct chan_snd *)(src & PATINA_T_MASK));
		chan_snd_evt_disassociate((struct chan_snd *)(src & PATINA_T_MASK));
	}

	return evt_rem((struct evt *)eid, id);
}

/**
 * Delete a event
 *
 * Arguments:
 * - @eid: id of the event
 *
 * @return return 'evt_teardown's return
 */
int
patina_event_delete(patina_event_t *eid)
{
	assert(eid);

	return evt_teardown((struct evt *)eid);
}

/**
 * Wait on a event (blocking)
 *
 * Arguments:
 * @param eid: id of the event
 * @return return 'evt_get's return
 */
int
patina_event_wait(patina_event_t *eid, struct patina_event_info events[], size_t num)
{
	assert(eid);

	word_t tmp;

	return evt_get((struct evt *)eid, EVT_WAIT_DEFAULT, &tmp, &tmp);
}

/**
 * Check on a event (non-blocking)
 *
 * Arguments:
 * - @eid: id of the event
 * - @events: holder of event info (an array, allow batching)
 * - @num: number of events client wants
 *
 * @return return 'evt_get's return
 */
int
patina_event_check(patina_event_t *eid, struct patina_event_info events[], size_t num)
{
	assert(eid);

	word_t tmp;

	return evt_get((struct evt *)eid, EVT_WAIT_NONBLOCKING, &tmp, &tmp);
}

/**
 * DEBUG usage
 */
evt_res_id_t
patina_event_debug_fake_add(patina_event_t *eid)
{
	assert(eid);

	return evt_add((struct evt *)eid, 0, 0);
}

/**
 * DEBUG usage
 */
int
patina_event_debug_trigger(evt_res_id_t rid)
{
	assert(rid);

	return evt_trigger(rid);
}
