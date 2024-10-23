/**
 * Redistribution of this file is permitted under the BSD two clause license.
 *
 * Copyright 2020, The George Washington University
 * Author: Bite Ye, bitye@gwu.edu
 */

#include <llprint.h>
#include <patina_chan.h>
#include <patina_types.h>
#include <static_slab.h>
#include <string.h>

/**
 * This is a wrapper of patina's native channel library.
 * For detail API usage guide, please check source codes
 * under 'src/components/lib/chan'
 */

SS_STATIC_SLAB(chan, struct chan, PATINA_MAX_NUM_CHAN);
SS_STATIC_SLAB(chan_rcv, struct chan_rcv, PATINA_MAX_NUM_CHAN);
SS_STATIC_SLAB(chan_snd, struct chan_snd, PATINA_MAX_NUM_CHAN);

/**
 * Create a channel
 *
 * Currently we only support CHAN_DEFAULT as flag, hence
 * the arugment 'flags' has no effect
 * Also note that name as arugment is not supported.
 *
 * Arguments:
 * - @type_size: size of the item in this channel
 * - @queue_length: size of this channel
 * - @ch_name: no effect
 * - @flags: no effect
 *
 * @return: id of the channel just been created.
 */
patina_chan_t
patina_channel_create(size_t type_size, size_t queue_length, int ch_name, size_t flags)
{
	assert(type_size && queue_length);

	struct chan *c = ss_chan_alloc();
	assert(c);

	assert(chan_init(c, type_size, queue_length, CHAN_DEFAULT) == 0);

	ss_chan_activate(c);

	return (patina_chan_t)c | PATINA_T_CHAN;
}

/**
 * Get recv endpoint of a channel
 *
 * Arguments:
 * - @cid: channel id
 *
 * @return: id of the recv endpoint
 */
patina_chan_r_t
patina_channel_get_recv(patina_chan_t cid)
{
	assert(cid);

	struct chan *    c = (struct chan *)(cid & PATINA_T_MASK);
	struct chan_rcv *r = ss_chan_rcv_alloc();
	assert(r);

	assert(!chan_rcv_init(r, c));

	ss_chan_rcv_activate(r);

	return (patina_chan_r_t)r | PATINA_T_CHAN_R;
}

/**
 * Get send endpoint
 *
 * Arugments:
 * - @cid: channel id
 *
 * @return: id of the send endpoint
 */
patina_chan_s_t
patina_channel_get_send(patina_chan_t cid)
{
	assert(cid);

	struct chan *    c = (struct chan *)(cid & PATINA_T_MASK);
	struct chan_snd *s = ss_chan_snd_alloc();
	assert(s);

	assert(!chan_snd_init(s, c));

	ss_chan_snd_activate(s);

	return (patina_chan_s_t)s | PATINA_T_CHAN_S;
}

/**
 * Get recv endpoint using ch_name (which currently being allocated while booting,
 * see chanmgr for more detail).
 *
 * Arguments:
 * - @type_size: size of the item in this channel
 * - @queue_length: size of the channel
 * - @ch_name: id of the channel
 *
 * @return: id of the recv endpoint
 */
patina_chan_r_t
patina_channel_retrieve_recv(size_t type_size, size_t queue_length, int ch_name)
{
	assert(type_size && queue_length);

	struct chan_rcv *r = ss_chan_rcv_alloc();
	assert(r);

	assert(!chan_rcv_init_with(r, ch_name, type_size, queue_length, CHAN_DEFAULT));

	ss_chan_rcv_activate(r);

	return (patina_chan_s_t)r | PATINA_T_CHAN_R;
}

/**
 * Get send endpoint using ch_name (which currently being allocated while booting,
 * see chanmgr for more detail).
 *
 * Arguments:
 * - @type_size: size of the item in this channel
 * - @queue_length: size of the channel
 * - @ch_name: id of the channel
 *
 * @return: id of the send endpoint
 */
patina_chan_s_t
patina_channel_retrieve_send(size_t type_size, size_t queue_length, int ch_name)
{
	assert(type_size && queue_length);

	struct chan_snd *s = ss_chan_snd_alloc();
	assert(s);

	assert(!chan_snd_init_with(s, ch_name, type_size, queue_length, CHAN_DEFAULT));

	ss_chan_snd_activate(s);

	return (patina_chan_s_t)s | PATINA_T_CHAN_S;
}

/**
 * Close a channel (this func close channel endpoint)
 *
 * Arguments:
 * - @eid: id of the endpoint
 *
 * @return: always success (return 0).
 */
int
patina_channel_close(size_t eid)
{
	assert(eid);

	if ((eid & (~PATINA_T_MASK)) == PATINA_T_CHAN_R) {
		struct chan_rcv *r = (struct chan_rcv *)(eid & PATINA_T_MASK);

		chan_rcv_teardown(r);
		ss_chan_rcv_free(r);
	} else if ((eid & (~PATINA_T_MASK)) == PATINA_T_CHAN_S) {
		struct chan_snd *s = (struct chan_snd *)(eid & PATINA_T_MASK);

		chan_snd_teardown(s);
		ss_chan_snd_free(s);
	}

	return 0;
}

/**
 * Close a channel (close THE channel)
 *
 * Arguments:
 * - @cid: id of the channel
 *
 * @return: always return 0
 */
int
patina_channel_destroy(patina_chan_t cid)
{
	assert(cid);

	struct chan *c = (struct chan *)(cid & PATINA_T_MASK);

	chan_teardown(c);
	ss_chan_free(c);

	return 0;
}

/**
 * Send data through channel
 *
 * For the flags, currently we don't do any translate so please use native chan lib's
 * flags.
 *
 * Arguments:
 * - @scid: id of send endpoint
 * - @len: no effect
 * - @flags: native chan lib's flags
 *
 * @return: return 'chan_send's return
 */
int
patina_channel_send(patina_chan_s_t scid, void *data, size_t len, size_t flags)
{
	assert(scid && data);

	return chan_send((struct chan_snd *)(scid & PATINA_T_MASK), data, (chan_comm_t)flags);
}

/**
 * Receive data through channel
 *
 * For the flags, currently we don't do any translate so please use native chan lib's
 * flags.
 *
 * Arguments:
 * - @scid: id of recv endpoint
 * - @len: no effect
 * - @flags: native chan lib's flags
 *
 * @return: return 'chan_recv's return
 */
int
patina_channel_recv(patina_chan_r_t rcid, void *buf, size_t len, size_t flags)
{
	assert(rcid && buf);

	return chan_recv((struct chan_rcv *)(rcid & PATINA_T_MASK), buf, (chan_comm_t)flags);
}

/* NOT IMPLEMENTED */
int
patina_channel_get_status(size_t cid, struct patina_channel_status *status)
{
	assert(0);
	return 0;
}
