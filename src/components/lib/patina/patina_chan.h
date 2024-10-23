#ifndef PATINA_CHAN_H
#define PATINA_CHAN_H

#include <cos_types.h>
#include <chan.h>

#define PATINA_MAX_NUM_CHAN 32

typedef size_t patina_chan_t;
typedef size_t patina_chan_s_t;
typedef size_t patina_chan_r_t;

struct patina_channel_status;

patina_chan_t   patina_channel_create(size_t type_size, size_t queue_length, int ch_name, size_t flags);
patina_chan_r_t patina_channel_get_recv(patina_chan_t cid);
patina_chan_s_t patina_channel_get_send(patina_chan_t cid);
patina_chan_r_t patina_channel_retrieve_recv(size_t type_size, size_t queue_length, int ch_name);
patina_chan_s_t patina_channel_retrieve_send(size_t type_size, size_t queue_length, int ch_name);
int             patina_channel_close(size_t cid);
int             patina_channel_destroy(patina_chan_t cid);
int             patina_channel_send(patina_chan_s_t scid, void *data, size_t len, size_t flags);
int             patina_channel_recv(patina_chan_r_t rcid, void *buf, size_t len, size_t flags);
int             patina_channel_get_status(size_t cid, struct patina_channel_status *status);

#endif
