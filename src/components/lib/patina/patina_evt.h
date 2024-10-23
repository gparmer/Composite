#ifndef PATINA_EVT_H
#define PATINA_EVT_H

#include <cos_types.h>
#include <evt.h>
#include <tmr.h>
#include <chan.h>
#include <stdint.h>

#define PATINA_MAX_NUM_EVT 32

typedef struct evt patina_event_t;

struct patina_event_info {
	size_t event_src_id;
	size_t event_type;
};

int patina_event_create(patina_event_t *eid, uint32_t n_sources);
int patina_event_add(patina_event_t *eid, size_t src, size_t flags);
int patina_event_remove(patina_event_t *eid, size_t src, size_t flags);
int patina_event_delete(patina_event_t *eid);
int patina_event_wait(patina_event_t *eid, struct patina_event_info events[], size_t num);
int patina_event_check(patina_event_t *eid, struct patina_event_info events[], size_t num);

evt_res_id_t patina_event_debug_fake_add(patina_event_t *eid);
int          patina_event_debug_trigger(evt_res_id_t rid);

#endif
