#ifndef PATINA_TIMER_H
#define PATINA_TIMER_H

#include <cos_types.h>
#include <patina_evt.h>
#include <tmr.h>

#define PATINA_MAX_NUM_TIMER 32

typedef size_t patina_timer_t;

struct patina_tmr {
	struct tmr      tmr;
	patina_event_t *eid;
};

/**
 * Time struct
 * hold time in sec + usec format
 */
typedef struct time {
	u64_t sec;
	u32_t usec;
} patina_time_t;

void           patina_time_current(struct time *result);
void           patina_time_create(struct time *a, u64_t sec, u32_t usec);
int            patina_time_add(struct time *a, struct time *b);
int            patina_time_sub(struct time *a, struct time *b);
u32_t          patina_timer_precision();
patina_timer_t patina_timer_create();
int            patina_timer_start(patina_timer_t tid, struct time *time);
int            patina_timer_periodic(patina_timer_t tid, struct time *offset, struct time *period);
int            patina_timer_cancel(patina_timer_t tid);
int            patina_timer_free(patina_timer_t tid);

#endif
