#include <cos_types.h>
#include <cos_component.h>
#include <slm.h>
#include <quantum.h>
#include <slm_api.h>
#include <heap.h>

/***
 * Quantum-based time management. Wooo. Periodic timer FTW.
 */

struct timer_global {
	struct heap  h;
	void        *data[MAX_NUM_THREADS];
	cycles_t     period;
	cycles_t     current_timeout;
} CACHE_ALIGNED;

static struct timer_global __timer_globals[NUM_CPU];

static inline struct timer_global *
timer_global(void) {
	return &__timer_globals[cos_coreid()];
}

/* wakeup any blocked threads! */
static void
quantum_wakeup_expired(cycles_t now)
{
	struct timer_global *g = timer_global();

	while (heap_size(&g->h) > 0) {
		struct slm_thd *tp, *th;
		struct slm_timer_thd *tt;

		/* Should we wake up the closest-timeout thread? */
		tp = heap_peek(&g->h);
		assert(tp);
		tt = slm_thd_timer_policy(tp);
		assert(tt && tt->timeout_idx > 0);

		/* No more threads to wake! */
		if (cycles_greater_than(tt->abs_wakeup, now)) break;

		/* Dequeue thread with closest wakeup */
		th = heap_highest(&g->h);
		assert(th == tp);

		tt->timeout_idx = -1;
		tt->abs_wakeup  = now;
		slm_thd_wakeup(th, 1);
	}
}

/* The timer expired */
void
slm_timer_quantum_expire(cycles_t now)
{
	struct timer_global *g = timer_global();
	cycles_t             offset;
	cycles_t             next_timeout;

	/*
	 * Note that we might miss specific quantum if we are in a
	 * virtualized environment. Thus we might be multiple periods
	 * into the future.
	 */
	assert(now >= g->current_timeout);

	offset = (now - g->current_timeout) % g->period;
 	assert(g->period > offset);
	next_timeout = now + (g->period - offset);
	assert(next_timeout > now);

	slm_timeout_set(next_timeout);
	g->current_timeout = next_timeout;

	quantum_wakeup_expired(now);
}

/*
 * Timeout and wakeup functionality
 *
 * TODO: Replace the in-place heap with a rb-tree to avoid external, static allocation.
 */

int
slm_timer_quantum_add(struct slm_thd *t, cycles_t absolute_timeout)
{
	struct slm_timer_thd *tt = slm_thd_timer_policy(t);
	struct timer_global *g = timer_global();

	assert(tt && tt->timeout_idx == -1);
	assert(heap_size(&g->h) < MAX_NUM_THREADS);

	tt->abs_wakeup = absolute_timeout;
	heap_add(&g->h, t);

	return 0;
}

int
slm_timer_quantum_cancel(struct slm_thd *t)
{
	struct slm_timer_thd *tt = slm_thd_timer_policy(t);
	struct timer_global *g   = timer_global();

	if (tt->timeout_idx == -1) return 0;

	assert(heap_size(&g->h));
	assert(tt->timeout_idx > 0);

	heap_remove(&g->h, tt->timeout_idx);
	tt->timeout_idx = -1;

	return 0;
}

int
slm_timer_quantum_thd_init(struct slm_thd *t)
{
	struct slm_timer_thd *tt = slm_thd_timer_policy(t);

	*tt = (struct slm_timer_thd){
		.timeout_idx = -1,
		.abs_wakeup  = 0
	};

	return 0;
}

void
slm_timer_quantum_thd_deinit(struct slm_thd *t)
{
	return;
}

static int
__slm_timeout_compare_min(void *a, void *b)
{
	/* FIXME: logic for wraparound in either timeout_cycs */
	return slm_thd_timer_policy((struct slm_thd *)a)->abs_wakeup <= slm_thd_timer_policy((struct slm_thd *)b)->abs_wakeup;
}

static void
__slm_timeout_update_idx(void *e, int pos)
{ slm_thd_timer_policy((struct slm_thd *)e)->timeout_idx = pos; }

static void
slm_policy_timer_init(microsec_t period)
{
	struct timer_global *g = timer_global();
	cycles_t next_timeout;

	memset(g, 0, sizeof(struct timer_global));
	g->period = slm_usec2cyc(period);
	heap_init(&g->h, MAX_NUM_THREADS, __slm_timeout_compare_min, __slm_timeout_update_idx);

	next_timeout = slm_now() + g->period;
	g->current_timeout = next_timeout;
	slm_timeout_set(next_timeout);
}

int
slm_timer_quantum_init(void)
{
	slm_policy_timer_init(200);

	return 0;
}
