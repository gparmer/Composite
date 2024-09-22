#ifndef SLM_PRIVATE_H
#define SLM_PRIVATE_H

#include <cos_component.h>
#include <ps.h>
#include <slm_api.h>

typedef unsigned long slm_cs_cached_t;
/* Critical section (cs) API to protect scheduler data-structures */
struct slm_cs {
	unsigned long owner_contention;
};

static inline int
slm_state_is_runnable(slm_thd_state_t s)
{ return s == SLM_THD_RUNNABLE || s == SLM_THD_WOKEN; }

static inline int
slm_state_is_dead(slm_thd_state_t s)
{ return s == SLM_THD_FREE || s == SLM_THD_DYING; }

extern struct slm_thd *nf_rx_table[256];

/**
 * Get the metadata about the critical section (CS). This includes the
 * owner thread (or `NULL`), and if the CS has been contended by another
 * thread.
 *
 * - @cs - the critical section
 * - @thd - the *returned* owner thread or `NULL`
 * - @contention - {`0`, `1`} depending on if there is contention
 * - @ret - a *cached* version of the critical section metadata to be passed into `__slm_cs_cas`.
 */
static inline slm_cs_cached_t
__slm_cs_data(struct slm_cs *cs, struct slm_thd **thd, int *contention)
{
	unsigned long oc = ps_load(&cs->owner_contention);
	/* least significant bit signifies contention */
	*thd        = (struct slm_thd *)(oc & (~0UL << 1));
	*contention = oc & 1;

	return oc;
}

/**
 * Update the critical section atomically using compare-and-swap.
 * `cached` was returned from `__slm_cs_data`.
 *
 * - @cs - the critical section
 * - @cached - the previous value of the critical section
 * - @thd - thread owning the critical section or NULL
 * - @contention - must be in {`0`, `1`} -- denotes if we want the
 *                 contention bit to be set.
 * - @ret - `0` on success to update the cs, `1` on failure
 */
static inline int
__slm_cs_cas(struct slm_cs *cs, slm_cs_cached_t cached, struct slm_thd *thd, int contention)
{
	return !ps_cas(&cs->owner_contention, (unsigned long)cached, ((unsigned long)thd | !!contention));
}

struct slm_global {
	struct slm_cs lock;

	struct slm_thd sched_thd;
	struct slm_thd idle_thd;

	int         cyc_per_usec;
	int         timer_set; 	  /* is the timer set? */
	cycles_t    timer_next;	  /* ...what is it set to? */
	tcap_time_t timeout_next; /* ...and what is the tcap representation? */

	struct ps_list_head event_head;     /* all pending events for sched end-point */
	struct ps_list_head graveyard_head; /* all deinitialized threads */
} CACHE_ALIGNED;

/*
 * Simply retrieve this core's global data-structures.
 */
static inline struct slm_global *
slm_global(void)
{
	extern struct slm_global __slm_global[NUM_CPU];

	return &__slm_global[cos_coreid()];
}

/*
 * Return if the given thread is normal, i.e. not the idle thread nor
 * the scheduler thread.
 */
static inline int
slm_thd_normal(struct slm_thd *t)
{
	struct slm_global *g = slm_global();

	return t != &g->idle_thd && t != &g->sched_thd;
}

/*
 * If the current thread is the scheduler or idle thread, return that
 * slm_thd. That thread should generally never be used
 */
struct slm_thd *slm_thd_special(void);

static inline int
slm_thd_activate(struct slm_thd *curr, struct slm_thd *t, sched_tok_t tok, int inherit_prio)
{
	struct cos_defcompinfo *dci = cos_defcompinfo_curr_get();
	struct cos_compinfo    *ci  = &dci->ci;
	struct slm_global      *g   = slm_global();
	tcap_prio_t             prio;
	tcap_time_t             timeout;
	int                     ret = 0;

	timeout = g->timeout_next;
	prio = inherit_prio ? curr->priority : t->priority;

	if (unlikely(t->properties & (SLM_THD_PROPERTY_SEND | SLM_THD_PROPERTY_OWN_TCAP | SLM_THD_PROPERTY_SPECIAL))) {
		if (t == &g->sched_thd) {
			timeout = TCAP_TIME_NIL;
			prio    = curr->priority;
		}
		if (t->properties & SLM_THD_PROPERTY_SEND) {
			return cos_sched_asnd(t->asnd, g->timeout_next, g->sched_thd.rcv, tok);
		} else if (t->properties & SLM_THD_PROPERTY_OWN_TCAP) {
			return cos_switch(t->thd, t->tc, prio, timeout, g->sched_thd.rcv, tok);
		}
	}
	ret = cos_defswitch(t->thd, prio, timeout, tok);

	if (unlikely(ret == -EPERM && !slm_thd_normal(t))) {
		/*
		 * Attempting to activate scheduler thread or idle
		 * thread failed for no budget in it's tcap. Force
		 * switch to the scheduler with current tcap.
		 */
		ret = cos_switch(g->sched_thd.thd, 0, curr->priority, TCAP_TIME_NIL, g->sched_thd.rcv, tok);
	}

	return ret;
}

static inline void slm_cs_exit(struct slm_thd *switchto, slm_cs_flags_t flags);
static inline int slm_cs_enter(struct slm_thd *current, slm_cs_flags_t flags);
/*
 * Do a few things: 1. call schedule to find the next thread to run,
 * 2. release the critical section (note this will cause visual
 * asymmetries in your code if you call slm_cs_enter before this
 * function), and 3. switch to the given thread. It hides some races,
 * and details that would make this difficult to write repetitively.
 *
 * Preconditions: if synchronization is required with code before
 * calling this, you must call slm_cs_enter before-hand (this is likely
 * a typical case).
 *
 * Return: the return value from cos_switch.  The caller must handle
 * this value correctly.
 *
 * A common use-case is:
 *
 * slm_cs_enter(...);
 * scheduling_stuff()
 * slm_cs_exit_reschedule(...);
 *
 * ...which correctly handles any race-conditions on thread selection and
 * dispatch.
 */
static inline int
slm_cs_exit_reschedule(struct slm_thd *curr, slm_cs_flags_t flags)
{
	struct cos_compinfo    *ci  = &cos_defcompinfo_curr_get()->ci;
	struct slm_global      *g   = slm_global();
	struct slm_thd         *t;
	sched_tok_t             tok;
	int                     ret;

try_again:
	tok  = cos_sched_sync();
	if (flags & SLM_CS_CHECK_TIMEOUT && g->timer_set) {
		cycles_t now = slm_now();

		/* Do we need to recompute the timer? */
		if (!cycles_greater_than(g->timer_next, now)) {
			g->timer_set = 0;
			/* The timer policy will likely reset the timer */
			slm_timer_expire(now);
		}
	}

	/* Make a policy decision! */
	t = slm_sched_schedule();
	if (unlikely(!t)) t = &g->idle_thd;

	if (nf_rx_table[t->tid] == t) {
		if (t->last_yield == 1) {
			t->last_yield = 0;
		} else {
			if (t->block_count++ > 5) {
				t->block_count = 0;
			} else {
				t = slm_sched_schedule();
				if (unlikely(!t)) t = &g->idle_thd;
			}
		}
	}

	assert(slm_state_is_runnable(t->state));
	slm_cs_exit(NULL, flags);

	ret = slm_thd_activate(curr, t, tok, 0);
	
	if (unlikely(ret != 0)) {
		/* Assuming only the single tcap with infinite budget...should not get EPERM */
		assert(ret != -EPERM);
		assert(ret != -EINVAL);

		/*
		 * If the slm_thd_activate returns -EBUSY, this means we are trying to switch to the scheduler thread,
		 * and scheduler thread still has pending events. Directly return to process pending events.
		 */
		if (ret == -EBUSY) return ret;
		/* If the slm_thd_activate returns -EAGAIN, this means this scheduling token is outdated, try again */
		assert(ret == -EAGAIN);
		slm_cs_enter(curr, SLM_CS_NONE);
		goto try_again;
	}

	return ret;
}

#endif	/* SLM_PRIVATE_H */
