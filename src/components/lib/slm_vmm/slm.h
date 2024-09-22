#ifndef SLM_H
#define SLM_H

#include <cos_component.h>
#include <cos_defkernel_api.h>
#include <ps.h>
#include <ck_ring.h>

/*
 * Simple state machine for each thread
 */
typedef enum {
	SLM_THD_FREE = 0,
	SLM_THD_BLOCKED,
	SLM_THD_WOKEN, /* if a race causes a wakeup before the thread's inevitable block */
	SLM_THD_RUNNABLE,
	SLM_THD_DYING,
} slm_thd_state_t;

typedef enum {
	SLM_THD_PROPERTY_OWN_TCAP  = 1,      /* Thread owns a tcap */
	SLM_THD_PROPERTY_SEND      = (1<<1), /* use asnd to dispatch to this thread */
	SLM_THD_PROPERTY_SUSPENDED = (1<<2), /* suspended on a rcv capability? See note below. */
	SLM_THD_PROPERTY_SPECIAL   = (1<<3), /* is this either the scheduler or idle thread? */
} slm_thd_property_t;

struct event_info {
	int         blocked; /* 1 - blocked. 0 - awake */
	cycles_t    cycles;  /* how many cycles the thread executed */
	tcap_time_t timeout;
};

struct slm_ipi_thd {
	arcvcap_t rcv;
	asndcap_t asnd;
	cpuid_t   cpuid;
	thdid_t   tid;
};

struct slm_ipi_event {
	thdid_t tid;
};

struct slm_ipi_percore {
	struct slm_ipi_thd   ipi_thd;
	struct ck_ring       ring;
	struct slm_ipi_event ringbuf[PAGE_SIZE / sizeof(struct slm_ipi_event)];
} CACHE_ALIGNED;

struct slm_thd {
	/*
	 * rcv_suspended: Tracks the kernel state of the AEP threads for whether they're
	 *                suspended on cos_rcv or not.
	 *		  rcv_suspended is used only for threads that are AEPs (call cos_rcv).
	 *
	 * Activations of these AEP threads cannot be fully controlled by the
	 * scheduler and depends on the global quality of the TCap associated with this
	 * AEP at any point an `asnd` happens to this AEP.
	 *
	 * Therefore, this is really not a thread state that the scheduler controls.
	 * if a thread has rcv_suspended set, it doesn't mean that it isn't running.
	 * But if the thread uses any of `sl` block/yield, this should first be reset and
	 * the thread must be put back to run-queue before doing anything!!
	 *
	 * Another important detail is, when the scheduler receives a "unblocked" event, it
	 * resets this. If rcv_suspended == 0, then the scheduler does not modify the thread states!
	 * This is because, a thread could have run without the scheduler's knowledge through the
	 * tcap mechanism and may have eventually tried to block/acquire a lock/futex
	 * which would then block the thread at user-level. A kernel scheduling event
	 * should not cause it to change to RUNNABLE state and enter a critical section when
	 * it isn't it's turn!
	 *
	 * This is the strongest motivation towards not combining user-level and kernel-level
	 * thread states.
	 *
	 * To sum up:
	 * if rcv_suspended: A thread could "still" be calling block/yield and therefore be
	 *                   in a RUNNABLE/BLOCKED/BLOCKED_TIMEOUT states. It could also be
	 *                   woken up at the user-level if there is another high-prio thread
	 *                   and that gets to run before scheduler is activated up on this
	 *                   thread calls block/yield and it then wakes this thread up.
	 * if !rcv_suspended: A thread could be in any state and also be in cos_rcv.
	 *
	 * The only thing this captures is, "unblocking" a thread from cos_rcv or "blocking" it
	 * on cos_rcv from a scheduler's context. BLOCKing a thread when the scheduler processes
	 * a "blocked" kernel event, clears any prior thread states and sets it to be BLOCKED/BLOCKED_TIMEOUT.
	 */
	slm_thd_property_t properties;
	slm_thd_state_t    state;

	/*
	 * All of the capabilities and kernel-relevant information for
	 * the thread.
	 */
	tcap_t      tc;
	thdcap_t    thd;
	thdid_t     tid;
	arcvcap_t   rcv;
	asndcap_t   asnd;
	tcap_prio_t priority;
	cpuid_t     cpuid;
	int last_yield;
	int block_count;

	/* Execution information retrieved by the scheduler thread */
	struct event_info event_info;
	struct ps_list    thd_list;       /* list of events for the scheduler */
	struct ps_list    graveyard_list; /* list of threads that have terminated that require deallocation */
};

typedef enum {
	SLM_CS_NONE     = 0,
	SLM_CS_NOSPIN   = 1, /* return if we race with another thread */
	SLM_CS_SWITCHTO = 2, /* we should try and switch to the `switchto` argument */
	SLM_CS_SCHEDEVT = 4, /* return if there are pending scheduler notifications */
	SLM_CS_CHECK_TIMEOUT = 8, /* should we check for pending timeouts on exit? */
} slm_cs_flags_t;

static inline cycles_t
slm_now(void)
{
	return ps_tsc();
}

unsigned long slm_get_cycs_per_usec(void);

#include <slm_private.h>

/***
 * The initialization procedure for the slm must include:
 *
 * ```c
 * void
 * cos_parallel_init(...) {
 *         t = thd_allow(slm_idle, ...); // bypass the slm in allocation
 *         slm_init(t->thdcap, t->thdid);
 *         ...
 * }
 *
 * int
 * parallel_main(...) {
 *         ...
 *         slm_sched_loop(); // start processing the scheduler, never return
 * }
 * ```
 */

/*
 * This is the idle function, and should be the function executed by
 * the thread. idle calls `slm_idle_comp_initialization()`, then goes
 * into an infinite loop calling `slm_idle_iteration();` each time.
 * These functions can be defined in other object files, and will be
 * correspondingly invoked. The initialization protocol (`init.c`)
 * overrides the first.
 */
void slm_idle(void *);
void slm_idle_comp_initialization(void);
void slm_idle_iteration(void);



/**
 * This function *must* be called as part of the scheduler
 * initialization, usually as part of `cos_init`. This assumes that
 * the calling thread will become the main scheduling thread, and that
 * it was created with the `defkernel` APIs.
 *
 * - @thd - a thread capability to the *idle thread* that is executing
 *     the `slm_idle` function
 * - @tid - the thread id of the idle thread
 */
void slm_init(thdcap_t thd, thdid_t tid);
/*
 * The initialization thread must execute this (post `slm_init`), and
 * this thread will become the scheduler notification thread that
 * polls the rcv end-point for other thread's activations and
 * suspensions.
 */
void slm_sched_loop(void);
void slm_sched_loop_nonblock(void);
/*
 * Return if the initialization is done *and* the scheduler thread on
 * this core has executed the scheduler loop. All threads should not
 * be activated in the policy (thus runnable) until this has been
 * done.
 */
int slm_init_done(void);
/* After a thread has been initialized, activate it! Calls `slm_thd_sched_update`. */
int slm_thd_commit_updates(struct slm_thd *t);

int  slm_thd_init(struct slm_thd *t, thdcap_t thd, thdid_t tid);
void slm_thd_deinit(struct slm_thd *t);

/* forward declarations, not part of the public API. */
int slm_cs_enter_contention(struct slm_cs *cs, slm_cs_cached_t cached, struct slm_thd *curr, struct slm_thd *owner, int contended, sched_tok_t tok);
int slm_cs_exit_contention(struct slm_cs *cs, struct slm_thd *curr, slm_cs_cached_t cached, sched_tok_t tok);

/**
 * Try to enter into the critical section. There are few ways that
 * this can play out.
 *
 * 1. The lock is not owned by anyone, so we can take it! Use an
 *     atomic instruction to update the value.
 *
 * 2. The lock is owned by another thread. We will try and switch
 *     directly to that thread. This is subtly powerful: it enables us
 *     to implement priority inheritance *regardless which scheduling
 *     policy is used*.
 *
 * 3. We don't see someone owning the lock, *but* we race on updating
 *     the lock to us as the owner, and the other thread wins. Instead
 *     of trying to do option 2 here we return an error so that the
 *     surrounding context can manage the "retries".
 *
 * - @current - The currently active thread that is calling this
 *     function! Note that the liveness is awkward here. How do we
 *     know if the thread's structure is live at this point? Simple:
 *     we're currently executing the thread, so we simply need to
 *     ensure that the `slm_thd` for a thread is live as long as the
 *     thread is live...something that is fairly natural.

 * - @ret - `0` if we have the critical section, `1` if there was a
 *     race on setting the lock, and we lost, `-N` for errors on the
 *     kernel call to switch threads, including `-EAGAIN` if there was
 *     a race on the scheduler token, and `-EBUSY` if we are a
 *     scheduling thread, and there are pending scheduler events.
 */
static inline int
slm_cs_enter(struct slm_thd *current, slm_cs_flags_t flags)
{
	struct slm_cs  *cs;
	slm_cs_cached_t cached;
	sched_tok_t     tok;
	struct slm_thd  *owner;
	int             contended;

	assert(current);
	cs = &(slm_global()->lock);

	while (1) {
		tok    = cos_sched_sync();
		cached = __slm_cs_data(cs, &owner, &contended);

		if (unlikely(owner)) {
			int ret;

			ret = slm_cs_enter_contention(cs, cached, current, owner, contended, tok);
			/* does the caller want to be notified of pending scheduler events? */
			if (flags & SLM_CS_SCHEDEVT && ret == -EBUSY) return ret;
			assert(ret != -EBUSY);
			if (flags & SLM_CS_NOSPIN) return ret;

			continue;
		}

		/* success! common case */
		if (likely(!__slm_cs_cas(cs, cached, current, 0))) return 0;
		if (flags & SLM_CS_NOSPIN) return 1;
	}
}

/*
 * Release the scheduler critical section, switch to the scheduler
 * thread if there is pending contention.
 *
 * Assume: the owner of the critical section is the same thread that
 * calls `slm_cs_exit`.
 *
 * TODO: use `switchto`
 */
static inline void
slm_cs_exit(struct slm_thd *switchto, slm_cs_flags_t flags)
{
	int ret = 1;
	struct slm_cs *cs = &(slm_global()->lock);

	while (ret != 0) {
		int             contention;
		sched_tok_t     tok;
		slm_cs_cached_t cached;
		struct slm_thd *current;

		tok    = cos_sched_sync();
		cached = __slm_cs_data(cs, &current, &contention);
		/* Another thread attempted to enter the critical section */
		if (unlikely(contention)) {
			if (!slm_cs_exit_contention(cs, current, cached, tok)) return;

			continue; /* we couldn't update the CS variable, try again */
		}

		/* The common case: release lock, no-one waiting for it */
		ret = __slm_cs_cas(cs, cached, NULL, 0);
		if (flags & SLM_CS_NOSPIN) return;
		if (flags & SLM_CS_SCHEDEVT && ret == -EBUSY) return;
	}

	return;
}

static inline int slm_cs_exit_reschedule(struct slm_thd *curr, slm_cs_flags_t flags);

/**
 * `slm_switch_to` attempts to perform scheduler bypass and switch
 * directly to the specified thread. This is pretty unsafe, in
 * general. There is no critical section, and it bypasses all
 * scheduling decisions. As we bypass scheduling decisions, we must
 * decide with which priority we want to execute: the current
 * thread's, or the next's. Thus, the `inherit_prio` value selects if
 * the switched-to thread inherits this thread's priority.
 *
 * This function is mainly useful in defining scheduling fast-paths
 * for communication between different threads. Though Composite IPC
 * is very fast, IPC between threads has the overhead of component
 * invocation, scheduling, and dispatch. Slite gets rid of the latter,
 * and this effectively gets rid of the scheduling overhead.
 *
 * *Synchronization*: `tok` is passed as an argument enabling some
 * limited synchronization as the surrounding context can access
 * data-structures after taken the token, and the thread switch will
 * be prevented if context switches happened in the mean-time.
 *
 * - `curr` - the current thread, only used when inheriting priority
 * - `to` - thread to switch to
 * - `tok` - the scheduler token, passed from the caller
 * - `inherit_prio` - should `to` inherit `curr`'s priority?
 */
static inline int
slm_switch_to(struct slm_thd *curr, struct slm_thd *to, sched_tok_t tok, int inherit_prio)
{
	if (unlikely(!slm_state_is_runnable(to->state))) return 1;

	return slm_thd_activate(curr, to, tok, inherit_prio);
}

int slm_thd_block(struct slm_thd *t);
int slm_thd_wakeup(struct slm_thd *t, int redundant);

/***
 * The `slm` time API. Unfortunately, three times are used in the
 * system:
 *
 * 1. cycles which are the finest-granularity, and are accessed with
 *    the least overhead (using direct instructions).
 * 2. microseconds (usec), which are an intuitive time unit with which
 *    users specify time. Relatively expensive to convert to and from
 *    (requiring general multiplication and division.
 * 3. tcap "ticks" which are some multiple of a cycle which are quick
 *    to convert to and from.
 *
 * `slm` simply tries to hide tcap times, and interfaces with timer
 * policy using only cycles. The conversion functions to and from
 * microseconds are provided here for that policy to use, should it
 * need it.
 */

static inline microsec_t
slm_cyc2usec(cycles_t cyc)
{
	return cyc / slm_global()->cyc_per_usec;
}

static inline cycles_t
slm_usec2cyc(microsec_t usec)
{
	return usec * slm_global()->cyc_per_usec;
}

/***
 * Simple timeout API to enable the timer module to set and remove
 * timeouts. Must be used with the scheduler's critical section taken.
 */
static inline void
slm_timeout_set(cycles_t timeout)
{
	struct slm_global *g = slm_global();

	g->timeout_next = tcap_cyc2time(timeout);
	g->timer_next   = timeout;
	g->timer_set    = 1;
}

static inline void
slm_timeout_clear(void)
{
	slm_global()->timer_set = 0;
}

#define SLM_IPI_THD_PRIO 20

int slm_ipi_event_enqueue(struct slm_ipi_event *event, cpuid_t id);
int slm_ipi_event_dequeue(struct slm_ipi_event *event, cpuid_t id);
int slm_ipi_event_empty(cpuid_t id);
struct slm_ipi_percore *slm_ipi_percore_get(cpuid_t id);

#endif	/* SLM_H */
