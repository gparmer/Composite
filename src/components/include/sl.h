/**
 * Redistribution of this file is permitted under the BSD two clause license.
 *
 * Copyright 2017, The George Washington University
 * Author: Gabriel Parmer, gparmer@gwu.edu
 */

/*
 * Scheduler library (sl) abstractions and functions.
 *
 * This library does a few things:
 * 1. hide the esoteric nature of the cos_kernel_api's dispatch
 *    methods, and the scheduler event notifications + scheduler
 *    thread,
 * 2. provide synchronization around scheduler data-strutures, and
 * 3. abstract shared details about thread blocking/wakeup, lookup,
 *    and inter-thread dependency management.
 *
 * This library interacts with a number of other libraries/modules.
 *
 * - uses: dispatching functions in the cos_kernel_api (which uses,
 *   the kernel system call layer)
 * - uses: parsec (ps) for atomic instructions and synchronization
 * - uses: memory allocation functions provided by a run-time (either
 *   management of static memory, or something like parsec)
 * - uses: scheduler modules that implement the scheduling policy
 *
 */

#ifndef SL_H
#define SL_H

#include <cos_defkernel_api.h>
#include <ps.h>
#include <res_spec.h>
#include <sl_mod_policy.h>
#include <sl_plugins.h>
#include <sl_thd.h>
#include <sl_consts.h>
#include <sl_xcore.h>
#include <heap.h>
#include <cos_ulsched_rcv.h>

#define SL_CS
#define SL_REPLENISH
#undef SL_PARENTCHILD

/* Critical section (cs) API to protect scheduler data-structures */
struct sl_cs {
	union sl_cs_intern {
		struct {
			thdcap_t owner : 31;
			u32_t    contention : 1;
		} PS_PACKED   s;
		unsigned long v;
	} u;
};

struct sl_global_core {
	struct sl_cs lock;

	thdcap_t       sched_thdcap;
	tcap_t         sched_tcap;
	arcvcap_t      sched_rcv;
	struct sl_thd *sched_thd;
	struct sl_thd *idle_thd;

	int         cyc_per_usec;
	cycles_t    period;
	cycles_t    timer_next, timer_prev;
	tcap_time_t timeout_next;

	struct cos_scb_info *scb_info;
	struct ps_list_head event_head; /* all pending events for sched end-point */
};

extern struct sl_global_core sl_global_core_data[];

typedef u32_t sched_blkpt_id_t;
#define SCHED_BLKPT_NULL 0
typedef word_t sched_blkpt_epoch_t;

static inline struct sl_global_core *
sl__globals_core(void)
{
	return &(sl_global_core_data[cos_cpuid()]);
}

static inline struct cos_scb_info *
sl_scb_info_core(void)
{
	return (sl__globals_core()->scb_info);
}

static inline void
sl_thd_setprio(struct sl_thd *t, tcap_prio_t p)
{
	t->prio = p;
}

/* for lazy retrieval of a child component thread in the parent */
extern struct sl_thd *sl_thd_retrieve_lazy(thdid_t tid);

static inline struct sl_thd *
sl_thd_lkup(thdid_t tid)
{
	struct sl_thd *t;
	struct sl_xcore_thd *xt;

	if (unlikely(tid < 1 || tid > MAX_NUM_THREADS)) return NULL;
	t = sl_mod_thd_get(sl_thd_lookup_backend(tid));
	if (likely(t && sl_thd_aepinfo(t))) return t;
	xt = sl_xcore_thd_lookup(tid);
	if (unlikely(xt && xt->core != cos_cpuid())) return NULL;

	/* FIXME: cross-core child threads must be handled in retrieve */
	return sl_thd_retrieve_lazy(tid);
}

/* only see if it's already sl_thd initialized */
static inline struct sl_thd *
sl_thd_try_lkup(thdid_t tid)
{
	struct sl_thd *t = NULL;

	if (unlikely(tid < 1 || tid > MAX_NUM_THREADS)) return NULL;

	t = sl_mod_thd_get(sl_thd_lookup_backend(tid));
	if (!sl_thd_aepinfo(t)) return NULL;

	return t;
}

static inline thdid_t
sl_thdid(void)
{
	return cos_thdid();
}

sched_blkpt_id_t sched_blkpt_alloc(void);
int sched_blkpt_free(sched_blkpt_id_t id);
int sched_blkpt_trigger(sched_blkpt_id_t blkpt, sched_blkpt_epoch_t epoch, int single);
int sched_blkpt_block(sched_blkpt_id_t blkpt, sched_blkpt_epoch_t epoch, thdid_t dependency);

static inline struct sl_thd *
sl_thd_curr(void)
{
	struct sl_thd *t = (struct sl_thd *)cos_get_slthd_ptr();

	if (likely(t)) return t;

	t = sl_thd_lkup(sl_thdid());
	cos_set_slthd_ptr((void *)t);

	return t;
}

/* are we the owner of the critical section? */
static inline int
sl_cs_owner(void)
{
	return sl__globals_core()->lock.u.s.owner == sl_thd_thdcap(sl_thd_curr());
}

/* ...not part of the public API */
/*
 * @csi: current critical section value
 * @cached: a cached copy of @csi
 * @curr: currently executing thread
 * @tok: scheduler synchronization token for cos_defswitch
 *
 * @ret:
 *     (Caller of this function should retry for a non-zero return value.)
 *     1 for cas failure or after successful thread switch to thread that owns the lock.
 *     -ve from cos_defswitch failure, allowing caller for ex: the scheduler thread to
 *     check if it was -EBUSY to first recieve pending notifications before retrying lock.
 */
int sl_cs_enter_contention(union sl_cs_intern *csi, union sl_cs_intern *cached, struct sl_global_core *gcore, struct sl_thd *curr, sched_tok_t tok);
/*
 * @csi: current critical section value
 * @cached: a cached copy of @csi
 * @tok: scheduler synchronization token for cos_defswitch
 *
 * @ret: returns 1 if we need a retry, 0 otherwise
 */
int sl_cs_exit_contention(union sl_cs_intern *csi, union sl_cs_intern *cached, struct sl_global_core *gcore, sched_tok_t tok);

/* Enter into the scheduler critical section */
static inline int
sl_cs_enter_nospin(void)
{
#ifdef SL_CS
	struct sl_global_core *gcore = sl__globals_core();
	struct sl_thd         *t     = sl_thd_curr();
	union sl_cs_intern csi, cached;

	assert(t);
	csi.v    = gcore->lock.u.v;
	cached.v = csi.v;

	if (unlikely(csi.s.owner)) {
		return sl_cs_enter_contention(&csi, &cached, gcore, t, cos_sched_sync());
	}

	csi.s.owner = sl_thd_thdcap(t);
	if (!ps_upcas(&gcore->lock.u.v, cached.v, csi.v)) return 1;
#endif
	return 0;
}

/* Enter into scheduler cs from a non-sched thread context */
static inline void
sl_cs_enter(void)
{
	while (sl_cs_enter_nospin())
		;
}

/*
 * Enter into scheduler cs from scheduler thread context
 * @ret: returns -EBUSY if sched thread has events to process and cannot switch threads, 0 otherwise.
 */
static inline int
sl_cs_enter_sched(void)
{
	int ret;

	while ((ret = sl_cs_enter_nospin())) {
		if (ret == -EBUSY) break;
	}

	return ret;
}

/*
 * Release the scheduler critical section, switch to the scheduler
 * thread if there is pending contention
 */
static inline void
sl_cs_exit(void)
{
#ifdef SL_CS
	struct sl_global_core *gcore = sl__globals_core();
	union sl_cs_intern csi, cached;

	assert(sl_cs_owner());
retry:
	csi.v    = gcore->lock.u.v;
	cached.v = csi.v;

	if (unlikely(csi.s.contention)) {
		if (sl_cs_exit_contention(&csi, &cached, gcore, cos_sched_sync())) goto retry;

		return;
	}

	if (!ps_upcas(&gcore->lock.u.v, cached.v, 0)) goto retry;
#endif
}

/*
 * if tid == 0, just block the current thread; otherwise, create a
 * dependency from this thread on the target tid (i.e. when the
 * scheduler chooses to run this thread, we will run the dependency
 * instead (note that "dependency" is transitive).
 */
void sl_thd_block(thdid_t tid);
/*
 * @abs_timeout: absolute timeout at which thread should be woken-up.
 *               if abs_timeout == 0, block forever = sl_thd_block()
 *
 * @returns: 0 if the thread is woken up by external events before timeout.
 *	     +ve - number of cycles elapsed from abs_timeout before the thread
 *		   was woken up by Timeout module.
 */
cycles_t sl_thd_block_timeout(thdid_t tid, cycles_t abs_timeout);
/*
 * blocks for a timeout = next replenishment period of the task.
 * Note: care should be taken to not interleave this with sl_thd_block_timeout().
 *       It may be required to interleave, in such cases, timeout values in
 *       sl_thd_block_timeout() should not be greater than or equal to
 *       the task's next replenishment period.
 *
 * @returns: 0 if the thread is woken up by external events before timeout.
 *           +ve - number of periods elapsed. (1 if it wokeup exactly at timeout = next period)
 */
unsigned int sl_thd_block_periodic(thdid_t tid);
/*
 * block the thread for it's tcap expiry until next period if it's a thread with it's own tcap..
 */
void         sl_thd_block_expiry(struct sl_thd *t);
int          sl_thd_block_no_cs(struct sl_thd *t, sl_thd_state_t block_type, cycles_t abs_timeout);
int          sl_thd_sched_block_no_cs(struct sl_thd *t, sl_thd_state_t block_type, cycles_t abs_timeout);

/* wakeup a thread that has (or soon will) block */
void sl_thd_wakeup(thdid_t tid);
int  sl_thd_wakeup_no_cs(struct sl_thd *t);
int  sl_thd_sched_wakeup_no_cs(struct sl_thd *t);
/* wakeup thread and do not remove from timeout queue if blocked on timeout */
int  sl_thd_wakeup_no_cs_rm(struct sl_thd *t);

void sl_thd_yield_intern(thdid_t tid);
void sl_thd_yield_intern_timeout(cycles_t abs_timeout);

void sl_thd_yield_cs_exit(thdid_t tid);

int sl_thd_migrate_no_cs(struct sl_thd *t, cpuid_t core);
/* @return: 0 - success, -1 - failure */
int sl_thd_migrate(thdid_t tid, cpuid_t core);

/* The entire thread allocation and free API */
struct sl_thd *sl_thd_alloc(cos_thd_fn_t fn, void *data);
struct sl_thd *sl_thd_aep_alloc(cos_aepthd_fn_t fn, void *data, int own_tcap, cos_channelkey_t key, microsec_t ipiwin, u32_t ipimax);
/*
 * This API creates a sl_thd object for this child component.
 * @comp: component created using cos_defkernel_api which includes initthd (with/without its own tcap & rcvcap).
 */
struct sl_thd *sl_thd_comp_init(struct cos_defcompinfo *comp, int is_sched);

struct sl_thd *sl_thd_initaep_alloc_dcb(struct cos_defcompinfo *comp, struct sl_thd *sched_thd, int is_sched, int own_tcap, cos_channelkey_t key, dcbcap_t dcap, microsec_t ipiwin, u32_t ipimax);
struct sl_thd *sl_thd_aep_alloc_ext_dcb(struct cos_defcompinfo *comp, struct sl_thd *sched_thd, thdclosure_index_t idx, int is_aep, int own_tcap, cos_channelkey_t key, dcbcap_t dcap, dcboff_t doff, microsec_t ipiwin, u32_t ipimax, arcvcap_t *extrcv);
struct sl_thd *sl_thd_initaep_alloc(struct cos_defcompinfo *comp, struct sl_thd *sched_thd, int is_sched, int own_tcap, cos_channelkey_t key, microsec_t ipiwin, u32_t ipimax, vaddr_t *dcbaddr);
struct sl_thd *sl_thd_aep_alloc_ext(struct cos_defcompinfo *comp, struct sl_thd *sched_thd, thdclosure_index_t idx, int is_aep, int own_tcap, cos_channelkey_t key, microsec_t ipiwin, u32_t ipimax, vaddr_t *dcbaddr, arcvcap_t *extrcv);

struct sl_thd *sl_thd_init_ext(struct cos_aep_info *aep, struct sl_thd *sched_thd);

void           sl_thd_free(struct sl_thd *t);
void           sl_thd_exit();

void sl_thd_param_set(struct sl_thd *t, sched_param_t sp);

static inline microsec_t
sl_cyc2usec(cycles_t cyc)
{
	return cyc / sl__globals_core()->cyc_per_usec;
}

static inline cycles_t
sl_usec2cyc(microsec_t usec)
{
	return usec * sl__globals_core()->cyc_per_usec;
}

static inline cycles_t
sl_now(void)
{
	return ps_tsc();
}

static inline microsec_t
sl_now_usec(void)
{
	return sl_cyc2usec(sl_now());
}

/*
 * Time and timeout API.
 *
 * This can be used by the scheduler policy module *and* by the
 * surrounding component code.  To avoid race conditions between
 * reading the time, and setting a timeout, we avoid relative time
 * measurements.  sl_now gives the current cycle count that is on an
 * absolute timeline.  The periodic function sets a period that can be
 * used when a timeout has happened, the relative function sets a
 * timeout relative to now, and the oneshot timeout sets a timeout on
 * the same absolute timeline as returned by sl_now.
 */
void sl_timeout_period(cycles_t period);

static inline cycles_t
sl_timeout_period_get(void)
{
	return sl__globals_core()->period;
}

static inline void
sl_timeout_oneshot(cycles_t absolute_us)
{
	struct sl_global_core *g = sl__globals_core();

	g->timer_prev   = g->timer_next;
	g->timer_next   = absolute_us;
	g->timeout_next = tcap_cyc2time(absolute_us);
}

static inline void
sl_timeout_relative(cycles_t offset)
{
	sl_timeout_oneshot(sl_now() + offset);
}

static inline void
sl_timeout_expended(microsec_t now, microsec_t oldtimeout)
{
	cycles_t offset;

	assert(now >= oldtimeout);

	/* in virtual environments, or with very small periods, we might miss more than one period */
	offset = (now - oldtimeout) % sl_timeout_period_get();
	sl_timeout_oneshot(now + sl_timeout_period_get() - offset);
}

/* to get timeout heap. not a public api */
struct heap *sl_timeout_heap(void);

/* wakeup any blocked threads! */
static inline void
sl_timeout_wakeup_expired(cycles_t now)
{
	if (likely(!heap_size(sl_timeout_heap()))) return;

	do {
		struct sl_thd *tp, *th;

		tp = heap_peek(sl_timeout_heap());
		assert(tp);

		/* FIXME: logic for wraparound in current tsc */
		if (likely(tp->timeout_cycs > now)) break;

		th = heap_highest(sl_timeout_heap());
		assert(th && th == tp);
		th->timeout_idx = -1;

		assert(th->wakeup_cycs == 0);
		th->wakeup_cycs = now;
		sl_thd_wakeup_no_cs_rm(th);
	} while (heap_size(sl_timeout_heap()));
}

static inline int
sl_thd_is_runnable(struct sl_thd *t)
{
	return (t->state == SL_THD_RUNNABLE || t->state == SL_THD_WOKEN);
}

static inline int
sl_thd_dispatch_kern(struct sl_thd *next, sched_tok_t tok, struct sl_thd *curr, tcap_time_t timeout, tcap_t tc, tcap_prio_t p)
{
	volatile struct cos_scb_info *scb = sl_scb_info_core();
	struct sl_global_core *g = sl__globals_core();
	struct cos_dcb_info *cd = sl_thd_dcbinfo(curr), *nd = sl_thd_dcbinfo(next);
	word_t a = ((sl_thd_thdcap(next)  + 1) << COS_CAPABILITY_OFFSET) + (tok >> 16);
	word_t b = (tc << 16) | g->sched_rcv;
	word_t S = (p << 32) >> 32;
	word_t D = (((p << 16) >> 48) << 16) | ((tok << 16) >> 16);
	word_t d = timeout; 
	int ret = 0;

	assert(curr != next);
	if (unlikely(!cd || !nd)) return cos_switch(sl_thd_thdcap(next), sl_thd_tcap(next), next->prio, timeout, g->sched_rcv, tok);

	__asm__ __volatile__ (			\
		"pushl %%ebp\n\t"		\
		"movl %%esp, %%ebp\n\t"		\
		"movl $1f, (%%esi)\n\t"		\
		"movl %%esp, 4(%%esi)\n\t"	\
		"movl %%ecx, %%esi\n\t"		\
		"movl $2f, %%ecx\n\t"		\
		"sysenter\n\t"			\
		"jmp 2f\n\t"			\
		".align 4\n\t"			\
		"1:\n\t"			\
		"movl $0, %%eax\n\t"		\
		".align 4\n\t"			\
		"2:\n\t"			\
		"popl %%ebp\n\t"		\
		: "=a" (ret)
		: "a" (a), "b" (b), "S" (cd), "D" (D), "d" (d), "c" (S)
		: "memory", "cc");

	scb = sl_scb_info_core();
	cd = sl_thd_dcbinfo(sl_thd_curr());
	cd->sp = 0;
	if (unlikely(ps_load(&scb->sched_tok) != tok)) return -EAGAIN;

	return ret;
}

static inline int
sl_thd_dispatch_usr(struct sl_thd *next, sched_tok_t tok, struct sl_thd *curr)
{
	volatile struct cos_scb_info *scb = sl_scb_info_core();
	struct cos_dcb_info *cd = sl_thd_dcbinfo(curr), *nd = sl_thd_dcbinfo(next);
	struct sl_global_core *g = sl__globals_core();

	assert(curr != next);
	if (unlikely(!cd || !nd)) return cos_defswitch(sl_thd_thdcap(next), next->prio, g->timeout_next, tok);

	/*
	 * jump labels in the asm routine:
	 *
	 * 1: slowpath dispatch using cos_thd_switch to switch to a thread
	 *    if the dcb sp of the next thread is reset.
	 *	(inlined slowpath sysenter to debug preemption problem)
	 *
	 * 2: if user-level dispatch routine completed successfully so
	 *    the register states still retained and in the dispatched thread
	 *    we reset its dcb sp!
	 *
	 * 3: if user-level dispatch was either preempted in the middle
	 *    of this routine or kernel at some point had to switch to a
	 *    thread that co-operatively switched away from this routine.
	 *    NOTE: kernel takes care of resetting dcb sp in this case!
	 *
	 * a simple cos_thd_switch() kind will disable timers! so, pass in the timeout anyway to 
	 * slowpath thread switch!
	 */

	__asm__ __volatile__ (			\
		"pushl %%ebp\n\t"		\
		"movl %%esp, %%ebp\n\t"		\
		"movl $2f, (%%eax)\n\t"		\
		"movl %%esp, 4(%%eax)\n\t"	\
		"cmp $0, 4(%%ebx)\n\t"		\
		"je 1f\n\t"			\
		"movl %%edx, (%%ecx)\n\t"	\
		"movl 4(%%ebx), %%esp\n\t"	\
		"jmp *(%%ebx)\n\t"		\
		".align 4\n\t"			\
		"1:\n\t"			\
		"movl $3f, %%ecx\n\t"		\
		"movl %%edx, %%eax\n\t"		\
		"inc %%eax\n\t"			\
		"shl $16, %%eax\n\t"		\
		"movl $0, %%ebx\n\t"		\
		"movl %%esi, %%edx\n\t"		\
		"movl $0, %%esi\n\t"		\
		"movl $0, %%edi\n\t"		\
		"sysenter\n\t"			\
		"jmp 3f\n\t"			\
		".align 4\n\t"			\
		"2:\n\t"			\
		"movl $0, 4(%%ebx)\n\t"		\
		".align 4\n\t"			\
		"3:\n\t"			\
		"popl %%ebp\n\t"		\
		:
		: "a" (cd), "b" (nd),
		  "S" (g->timeout_next), "D" (tok),
		  "c" (&(scb->curr_thd)), "d" (sl_thd_thdcap(next))
		: "memory", "cc");

	scb = sl_scb_info_core();
	if (unlikely(ps_load(&scb->sched_tok) != tok)) return -EAGAIN;

	return 0;
}

static inline int
sl_thd_activate_c(struct sl_thd *t, sched_tok_t tok, tcap_time_t timeout, tcap_prio_t prio, struct sl_thd *curr, struct sl_global_core *g)
{
	if (unlikely(t->properties & SL_THD_PROPERTY_SEND)) {
		return cos_sched_asnd(t->sndcap, g->timeout_next, g->sched_rcv, tok);
	}

	/* there is more events.. run scheduler again! */
	if (unlikely(cos_sched_ispending())) {
		if (curr == g->sched_thd) return -EBUSY;
		return sl_thd_dispatch_usr(g->sched_thd, tok, curr);
	}

	if (unlikely(t->properties & SL_THD_PROPERTY_OWN_TCAP)) {
		return sl_thd_dispatch_kern(t, tok, curr, timeout, sl_thd_tcap(t), prio == 0 ? t->prio : prio);
	}

	/* TODO: there is something in the kernel that seem to disable timers..!! */
	/* WORKAROUND: idle thread is a big cpu hogger.. so make sure there is timeout set around switching to and away! */
	if (unlikely(curr == g->idle_thd || t == g->idle_thd)) {
		return sl_thd_dispatch_kern(t, tok, curr, g->timeout_next, g->sched_tcap, prio);
	}

	if (unlikely(timeout || prio)) {
		return sl_thd_dispatch_kern(t, tok, curr, timeout, g->sched_tcap, prio);
	} else {
		assert(t != g->idle_thd);
		return sl_thd_dispatch_usr(t, tok, curr);
	}
}


static inline int
sl_thd_activate(struct sl_thd *t, sched_tok_t tok, tcap_time_t timeout, tcap_prio_t prio)
{
	struct sl_global_core *g = sl__globals_core();

	return sl_thd_activate_c(t, tok, timeout, prio, sl_thd_curr(), g);
}

static inline int
sl_cs_exit_schedule_nospin_arg_c(struct sl_thd *curr, struct sl_thd *next)
{
	sched_tok_t tok;
#ifdef SL_CS
	if (likely(!sl_cs_owner())) sl_cs_enter();
#endif
	tok = cos_sched_sync();
#ifdef SL_CS
	sl_cs_exit();
#endif
	return sl_thd_activate_c(next, tok, 0, 0, curr, sl__globals_core());
}

void sl_thd_replenish_no_cs(struct sl_thd *t, cycles_t now);
/*
 * Do a few things: 1. take the critical section if it isn't already
 * taken, 2. call schedule to find the next thread to run, 3. release
 * the critical section (note this will cause visual asymmetries in
 * your code if you call sl_cs_enter before this function), and
 * 4. switch to the given thread.  It hides some races, and details
 * that would make this difficult to write repetitively.
 *
 * Preconditions: if synchronization is required with code before
 * calling this, you must call sl_cs_enter before-hand (this is likely
 * a typical case).
 *
 * Return: the return value from cos_switch.  The caller must handle
 * this value correctly.
 *
 * A common use-case is:
 *
 * sl_cs_enter();
 * scheduling_stuff()
 * sl_cs_exit_schedule();
 *
 * ...which correctly handles any race-conditions on thread selection and
 * dispatch.
 */
static inline int
sl_cs_exit_schedule_nospin_arg(struct sl_thd *to)
{
	struct sl_thd         *t = to, *c = sl_thd_curr();
	struct sl_global_core *globals = sl__globals_core();
	sched_tok_t            tok;
#ifdef SL_REPLENISH
	cycles_t               now;
#endif
	s64_t                  offset;
	int                    ret;

	/* Don't abuse this, it is only to enable the tight loop around this function for races... */
#ifdef SL_CS
	if (likely(!sl_cs_owner())) sl_cs_enter();
#endif

	tok    = cos_sched_sync();
#ifdef SL_REPLENISH
	now    = sl_now();
#endif

	/*
	 * Once we exit, we can't trust t's memory as it could be
	 * deallocated/modified, so cache it locally.  If these values
	 * are out of date, the scheduler synchronization tok will
	 * catch it.  This is a little twitchy and subtle, so lets put
	 * it in a function, here.
	 */
	if (likely(to)) {
		t = to;
		if (unlikely(!sl_thd_is_runnable(t))) to = NULL;
	}
	if (unlikely(!to)) {
		struct sl_thd_policy *pt = sl_mod_schedule();

		if (unlikely(!pt))
			t = globals->idle_thd;
		else
			t = sl_mod_thd_get(pt);
	}
	if (unlikely(!t)) t= globals->sched_thd;

#ifdef SL_REPLENISH
	sl_thd_replenish_no_cs(t, now);
#endif

	assert(t && sl_thd_is_runnable(t));
#ifdef SL_CS
	sl_cs_exit();
#endif
	if (unlikely(t == c)) return 0;

	ret = sl_thd_activate_c(t, tok, 0, 0, c, globals);

	/*
	 * one observation, in slowpath switch:
	 *        if the kernel decides to switch over to scheduler thread and
	 *        later at some point decides to resume this thread, the ret value
	 *        from the syscall is probably 0, even though token has advanced and
	 *        the switch this thread intended, did not go through.
	 *
	 * there is some wierd race in user-level thread switch:
	 *        a thread sl_thd_block()'s itself and decides to switch to a runnable
	 *        thread at user-level.
	 *        if a preemption occurs and eventually this thread is resumed, 
	 *        for some reason the token check is not working well.
	 *
	 * what is more wierd is, even in slowpath sl_thd_activate(), I see that
	 * on return from syscall, this thread is not runnable. 
	 * how is this possible? is there a race? i don't think so.
	 * only the current thread can block itself, of course this is not true for AEPs.
	 * But for non AEPs, I don't know why this triggers!
	 *
	 * I'll need to rethink about some possible scenario, perhaps some bug in the code
	 * that returns to this thread when it is not runnable.
	 * something!!!!
	 */
	if (unlikely(!sl_thd_is_runnable(c))) return -EAGAIN;

#ifdef SL_REPLENISH 
	/*
	 * dispatch failed with -EPERM because tcap associated with thread t does not have budget.
	 * Block the thread until it's next replenishment and return to the scheduler thread.
	 *
	 * If the thread is not replenished by the scheduler (replenished "only" by
	 * the inter-component delegations), block till next timeout and try again.
	 */
	if (unlikely(ret == -EPERM)) {
		assert(t != globals->sched_thd && t != globals->idle_thd);
		sl_thd_block_expiry(t);
		if (unlikely(sl_thd_curr() != globals->sched_thd)) ret = sl_thd_activate(globals->sched_thd, tok, globals->timeout_next, 0);
	}
#endif
	/* either this thread is runnable at this point or a switch failed */
	assert(sl_thd_is_runnable(c) || ret);

	return ret;
}

static inline int
sl_cs_exit_schedule_nospin_arg_timeout(struct sl_thd *to, cycles_t abs_timeout)
{
	struct sl_thd         *t = to, *c = sl_thd_curr();
	struct sl_global_core *globals = sl__globals_core();
	sched_tok_t            tok;
	cycles_t               now;
	s64_t                  offset;
	int                    ret;
	struct cos_dcb_info *cb;
	tcap_time_t            timeout = 0;

	/* Don't abuse this, it is only to enable the tight loop around this function for races... */
#ifdef SL_CS
	if (likely(!sl_cs_owner())) sl_cs_enter();
#endif

	tok    = cos_sched_sync();
	now    = sl_now();

	offset = (s64_t)(globals->timer_next - now);
	if (offset <= 0) sl_timeout_expended(now, globals->timer_next);
	sl_timeout_wakeup_expired(now);

	/*
	 * Once we exit, we can't trust t's memory as it could be
	 * deallocated/modified, so cache it locally.  If these values
	 * are out of date, the scheduler synchronization tok will
	 * catch it.  This is a little twitchy and subtle, so lets put
	 * it in a function, here.
	 */
	if (likely(to)) {
		t = to;
		if (unlikely(!sl_thd_is_runnable(t))) to = NULL;
	}
	if (unlikely(!to)) {
		struct sl_thd_policy *pt = sl_mod_schedule();

		if (unlikely(!pt))
			t = globals->idle_thd;
		else
			t = sl_mod_thd_get(pt);
	}
	if (unlikely(!t)) t= globals->sched_thd;

#ifdef SL_REPLENISH
	sl_thd_replenish_no_cs(t, now);
#endif

	assert(t && sl_thd_is_runnable(t));
	if (offset <= 0 || 
	    (abs_timeout > now && abs_timeout > globals->timer_next + globals->cyc_per_usec)) {
		timeout = offset <= 0 ? globals->timer_next : (abs_timeout > now ? tcap_cyc2time(abs_timeout) : 0);
	}

#ifdef SL_CS
	sl_cs_exit();
#endif
	if (likely(c == t && t == globals->sched_thd && timeout)) {
		/* program the new timer.. */
		return cos_defswitch(globals->sched_thdcap, globals->sched_thd->prio, timeout, tok);
	}
	if (unlikely(t == c)) return 0;

	/* 
	 * if the requested timeout is greater than next timeout 
	 * and timer is already programmed to be over a usec away, don't 
	 * reprogam it.
	 *
	 * else, reprogram for an earlier timeout requested.
	 */

	ret = sl_thd_activate_c(t, tok, timeout, 0, c, globals);
	if (unlikely(!sl_thd_is_runnable(c))) return -EAGAIN;

#ifdef SL_REPLENISH 
	/*
	 * dispatch failed with -EPERM because tcap associated with thread t does not have budget.
	 * Block the thread until it's next replenishment and return to the scheduler thread.
	 *
	 * If the thread is not replenished by the scheduler (replenished "only" by
	 * the inter-component delegations), block till next timeout and try again.
	 */
	if (unlikely(ret == -EPERM)) {
		assert(t != globals->sched_thd && t != globals->idle_thd);
		sl_thd_block_expiry(t);
		if (unlikely(sl_thd_curr() != globals->sched_thd)) ret = sl_thd_activate_c(globals->sched_thd, tok, globals->timeout_next, 0, c, globals);
	}
#endif

	return ret;
}

static inline int
sl_cs_exit_schedule_nospin(void)
{
	return sl_cs_exit_schedule_nospin_arg(NULL);
}

static inline void
sl_cs_exit_schedule(void)
{
	while (sl_cs_exit_schedule_nospin())
		;
}

static inline void
sl_cs_exit_switchto(struct sl_thd *to)
{
	/*
	 * We only try once, so it is possible that we don't end up
	 * switching to the desired thread.  However, this is always a
	 * case that the caller has to consider if the current thread
	 * has a higher priority than the "to" thread.
	 */
	if (sl_cs_exit_schedule_nospin_arg(to)) {
		sl_cs_exit_schedule();
	}
}

static inline int
sl_cs_exit_schedule_nospin_timeout(cycles_t abs_timeout)
{
	return sl_cs_exit_schedule_nospin_arg_timeout(NULL, abs_timeout);
}

static inline void
sl_cs_exit_schedule_timeout(cycles_t abs_timeout)
{
	while (sl_cs_exit_schedule_nospin_timeout(abs_timeout) && sl_now() < abs_timeout)
		;
}

static inline void
sl_cs_exit_switchto_timeout(struct sl_thd *to, cycles_t abs_timeout)
{
	/*
	 * We only try once, so it is possible that we don't end up
	 * switching to the desired thread.  However, this is always a
	 * case that the caller has to consider if the current thread
	 * has a higher priority than the "to" thread.
	 */
	if (sl_cs_exit_schedule_nospin_arg_timeout(to, abs_timeout)) {
		sl_cs_exit_schedule_timeout(abs_timeout);
	}
}

static inline void
sl_cs_exit_switchto_c(struct sl_thd *c, struct sl_thd *n)
{
	if (sl_cs_exit_schedule_nospin_arg_c(c, n)) {
		sl_cs_exit_schedule();
	}
}

/*
 * Initialization protocol in cos_init: initialization of
 * library-internal data-structures, and then the ability for the
 * scheduler thread to start its scheduling loop.
 *
 * sl_init(period); <- using `period` for scheduler periodic timeouts
 * sl_*;            <- use the sl_api here
 * ...
 * sl_sched_loop(); <- loop here. or using sl_sched_loop_nonblock();
 */
void sl_init(microsec_t period);
/*
 * @cpubmp - cpu/cores on which this scheduler will run on!
 */
void sl_init_corebmp(microsec_t period, u32_t *corebmp);
/*
 * sl_sched_loop internally calls the kernel api - cos_sched_rcv
 * which blocks (suspends) the calling thread if there are no pending events.
 */
void sl_sched_loop(void) __attribute__((noreturn));
/*
 * sl_sched_loop_nonblock internally calls the kernel api - cos_sched_rcv
 * with a RCV_NONBLOCK flag, the kernel returns to the calling thread immediately if
 * there are no pending events.
 *
 * This is useful for the system scheduler in a hierarchical settings where
 * booter (perhaps only doing simple chronos delegations) hands off the
 * system scheduling responsibility to another component.
 *
 * Note: sl_sched_loop_nonblock has same semantics as sl_sched_loop for
 * booter receive (INITRCV) end-point at the kernel level.
 */
void sl_sched_loop_nonblock(void) __attribute__((noreturn));
static inline void
sl_thd_yield_thd_c(struct sl_thd *c, struct sl_thd *n)
{
	if (likely(c && n)) sl_cs_exit_switchto_c(c, n);
	else                sl_thd_yield_intern(0);
}

static inline void
sl_thd_yield_thd(struct sl_thd *n)
{
	if (likely(n)) sl_cs_exit_switchto(n);
	else           sl_thd_yield_intern(0);
}

static inline void
sl_thd_yield(thdid_t tid)
{
	if (likely(tid)) {
		sl_cs_enter();
		sl_cs_exit_switchto(sl_thd_lkup(tid));
	} else {
		sl_thd_yield_intern(0);
	}
}

static inline void
sl_thd_yield_timeout(thdid_t tid, cycles_t abs_timeout)
{
	if (likely(tid)) {
		sl_cs_enter();
		sl_cs_exit_switchto_timeout(sl_thd_lkup(tid), abs_timeout);
	} else {
		sl_thd_yield_intern_timeout(abs_timeout);
	}
}

static inline void
sl_thd_event_info_reset(struct sl_thd *t)
{
	t->event_info.blocked      = 0;
	t->event_info.elapsed_cycs = 0;
	t->event_info.next_timeout = 0;
	t->event_info.epoch        = 0;
}

static inline void
sl_thd_event_enqueue(struct sl_thd *t, struct cos_thd_event *e)
{
	struct sl_global_core *g = sl__globals_core();

	assert(e->epoch);
	if (e->epoch <= t->event_info.epoch) return;

	if (ps_list_singleton(t, SL_THD_EVENT_LIST)) ps_list_head_append(&g->event_head, t, SL_THD_EVENT_LIST);

	t->event_info.blocked       = e->blocked;
	t->event_info.elapsed_cycs += e->elapsed_cycs;
	t->event_info.next_timeout  = e->next_timeout;
}

static inline void
sl_thd_event_dequeue(struct sl_thd *t, struct cos_thd_event *e)
{
	ps_list_rem(t, SL_THD_EVENT_LIST);

	e->blocked      = t->event_info.blocked;
	e->elapsed_cycs = t->event_info.elapsed_cycs;
	e->next_timeout = t->event_info.next_timeout;
	sl_thd_event_info_reset(t);
}

static inline int
sl_thd_rcv(rcv_flags_t flags)
{
	return cos_ul_rcv(sl_thd_rcvcap(sl_thd_curr()), flags, sl__globals_core()->timeout_next);
//	/* FIXME: elapsed_cycs accounting..?? */
//	struct cos_thd_event ev = { .blocked = 1, .next_timeout = 0, .epoch = 0, .elapsed_cycs = 0 };
//	struct sl_thd *t = sl_thd_curr();
//	unsigned long *p = &sl_thd_dcbinfo(t)->pending, q = 0;
//	int ret = 0;
//
//	assert(sl_thd_rcvcap(t));
//	assert(!(flags & RCV_ULSCHED_RCV));
//
//recheck:
//	if ((q = ps_load(p)) == 0) {
//		if (!(flags & RCV_ULONLY)) {
//			ret = cos_rcv(sl_thd_rcvcap(t), flags);
//			q = ps_load(p);
//			goto done;
//		}
//		if (unlikely(flags & RCV_NON_BLOCKING)) return -EAGAIN;
//
//		sl_cs_enter();
//		ev.epoch = sl_now();
//		sl_thd_event_enqueue(t, &ev);
//		sl_thd_sched_block_no_cs(t, SL_THD_BLOCKED, 0);
//		sl_cs_exit_switchto(sl__globals_core()->sched_thd);
//		goto recheck;
//		//q = ps_load(p);
//	}
//	assert(sl_thd_dcbinfo(t)->sp == 0);
//	assert(q == 1); /* q should be 1 if the thread did not call COS_RCV and is woken up.. */
//
//done:
//	ps_upcas(p, q, 0);
////if (cos_spd_id() != 4) printc("[R%u]", cos_thdid()); 
//	return ret;
}

#endif /* SL_H */
